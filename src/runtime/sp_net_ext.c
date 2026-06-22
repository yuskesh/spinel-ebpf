/* sp_net_ext.c -- spinel-ebpf's OWN sp_net extensions, kept OUT of upstream
 * lib/sp_net.c (keeping the upstream surface minimal). Linked into the final
 * binary via bin/spinel-ebpf's extra_sources, NOT patched into libspinel_rt.a.
 *
 * Provides the HTTP-server / observability surface upstream sp_net lacks:
 *   - buffered line read    : sp_net_read_line(+_reset/_buffered_remaining)
 *   - zero-copy static file : sp_net_file_size / sp_net_sendfile
 *   - epoll readiness mux    : sp_net_epoll_create/_add/_del/_wait_one
 *   - SIGCHLD auto-reap      : sp_net_reap_nb / sp_net_autoreap_on
 *   - PTY + WebSocket pumps  : sp_pty_* / sp_ws_*
 *
 * Reaches upstream's sp_net_close / sp_net_recv_some / sp_net_shutdown_requested
 * by symbol (resolved from libspinel_rt.a at link time) -- upstream's source is
 * untouched. The old "dormant hooks" that edited upstream's close/recv_some are
 * replaced here by read_line-aware variants sp_net_rl_close / sp_net_rl_recv_some
 * that callers using read_line invoke instead.
 */
#include "sp_net.h"   /* upstream decls: sp_net_close / sp_net_recv_some / sp_net_shutdown_requested */

/* read_line-aware variants are part of this TU's contract; declare for callers. */
void        sp_net_read_line_reset(int fd);
int         sp_net_read_line_buffered_remaining(int fd, char *out, int max);
const char *sp_net_read_line(int fd);
int         sp_net_rl_close(int fd);
const char *sp_net_rl_recv_some(int fd, int maxlen);

#if defined(_WIN32)

/* ---------- Windows (MinGW): no POSIX net/process surface ---------- */
const char *sp_net_read_line(int fd)               { (void)fd; return ""; }
void        sp_net_read_line_reset(int fd)         { (void)fd; }
int         sp_net_read_line_buffered_remaining(int fd, char *out, int max) { (void)fd; (void)out; (void)max; return 0; }
int         sp_net_rl_close(int fd)                { (void)fd; return -1; }
const char *sp_net_rl_recv_some(int fd, int maxlen){ (void)fd; (void)maxlen; return ""; }
int         sp_net_file_size(const char *path)             { (void)path; return -1; }
int         sp_net_sendfile(int out_fd, const char *path)  { (void)out_fd; (void)path; return -1; }
int         sp_net_epoll_create(void)            { return -1; }
int         sp_net_epoll_add(int epfd, int fd)   { (void)epfd; (void)fd; return -1; }
int         sp_net_epoll_del(int epfd, int fd)   { (void)epfd; (void)fd; return -1; }
int         sp_net_epoll_wait_one(int epfd)      { (void)epfd; return -1; }
int         sp_net_reap_nb(void)                  { return 0; }
int         sp_net_autoreap_on(void)              { return -1; }
int         sp_pty_spawn(const char *cmd, int rows, int cols) { (void)cmd; (void)rows; (void)cols; return -1; }
int         sp_pty_set_winsize(int fd, int rows, int cols) { (void)fd; (void)rows; (void)cols; return -1; }
const char *sp_pty_read(int fd, int maxlen)               { (void)fd; (void)maxlen; return ""; }
int         sp_pty_write(int fd, const char *data, int n)  { (void)fd; (void)data; (void)n; return -1; }

#else /* POSIX */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <termios.h>
#include <stdint.h>

#define SP_NET_BUFSIZE 65536   /* matches upstream lib/sp_net.c */

/* ---------- buffered line read ---------- */
/* The original read_line did one recv(fd,&c,1,0) per byte (~27 recvfrom/req);
 * we refill a buffer with one recv() and serve lines from it (~1 recv/req,
 * like nginx / CRuby IO#gets). One buffer is correct because a connection is
 * handled serially (accept -> read_line* -> write -> close); sp_net_rl_close()
 * resets it so a recycled fd never inherits stale bytes. Multi-worker servers
 * fork, so each worker gets its own copy. A caller that switches to raw recv()
 * after read_line() (HTTP->WebSocket upgrade) must drain the buffered remainder
 * first -- see sp_net_read_line_buffered_remaining(). */
static char          sp_net_line_buf[SP_NET_BUFSIZE];
static unsigned char sp_net_fill_buf[SP_NET_BUFSIZE];
static int sp_net_fill_len = 0;   /* valid bytes in sp_net_fill_buf */
static int sp_net_fill_pos = 0;   /* next unread byte */
static int sp_net_fill_fd  = -1;  /* fd the buffered bytes belong to */

void sp_net_read_line_reset(int fd) {
    if (fd < 0 || fd == sp_net_fill_fd) {
        sp_net_fill_len = 0;
        sp_net_fill_pos = 0;
        sp_net_fill_fd  = -1;
    }
}

/* Bytes already pulled off the socket into the fill buffer but not yet consumed
 * (read past the last returned line). A WebSocket-upgrade caller fetches these
 * so no client bytes are lost when it switches to raw recv(). */
int sp_net_read_line_buffered_remaining(int fd, char *out, int max) {
    if (fd != sp_net_fill_fd || sp_net_fill_pos >= sp_net_fill_len) return 0;
    int avail = sp_net_fill_len - sp_net_fill_pos;
    if (max > 0 && avail > max) avail = max;
    memcpy(out, sp_net_fill_buf + sp_net_fill_pos, (size_t)avail);
    sp_net_fill_pos += avail;
    return avail;
}

const char *sp_net_read_line(int fd) {
    size_t pos = 0;
    sp_net_line_buf[0] = '\0';
    if (fd != sp_net_fill_fd) {        /* new connection: drop any stale bytes */
        sp_net_fill_fd  = fd;
        sp_net_fill_len = 0;
        sp_net_fill_pos = 0;
    }
    while (pos + 1 < SP_NET_BUFSIZE) {
        if (sp_net_fill_pos >= sp_net_fill_len) {   /* buffer empty: one recv refills it */
            ssize_t n = recv(fd, sp_net_fill_buf, SP_NET_BUFSIZE, 0);
            if (n == 0) {              /* EOF: return what we have so far */
                sp_net_line_buf[pos] = '\0';
                return sp_net_line_buf;
            }
            if (n < 0) {
                if (errno == EINTR) continue;
                return NULL;
            }
            sp_net_fill_len = (int)n;
            sp_net_fill_pos = 0;
        }
        char c = (char)sp_net_fill_buf[sp_net_fill_pos++];
        if (c == '\n') {              /* strip trailing CR (CRLF or bare LF) */
            if (pos > 0 && sp_net_line_buf[pos - 1] == '\r') pos--;
            sp_net_line_buf[pos] = '\0';
            return sp_net_line_buf;
        }
        sp_net_line_buf[pos++] = c;
    }
    sp_net_line_buf[pos] = '\0';      /* line too long: truncate + return */
    return sp_net_line_buf;
}

/* ---------- read_line-aware close / recv_some (replaces upstream dormant hooks) ----------
 * Callers that used read_line() on an fd must close it via sp_net_rl_close (so the
 * fill buffer is dropped before the fd is recycled), and -- if they switch to raw
 * recv() after read_line() -- read via sp_net_rl_recv_some so any over-read
 * remainder is returned before touching the socket. Upstream's sp_net_close /
 * sp_net_recv_some stay verbatim and are reached for the recv path. */
int sp_net_rl_close(int fd) {
    sp_net_read_line_reset(fd);
    return sp_net_close(fd);
}

const char *sp_net_rl_recv_some(int fd, int maxlen) {
    static char buf[SP_NET_BUFSIZE];
    if (maxlen <= 0 || maxlen >= SP_NET_BUFSIZE) maxlen = SP_NET_BUFSIZE - 1;
    int rem = sp_net_read_line_buffered_remaining(fd, buf, maxlen);
    /* publish sp_net_bin_len so the FFI `:binstr` return mode is binary-safe
       on the read_line-buffered path too (the upstream sp_net_recv_some path below
       already sets it). Needed when a body with embedded NULs follows headers. */
    if (rem > 0) { buf[rem] = '\0'; sp_net_bin_len = rem; return buf; }
    return sp_net_recv_some(fd, maxlen);   /* upstream verbatim recv (sets sp_net_bin_len) */
}

/* ---------- zero-copy static file ---------- */
int sp_net_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode))  return -1;
    return (int)st.st_size;
}

int sp_net_sendfile(int out_fd, const char *path) {
    int in_fd = open(path, O_RDONLY);
    if (in_fd < 0) return -1;
    struct stat st;
    if (fstat(in_fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(in_fd); return -1; }
    off_t off = 0;
    off_t remaining = st.st_size;
    while (remaining > 0) {
        ssize_t sent = sendfile(out_fd, in_fd, &off, (size_t)remaining);
        if (sent <= 0) {
            if (sent < 0 && errno == EINTR) continue;
            close(in_fd);
            return -1;
        }
        remaining -= sent;   /* off advanced by sendfile itself */
    }
    close(in_fd);
    return 0;
}

/* ---------- epoll readiness mux ---------- */
#define SP_NET_EPOLL_MAX 1024
static struct epoll_event sp_net_ep_batch[SP_NET_EPOLL_MAX];
static int sp_net_ep_n = 0, sp_net_ep_i = 0;

int sp_net_epoll_create(void) {
    sp_net_ep_n = 0; sp_net_ep_i = 0;
    return epoll_create1(0);
}

int sp_net_epoll_add(int epfd, int fd) {
    struct epoll_event ev;
    ev.events  = EPOLLIN;
    ev.data.fd = fd;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

int sp_net_epoll_del(int epfd, int fd) {
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

int sp_net_epoll_wait_one(int epfd) {
    if (sp_net_ep_i >= sp_net_ep_n) {
        for (;;) {
            if (sp_net_shutdown_requested()) return -1;
            int n = epoll_wait(epfd, sp_net_ep_batch, SP_NET_EPOLL_MAX, -1);
            if (n > 0) { sp_net_ep_n = n; sp_net_ep_i = 0; break; }
            if (n < 0 && errno == EINTR) { if (sp_net_shutdown_requested()) return -1; continue; }
            return -1;
        }
    }
    return sp_net_ep_batch[sp_net_ep_i++].data.fd;
}

/* ---------- SIGCHLD auto-reap ---------- */
int sp_net_reap_nb(void) {
    int n = 0, status = 0;
    while (waitpid(-1, &status, WNOHANG) > 0) n++;
    return n;
}

/* opt-in SIGCHLD auto-reaper for fork-per-session servers. Without it a session
 * child that _exit()s while the parent is blocked in accept() stays a zombie
 * until the next connection. Only EXITED children are reaped (WNOHANG), so
 * long-lived prefork workers are untouched. */
static void sp_net_sigchld_reap(int sig) {
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) { }
    errno = saved;
}
int sp_net_autoreap_on(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sp_net_sigchld_reap;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    return sigaction(SIGCHLD, &sa, NULL);
}

/* ---------- PTY ---------- */
static pid_t sp_pty_child = -1;

int sp_pty_spawn(const char *cmd, int rows, int cols) {
    struct winsize ws;
    ws.ws_row    = (unsigned short)(rows > 0 ? rows : 24);
    ws.ws_col    = (unsigned short)(cols > 0 ? cols : 80);
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    int master = -1;
    pid_t pid = forkpty(&master, NULL, NULL, &ws);
    if (pid < 0) return -1;
    if (pid == 0) {
        setenv("TERM", "xterm-256color", 1);
        /* UTF-8 locale so vim/less render multibyte; launcher LANG/LC_ALL wins (overwrite=0). */
        setenv("LANG", "C.UTF-8", 0);
        setenv("LC_ALL", "C.UTF-8", 0);
        const char *sh = (cmd && cmd[0]) ? cmd : "/bin/bash";
        execlp(sh, sh, (char *)NULL);
        _exit(127);
    }
    sp_pty_child = pid;
    return master;
}

int sp_pty_set_winsize(int fd, int rows, int cols) {
    struct winsize ws;
    ws.ws_row    = (unsigned short)(rows > 0 ? rows : 24);
    ws.ws_col    = (unsigned short)(cols > 0 ? cols : 80);
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    return ioctl(fd, TIOCSWINSZ, &ws);
}

/* ---------- PTY raw read/write ---------- */
/* The PTY master is a character device, not a socket, so send()/recv()
 * (sp_net_write_bytes / sp_net_recv_some) fail on it with ENOTSOCK. These
 * read(2)/write(2) primitives let the Ruby side pump bytes to/from the pty.
 * WebSocket frame parse/unmask/build now lives entirely in Ruby
 * (serve_deck_pty.rb), so the former sp_ws_pump_* / sp_ws_send_frame C shims
 * are gone -- the :binstr FFI return mode makes binary-safe frame handling
 * possible in Ruby. */
static unsigned char sp_pty_buf[SP_NET_BUFSIZE];

/* read up to maxlen bytes from the pty master; binary-safe for the FFI :binstr
 * return mode (byte count published in sp_net_bin_len). "" (len 0) = EOF/error. */
const char *sp_pty_read(int fd, int maxlen) {
    if (maxlen <= 0 || maxlen > SP_NET_BUFSIZE - 1) maxlen = SP_NET_BUFSIZE - 1;
    ssize_t n;
    for (;;) {
        n = read(fd, sp_pty_buf, (size_t)maxlen);
        if (n >= 0) break;
        if (errno == EINTR) continue;
        n = 0; break;
    }
    sp_pty_buf[n] = '\0';
    sp_net_bin_len = (int)n;
    return (const char *)sp_pty_buf;
}

/* write all n bytes to the pty master (NUL-safe). Returns n, or -1 on error. */
int sp_pty_write(int fd, const char *data, int n) {
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t w = write(fd, data + off, (size_t)n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return n;
}

#endif /* _WIN32 */
