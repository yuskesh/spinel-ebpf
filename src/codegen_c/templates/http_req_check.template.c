static __always_inline int spnl_is_http_req(const unsigned char *h) {
    if (h[0]=='G'&&h[1]=='E'&&h[2]=='T'&&h[3]==' ') return 1;
    if (h[0]=='P'&&h[1]=='O'&&h[2]=='S'&&h[3]=='T') return 1;
    if (h[0]=='P'&&h[1]=='U'&&h[2]=='T'&&h[3]==' ') return 1;
    if (h[0]=='H'&&h[1]=='E'&&h[2]=='A'&&h[3]=='D') return 1;
    if (h[0]=='D'&&h[1]=='E'&&h[2]=='L'&&h[3]=='E') return 1;
    if (h[0]=='O'&&h[1]=='P'&&h[2]=='T'&&h[3]=='I') return 1;
    if (h[0]=='P'&&h[1]=='A'&&h[2]=='T'&&h[3]=='C') return 1;
    return 0;
}

