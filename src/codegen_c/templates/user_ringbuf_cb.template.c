/* user_ringbuf callback for user_ringbuf__@CB@ */
static long spnl_user_ringbuf_cb_@CB@(struct bpf_dynptr *dynptr, void *_uctx)
{
    @CTYPE@ @PARAM@ = 0;
    bpf_dynptr_read(&@PARAM@, sizeof(@PARAM@), dynptr, 0, 0);
    (void)_uctx;
@BODY@    return 0;
}
