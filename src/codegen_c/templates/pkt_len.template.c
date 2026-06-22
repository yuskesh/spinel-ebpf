/* total packet length (data_end - data). Always safe.
 * The intermediate unsigned-long conversion forces the verifier to
 * see both sides as scalars before the subtraction - otherwise pkt_end
 * leaks into downstream arithmetic. */
static __noinline __s64 @SIG@
{
    unsigned long e = (unsigned long)(long)ctx->data_end;
    unsigned long d = (unsigned long)(long)ctx->data;
    return (__s64)(e - d);
}
