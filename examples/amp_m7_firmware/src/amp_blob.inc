/* amp_blob.inc -- placeholder. Run build-amp-blob.sh to embed an AOT'd Ruby probe
 * (2-pass host-AOT). With the placeholder in place the firmware falls back to the
 * hand-written producer (amp_blob_installed=0). */
#define AMP_BLOB_MAX 512
static const unsigned char amp_blob[AMP_BLOB_MAX] __attribute__((aligned(8))) = { 0 };
static const volatile int amp_blob_installed = 0;
