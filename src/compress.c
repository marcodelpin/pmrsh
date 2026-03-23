/* compress.c — Simple RLE compression */
#include "sys.h"

int rle_compress(const uint8_t *in, int inlen, uint8_t *out) {
    int oi = 0, i = 0;
    while (i < inlen) {
        /* Check for repeat run (3+) */
        if (i + 2 < inlen && in[i] == in[i+1] && in[i] == in[i+2]) {
            uint8_t val = in[i];
            int run = 1;
            while (i + run < inlen && run < 128 && in[i+run] == val) run++;
            out[oi++] = 0x80 + (run - 1);
            out[oi++] = val;
            i += run;
        } else {
            /* Literal run */
            int start = i, run = 0;
            while (i < inlen && run < 128) {
                if (i + 2 < inlen && in[i] == in[i+1] && in[i] == in[i+2]) break;
                i++; run++;
            }
            out[oi++] = run - 1;
            pm_memcpy(out + oi, in + start, run);
            oi += run;
        }
    }
    return oi;
}

int rle_decompress(const uint8_t *in, int inlen, uint8_t *out) {
    int oi = 0, i = 0;
    while (i < inlen) {
        uint8_t ctrl = in[i++];
        if (ctrl & 0x80) {
            int count = (ctrl & 0x7F) + 1;
            if (i >= inlen) break;
            pm_memset(out + oi, in[i++], count);
            oi += count;
        } else {
            int count = ctrl + 1;
            pm_memcpy(out + oi, in + i, count);
            oi += count; i += count;
        }
    }
    return oi;
}
