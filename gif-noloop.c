#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 65536

// Returns 1 if the block at p is a NETSCAPE2.0 App Extension
int is_netscape_block(unsigned char *p) {
    return p[0] == 0x21 && p[1] == 0xFF && p[2] == 0x0B &&
           memcmp(p + 3, "NETSCAPE2.0", 11) == 0;
}

// Skip sub-blocks (returns offset to byte after 0x00 terminator)
size_t skip_sub_blocks(unsigned char *p, size_t max_len) {
    size_t i = 0;
    while (i < max_len) {
        unsigned char len = p[i];
        if (len == 0x00) return i + 1;
        i += 1 + len;
    }
    return 0; // malformed
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s input.gif output.gif\n", argv[0]);
        return 1;
    }

    // Load file
    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror("Input");
        return 1;
    }
    fseek(in, 0, SEEK_END);
    long fsize = ftell(in);
    rewind(in);
    unsigned char *buf = malloc(fsize);
    if (!buf) { fclose(in); return 1; }
    fread(buf, 1, fsize, in);
    fclose(in);

    // Allocate output buffer
    unsigned char *out = malloc(fsize);
    if (!out) { free(buf); return 1; }

    size_t r = 0, w = 0;
    while (r + 16 < (size_t)fsize) {
        if (is_netscape_block(&buf[r])) {
            // Skip 3 + 11 = 14 bytes (header + NETSCAPE2.0)
            size_t skip = skip_sub_blocks(&buf[r + 14], fsize - r - 14);
            if (skip == 0) break; // malformed, stop
            r += 14 + skip; // skip entire block
        } else {
            out[w++] = buf[r++];
        }
    }
    // Copy remaining bytes
    while (r < (size_t)fsize) out[w++] = buf[r++];

    // Write output
    FILE *outf = fopen(argv[2], "wb");
    if (!outf) {
        perror("Output");
        free(buf); free(out);
        return 1;
    }
    fwrite(out, 1, w, outf);
    fclose(outf);

    printf("✓ Stripped NETSCAPE blocks from '%s' → '%s' (%zu → %zu bytes)\n", argv[1], argv[2], (size_t)fsize, w);

    free(buf);
    free(out);
    return 0;
}
