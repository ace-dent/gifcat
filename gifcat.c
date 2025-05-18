// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 Andrew Dent <hi@aced.cafe>
//
// gifcat.c
//
// gifcat: Concatenate multiple single-frame GIFs into a single looping animation.
//
// Features:
//   • Preserves raw LZW-compressed image data for pixel-perfect frames.
//   • Maintains transparency, disposal methods, and delay times (defaults applied if missing).
//   • Retains and compares global palettes; embeds local palettes on mismatch.
//   • Inserts a Netscape application extension to enable infinite looping if absent.
//   • Validates inputs: checks GIF signature, file size boundaries,
//     nonzero screen dimensions, presence of an image descriptor, and sub-block bounds.
//   • Ensures subsequent frames fit within the initial screen dimensions.
//   • Supports inserting a 1×1 "dummy" frame referencing the first frame's top-left color.
//
// Usage:
//   gifcat output.gif [-fallback-delay CS] frame0.gif [frame1.gif ...]
//   (use literal "dummy" as input path to append a 1×1 frame with disposal=1 and default delay)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

// -----------------------------------------------------------------------------
// File format constants (per GIF89a specification: https://www.w3.org/Graphics/GIF/spec-gif89a.txt)
// Section 17 & 18: Header is 6 bytes, Logical Screen Descriptor is 7 bytes
// Minimum file size accounts for signature + screen descriptor + trailer
// Maximum size is arbitrary safeguard against excessive memory usage
// -----------------------------------------------------------------------------
static const size_t MIN_FILE_SIZE          = 18;  // min GIF file length in bytes
static const size_t MAX_FILE_SIZE          = 10 * 1024 * 1024; // 10 MB cap

// Default frame delay (hundredths of a second)
// See Graphic Control Extension in Section 23.vii of spec
static const int    DEFAULT_DELAY_CS       = 50;

// -----------------------------------------------------------------------------
// GIF header signature constants: 'GIF87a' and 'GIF89a'
// Section 17: Signature (3 bytes) + Version (3 bytes)
// -----------------------------------------------------------------------------
static const size_t GIF_SIG_LEN = 6;
static const char GIF87a_SIG[6] = "GIF87a";
static const char GIF89a_SIG[6] = "GIF89a";

// -----------------------------------------------------------------------------
// Block introducers and labels
// EXT_INTRODUCER: 0x21 Introduces all extension blocks (Appendix)
// GCE_LABEL: 0xF9 for Graphic Control Extension (Section 23.ii)
// APPLICATION_EXTENSION_LABEL: 0xFF for Application Extension (Section 26.ii)
// IMAGE_SEPARATOR: 0x2C marks Image Descriptor (Section 20.i)
// TRAILER_BYTE: 0x3B marks end of file (Section 27)
// -----------------------------------------------------------------------------
static const unsigned char EXT_INTRODUCER               = 0x21;
static const unsigned char GCE_LABEL                    = 0xF9;
static const unsigned char APPLICATION_EXTENSION_LABEL  = 0xFF;
static const unsigned char IMAGE_SEPARATOR              = 0x2C;
static const unsigned char TRAILER_BYTE                 = 0x3B;

// -----------------------------------------------------------------------------
// Netscape Application Extension details for looping (non-spec but widespread)
// -----------------------------------------------------------------------------
static const unsigned char APP_EXT_BLOCK_SIZE           = 0x0B;
static const char    NETSCAPE2_HDR[11]                  = "NETSCAPE2.0";
static const unsigned char NETSCAPE_LOOP_SUBBLOCK_SIZE  = 0x03;
static const unsigned char NETSCAPE_LOOP_SUBBLOCK_ID    = 0x01;

// -----------------------------------------------------------------------------
// Disposal method flags in GCE packed fields (Section 23.iv)
// Bits 2-4 of the packed byte represent disposal method
// -----------------------------------------------------------------------------
static const int    DISPOSAL_SHIFT        = 2;
static const unsigned char DISPOSAL_MASK               = 0x1C;

// -----------------------------------------------------------------------------
// Local color table flag and size mask (Section 20.vi)
// Bit 7 indicates presence of local color table
// Bits 0-2 give size of table
// -----------------------------------------------------------------------------
static const unsigned char LOCAL_PALETTE_FLAG          = 0x80;
static const unsigned char COLOR_TABLE_SIZE_MASK       = 0x07;

// -----------------------------------------------------------------------------
// Dummy frame LZW data: minimal valid sub-block sequence (Appendix F)
// LZW minimum code size byte + sub-blocks ending in zero-length
// -----------------------------------------------------------------------------
static const unsigned char LZW_MIN_CODE_SIZE_DUMMY     = 2;
static const unsigned char DUMMY_LZW_DATA[5]           = {LZW_MIN_CODE_SIZE_DUMMY, 2, 0x4C, 0, 0};
/*
 TODO: Make sure we are using the minimal code length (bit depth) based on
 actual Global Table Palette entries. e.g. index 1,2 = 1bpp; index 3,4 =2bpp, etc.
 We should be reading the first pixel of the last non-disposal frame (disposal=0 or 1),
 prior to inserting the dummy frame.
 Check for issues requiring a 1bit transparent local color table.
*/

// Globals for output and resource tracking
static FILE           *outfp                   = NULL;
static int            *g_disp_arr              = NULL;
static bool           *g_local_arr             = NULL;
static int            *g_pixel_arr             = NULL;
static unsigned char  *first_palette           = NULL;
static size_t          first_palette_size      = 0;
static uint16_t        first_width             = 0;
static uint16_t        first_height            = 0;
static const char     *current_file            = NULL;
static int             first_pixel_index       = 0;

// Clean up allocated resources at exit
static void cleanup_resources(void) {
    if (outfp) {
        fflush(outfp);
        if (ferror(outfp)) perror("flushing output");
        fclose(outfp);
        outfp = NULL;
    }
    free(first_palette);
    first_palette = NULL;
    free(g_disp_arr);
    g_disp_arr = NULL;
    free(g_local_arr);
    g_local_arr = NULL;
    free(g_pixel_arr);
    g_pixel_arr = NULL;
}

// Load a GIF file into memory, validate signature and dimensions
static unsigned char* load_file(const char *path, size_t *out_size,
                                 uint16_t *out_w, uint16_t *out_h) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    if (fseeko(f, 0, SEEK_END) < 0) { perror("fseeko"); fclose(f); return NULL; }
    off_t sz = ftello(f);
    if (sz < (off_t)MIN_FILE_SIZE || (size_t)sz > MAX_FILE_SIZE) {
        fprintf(stderr, "%s: invalid file size %lld bytes\n", path, (long long)sz);
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fprintf(stderr, "OOM loading %s\n", path); fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { perror("fread"); free(buf); fclose(f); return NULL; }
    fclose(f);
    if (memcmp(buf, GIF87a_SIG, GIF_SIG_LEN) != 0 && memcmp(buf, GIF89a_SIG, GIF_SIG_LEN) != 0) {
        fprintf(stderr, "%s: invalid GIF signature\n", path);
        free(buf);
        return NULL;
    }
    uint16_t w = buf[6] | (buf[7] << 8);
    uint16_t h = buf[8] | (buf[9] << 8);
    if (w == 0 || h == 0) {
        fprintf(stderr, "%s: zero screen dimensions %u×%u\n", path, w, h);
        free(buf);
        return NULL;
    }
    *out_w = w;
    *out_h = h;
    *out_size = (size_t)sz;
    return buf;
}
/*
 TODO: We should validate for multi-frame GIF input.
 Warn the user and only import the first frame present.
*/

// Write LZW sub-blocks until zero-length terminator
static void write_blocks(FILE *out, const unsigned char *buf,
                         size_t start, size_t end) {
    size_t pos = start;
    while (pos < end) {
        unsigned char block_len = buf[pos++];
        fwrite(&block_len, 1, 1, out);
        if (block_len == 0) break;
        if (pos + block_len > end) {
            fprintf(stderr, "Error: LZW block past EOF in %s at %zu\n",
                    current_file, pos);
            exit(1);
        }
        fwrite(buf + pos, 1, block_len, out);
        pos += block_len;
    }
}

// Ensure Netscape loop extension is present
static void ensure_loop(FILE *out, const unsigned char *buf,
                        size_t start, size_t end) {
    size_t pos = start;
    // Scan existing extensions
    while (pos + APP_EXT_BLOCK_SIZE < end) {
        if (buf[pos]==EXT_INTRODUCER && buf[pos+1]==APPLICATION_EXTENSION_LABEL &&
            buf[pos+2]==APP_EXT_BLOCK_SIZE &&
            memcmp(buf+pos+3, NETSCAPE2_HDR, sizeof(NETSCAPE2_HDR))==0)
            return;
        if (buf[pos]==IMAGE_SEPARATOR || buf[pos]==TRAILER_BYTE) break;
        if (buf[pos]==EXT_INTRODUCER) {
            pos += 2;
            unsigned char sz = buf[pos++];
            while (sz) { pos += sz; sz = buf[pos++]; }
        } else pos++;
    }
    // Write Netscape Application Extension
    unsigned char header[] = {EXT_INTRODUCER, APPLICATION_EXTENSION_LABEL, APP_EXT_BLOCK_SIZE};
    fwrite(header, 1, sizeof(header), out);
    fwrite((unsigned char*)NETSCAPE2_HDR, 1, APP_EXT_BLOCK_SIZE, out);
    unsigned char loop_ext[] = {NETSCAPE_LOOP_SUBBLOCK_SIZE, NETSCAPE_LOOP_SUBBLOCK_ID,
                0x00, // loop count LSB=0 for infinite
                0x00, // loop count MSB
                0x00  // block terminator
            };
    fwrite(loop_ext, 1, sizeof(loop_ext), out);
}

// Extract global color table if present
static unsigned char* extract_palette(const unsigned char *buf, size_t size,
                                      size_t *pal_bytes) {
    if (size < 13 || !(buf[10] & LOCAL_PALETTE_FLAG)) { *pal_bytes = 0; return NULL; }
    int entries = 1 << ((buf[10] & COLOR_TABLE_SIZE_MASK) + 1);
    *pal_bytes = 3 * entries;
    unsigned char *palette = malloc(*pal_bytes);
    if (!palette) { fprintf(stderr, "%s: OOM palette\n", current_file); exit(1); }
    memcpy(palette, buf + 13, *pal_bytes);
    return palette;
}

// Read one LZW code from a bitstream
static int read_lzw_code(const unsigned char *data, size_t len,
                         int code_size, int *bit_pos) {
    int bits = code_size + 1;
    int code = 0;
    for (int i = 0; i < bits; i++) {
        int byte_idx = (*bit_pos) >> 3;
        int bit_idx  = (*bit_pos) & 7;
        if (byte_idx < (int)len)
            code |= ((data[byte_idx] >> bit_idx) & 1) << i;
        (*bit_pos)++;
    }
    return code;
}

int main(int argc, char **argv) {
    int ret = 0;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s output.gif [-fallback-delay CS] frame0.gif [frame1.gif ...]\n", argv[0]);
        return 1;
    }
    atexit(cleanup_resources);

    outfp = fopen(argv[1], "wb");
    if (!outfp) { perror("fopen"); return 1; }

    int fallback_delay = DEFAULT_DELAY_CS;
    int max_frames = argc - 2;
    g_disp_arr  = calloc(max_frames, sizeof(int));
    g_local_arr = calloc(max_frames, sizeof(bool));
    g_pixel_arr = calloc(max_frames, sizeof(int));
    if (!g_disp_arr || !g_local_arr || !g_pixel_arr) {
        fprintf(stderr, "OOM allocating frame arrays\n");
        return 1;
    }

    int frame_index = 0;
    for (int i = 2; i < argc; i++) {
        const char *path = argv[i];
        if (strcmp(path, "-fallback-delay") == 0) {
            if (++i >= argc) { fprintf(stderr, "Missing CS value for -fallback-delay\n"); return 1; }
            fallback_delay = atoi(argv[i]);
            continue;
        }
        current_file = path;
        off_t before = ftello(outfp);

        if (strcmp(path, "dummy") == 0) {
            int target = frame_index - 1;
            while (target >= 0 && g_disp_arr[target] != 1 && g_disp_arr[target] != 0) target--;
            if (target < 0) target = 0;
            int color_index = g_pixel_arr[target];
            bool need_local = g_local_arr[target];
            unsigned char gce[8] = {EXT_INTRODUCER, GCE_LABEL, 4,
                                    (unsigned char)(need_local ? 1<<DISPOSAL_SHIFT : 0) | 0x04,
                                    (unsigned char)fallback_delay, 0, 0, 0};
            fwrite(gce, 1, sizeof(gce), outfp);
            unsigned char desc[10] = {IMAGE_SEPARATOR,0,0,0,0,1,0,1,0,
                                      (unsigned char)(need_local ? LOCAL_PALETTE_FLAG : 0)};
            fwrite(desc, 1, sizeof(desc), outfp);
            if (need_local) {
                unsigned char pal2[6] = {0,0,0,
                    first_palette[3*color_index], first_palette[3*color_index+1], first_palette[3*color_index+2]};
                fwrite(pal2, 1, sizeof(pal2), outfp);
                color_index = 1;
            }
            fwrite(DUMMY_LZW_DATA, 1, sizeof(DUMMY_LZW_DATA), outfp);
            fprintf(stderr, "Frame %d: 15 bytes added, disposal=1, delay=%dcs, 1x1px 'dummy'\n",
                    frame_index, fallback_delay);
            frame_index++;
            continue;
        }

        size_t buf_size;
        uint16_t w, h;
        unsigned char *buf = load_file(path, &buf_size, &w, &h);
        if (!buf) return 1;
        if (i == 2) {
            first_width  = w;
            first_height = h;
        } else if (w > first_width || h > first_height) {
            fprintf(stderr, "%s: dimensions %u×%u exceed %u×%u\n",
                    path, w, h, first_width, first_height);
            free(buf);
            return 1;
        }

        size_t palette_bytes;
        unsigned char *palette = extract_palette(buf, buf_size, &palette_bytes);
        size_t hdr_end = (i == 2 ? 13 + palette_bytes : 13 + first_palette_size);
        if (i == 2) {
            first_palette = palette;
            first_palette_size = palette_bytes;
            fwrite(buf, 1, hdr_end, outfp);
            ensure_loop(outfp, buf, hdr_end, buf_size);
        }

        bool found = false;
        for (size_t j = hdr_end; j + 1 < buf_size; j++) {
            if (buf[j] == IMAGE_SEPARATOR) { found = true; break; }
        }
        if (!found) {
            fprintf(stderr, "%s: no image descriptor\n", path);
            free(buf);
            return 1;
        }

        size_t p = hdr_end;
        bool has_gce = false;
        size_t gce_pos = 0;
        while (p + 1 < buf_size) {
            if (buf[p]==EXT_INTRODUCER && buf[p+1]==GCE_LABEL) { has_gce = true; gce_pos = p; break; }
            if (buf[p]==IMAGE_SEPARATOR) break;
            if (buf[p]==EXT_INTRODUCER) {
                p += 2; unsigned char sz = buf[p++]; while (sz) { p += sz; sz = buf[p++]; }
            } else p++;
        }
        unsigned char gce_block_size = has_gce ? buf[gce_pos+2] : 4;
        unsigned char orig_flags     = has_gce ? buf[gce_pos+3] : 0;
        int disposal                 = (orig_flags >> DISPOSAL_SHIFT) & (DISPOSAL_MASK >> DISPOSAL_SHIFT);
        if (!disposal) disposal = 1;
        unsigned int delay           = has_gce ? (buf[gce_pos+4] | (buf[gce_pos+5] << 8)) : DEFAULT_DELAY_CS;
        if (!delay) delay = fallback_delay;

        // Determine first-pixel index for reuse
        if (i == 2 && has_gce) {
            int bit_pos = 0;
            size_t data_start = gce_pos + 2 + 1 + gce_block_size + 1;
            unsigned char *data = NULL;
            size_t dlen = 0;
            size_t q = data_start;
            while (q < buf_size) {
                unsigned char sz = buf[q++];
                if (!sz) break;
                data = realloc(data, dlen + sz);
                memcpy(data + dlen, buf + q, sz);
                dlen += sz;
                q += sz;
            }
            read_lzw_code(data, dlen, gce_block_size, &bit_pos);
            first_pixel_index = read_lzw_code(data, dlen, gce_block_size, &bit_pos);
            free(data);
        }

        // Write updated GCE
        unsigned char gce2[8] = {EXT_INTRODUCER, GCE_LABEL, gce_block_size,
            (unsigned char)((orig_flags & ~DISPOSAL_MASK) | (disposal << DISPOSAL_SHIFT)),
            delay & 0xFF, (delay >> 8) & 0xFF,
            has_gce ? buf[gce_pos+6] : 0,
            has_gce ? buf[gce_pos+7] : 0};
        fwrite(gce2, 1, sizeof(gce2), outfp);

        if (has_gce) {
            size_t q = gce_pos + 2;
            unsigned char sz = buf[q++];
            while (sz) { q += sz; sz = buf[q++]; }
            p = q;
        }

        // Image descriptor and optional local palette handling
        fwrite(buf + p, 1, 9, outfp);
        unsigned char descriptor_byte = buf[p+9];
        p += 10;

        bool used_local_palette = false;
        size_t local_palette_bytes = 0;
        unsigned char packed_fields = descriptor_byte;

        // If the original frame has a local table, compare its entries (ignoring trailing zeros) to the global palette
        if (descriptor_byte & LOCAL_PALETTE_FLAG) {
            int table_size = 1 << ((descriptor_byte & COLOR_TABLE_SIZE_MASK) + 1);
            size_t palette_bytes = 3 * table_size;
            unsigned char *frame_palette = buf + p;

            // Trim trailing 0x00 triplets
            size_t entries = table_size;
            while (entries > 0) {
                size_t idx = entries - 1;
                size_t base = idx * 3;
                if (frame_palette[base] || frame_palette[base + 1] || frame_palette[base + 2]) break;
                entries--;
            }
            size_t effective_bytes = entries * 3;

            // Compare to global palette
            bool match = (first_palette_size >= effective_bytes);
            for (size_t j = 0; match && j < effective_bytes; j++) {
                if (frame_palette[j] != first_palette[j]) match = false;
            }

            if (match) {
                // Drop local palette flag
                packed_fields &= ~LOCAL_PALETTE_FLAG;
                fwrite(&packed_fields, 1, 1, outfp);
            } else {
                // Keep local palette
                used_local_palette = true;
                local_palette_bytes = palette_bytes;
                fwrite(&packed_fields, 1, 1, outfp);
                fwrite(frame_palette, 1, local_palette_bytes, outfp);
            }

            p += palette_bytes;
        } else {
            // No local palette: write packed fields as-is
            fwrite(&packed_fields, 1, 1, outfp);
        }

        unsigned char lzw_min = buf[p++];
        fwrite(&lzw_min, 1, 1, outfp);
        write_blocks(outfp, buf, p, buf_size);

        g_disp_arr[frame_index]      = disposal;
        g_local_arr[frame_index]     = used_local_palette;
        g_pixel_arr[frame_index]     = first_pixel_index;
        frame_index++;

        if (i > 2) free(palette);
        free(buf);

        off_t after = ftello(outfp);
        fprintf(stderr, "Frame %d: %lld bytes added, disposal=%d, delay=%ucs%s",
                frame_index-1,
                (long long)(after-before),
                disposal,
                delay,
                used_local_palette ? ", local palette (" : "\n");
        if (used_local_palette) fprintf(stderr, "%zu bytes)\n", local_palette_bytes);
    }

    // Write GIF trailer
    fwrite((unsigned char[]){TRAILER_BYTE}, 1, 1, outfp);
    fflush(outfp);
    if (ferror(outfp)) perror("writing trailer");
    return ret;
}

/*
 TODO: Future Optimizations:
 - Ensure file only ever has zero or one NETSCAPE (loop) App Extension, that is correctly positioned.
 - Check if all colors are required in a local color table. Remove redundant entries.
 - Scan and concatenate any comment blocks, to reduce some overhead. Optionally remove all comments.
*/
