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

#define MIN_FILE_SIZE   18
#define MAX_FILE_SIZE   (10 * 1024 * 1024)
#define DEFAULT_DELAY   50

// Global resources for cleanup
static FILE        *outfp         = NULL;
static int         *g_disp_arr    = NULL;
static bool        *g_local_arr   = NULL;
static int         *g_pixel_arr   = NULL;
static unsigned char *first_pal   = NULL;
static size_t        first_pal_size = 0;
static uint16_t      first_width   = 0;
static uint16_t      first_height  = 0;
static const char   *current_file  = NULL;
static int           first_pixel_index = 0;

// Cleanup function registered with atexit
static void cleanup_resources(void) {
    if (outfp) {
        fflush(outfp);
        if (ferror(outfp)) perror("flushing output");
        fclose(outfp);
        outfp = NULL;
    }
    free(first_pal);
    first_pal = NULL;
    free(g_disp_arr);
    g_disp_arr = NULL;
    free(g_local_arr);
    g_local_arr = NULL;
    free(g_pixel_arr);
    g_pixel_arr = NULL;
}

// Read GIF into memory and validate header
static unsigned char* load_file(const char *path, size_t *out_size,
                                 uint16_t *out_w, uint16_t *out_h) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    if (fseeko(f, 0, SEEK_END) < 0) { perror("fseeko"); fclose(f); return NULL; }
    off_t sz = ftello(f);
    if (sz < MIN_FILE_SIZE || (size_t)sz > MAX_FILE_SIZE) {
        fprintf(stderr, "%s: invalid file size %lld bytes\n", path, (long long)sz);
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fprintf(stderr, "OOM loading %s\n", path); fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { perror("fread"); free(buf); fclose(f); return NULL; }
    fclose(f);
    if (memcmp(buf, "GIF87a", 6) != 0 && memcmp(buf, "GIF89a", 6) != 0) {
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

// Write LZW sub-blocks until zero-length block
static void write_blocks(FILE *out, const unsigned char *buf,
                         size_t start, size_t end) {
    size_t p = start;
    while (p < end) {
        unsigned char n = buf[p++];
        fwrite(&n, 1, 1, out);
        if (n == 0) break;
        if (p + n > end) {
            fprintf(stderr, "Error: LZW block past EOF in %s at %zu\n",
                    current_file, p);
            exit(1);
        }
        fwrite(buf + p, 1, n, out);
        p += n;
    }
}

// Ensure Netscape looping extension exists
static void ensure_loop(FILE *out, const unsigned char *buf,
                        size_t start, size_t end) {
    size_t p = start;
    while (p + 2 < end) {
        if (buf[p]==0x21 && buf[p+1]==0xFF && buf[p+2]==0x0B
            && memcmp(buf+p+3, "NETSCAPE2.0", 11)==0) return;
        if (buf[p]==0x2C || buf[p]==0x3B) break;
        if (buf[p]==0x21) {
            p += 2;
            unsigned char sz = buf[p++];
            while (sz) { p += sz; sz = buf[p++]; }
        } else p++;
    }
    unsigned char ext[] = {0x21,0xFF,0x0B,'N','E','T','S','C','A','P','E','2','.','0',
                           0x03,0x01,0x00,0x00,0x00};
    fwrite(ext, 1, sizeof(ext), out);
}

// Extract global color palette
static unsigned char* extract_palette(const unsigned char *buf, size_t size,
                                      size_t *pal_bytes) {
    if (size < 13 || !(buf[10] & 0x80)) { *pal_bytes = 0; return NULL; }
    int entries = 1 << ((buf[10] & 0x07) + 1);
    *pal_bytes = 3 * entries;
    unsigned char *pal = malloc(*pal_bytes);
    if (!pal) { fprintf(stderr, "%s: OOM palette\n", current_file); exit(1); }
    memcpy(pal, buf + 13, *pal_bytes);
    return pal;
}

// Read one LZW code from bitstream
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
    // Register cleanup
    atexit(cleanup_resources);

    outfp = fopen(argv[1], "wb");
    if (!outfp) {
        perror("fopen");
        return 1;
    }

    int fallback_delay = DEFAULT_DELAY;
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
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing CS value for -fallback-delay\n");
                return 1;
            }
            fallback_delay = atoi(argv[++i]);
            continue;
        }
        current_file = path;
        off_t before = ftello(outfp);

        if (strcmp(path, "dummy") == 0) {
            int target = frame_index - 1;
            while (target >= 0 && g_disp_arr[target] != 1 && g_disp_arr[target] != 0) {
                target--;
            }
            if (target < 0) target = 0;
            int color_index = g_pixel_arr[target];
            bool need_local = g_local_arr[target];
            unsigned char gce[8] = {0x21,0xF9,0x04,0x04,(unsigned char)fallback_delay,0,0,0};
            if (need_local) { gce[3] |= 0x01; gce[6] = 0; }
            fwrite(gce, 1, 8, outfp);
            unsigned char desc[10] = {0x2C,0,0,0,0,1,0,1,0,(unsigned char)(need_local?0x80:0x00)};
            fwrite(desc, 1, 10, outfp);
            if (need_local) {
                unsigned char pal2[6] = {0,0,0,
                    first_pal[3*color_index], first_pal[3*color_index+1], first_pal[3*color_index+2]};
                fwrite(pal2, 1, 6, outfp);
                color_index = 1;
            }
            unsigned char lzw[5] = {2,2,0x4C,(unsigned char)color_index,0};
            fwrite(lzw, 1, 5, outfp);
            fprintf(stderr, "Frame %d: 15 bytes added, disposal=1, delay=%dcs, 1x1px 'dummy'\n", frame_index, fallback_delay);
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

        size_t pal_size;
        unsigned char *pal = extract_palette(buf, buf_size, &pal_size);
        size_t hdr_end = (i == 2 ? 13 + pal_size : 13 + first_pal_size);
        if (i == 2) {
            first_pal = pal;
            first_pal_size = pal_size;
            fwrite(buf, 1, hdr_end, outfp);
            ensure_loop(outfp, buf, hdr_end, buf_size);
        }

        bool found = false;
        for (size_t j = hdr_end; j + 1 < buf_size; j++) {
            if (buf[j] == 0x2C) { found = true; break; }
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
            if (buf[p]==0x21 && buf[p+1]==0xF9) { has_gce = true; gce_pos = p; break; }
            if (buf[p]==0x2C) break;
            if (buf[p]==0x21) {
                p += 2;
                unsigned char sz = buf[p++];
                while (sz) { p += sz; sz = buf[p++]; }
            } else p++;
        }
        unsigned char bs   = has_gce ? buf[gce_pos+2] : 4;
        unsigned char orig = has_gce ? buf[gce_pos+3] : 0;
        int disp = (orig >> 2) & 7;
        if (!disp) disp = 1;
        unsigned int delay = DEFAULT_DELAY;
        if (has_gce) {
            delay = buf[gce_pos+4] | (buf[gce_pos+5] << 8);
            if (!delay) delay = fallback_delay;
        }

        if (i == 2 && has_gce) {
            int code_size = bs;
            int bit_pos   = 0;
            size_t ds     = gce_pos + 2 + 1 + bs + 1;
            unsigned char *data = NULL;
            size_t dlen   = 0;
            size_t q      = ds;
            while (q < buf_size) {
                unsigned char sz = buf[q++];
                if (!sz) break;
                data = realloc(data, dlen + sz);
                memcpy(data + dlen, buf + q, sz);
                dlen += sz;
                q += sz;
            }
            read_lzw_code(data, dlen, code_size, &bit_pos);
            first_pixel_index = read_lzw_code(data, dlen, code_size, &bit_pos);
            free(data);
        }

        unsigned char gce2[8];
        gce2[0] = 0x21;
        gce2[1] = 0xF9;
        gce2[2] = bs;
        gce2[3] = (orig & ~0x1C) | (disp << 2);
        gce2[4] = delay & 0xFF;
        gce2[5] = (delay >> 8) & 0xFF;
        gce2[6] = has_gce ? buf[gce_pos+6] : 0;
        gce2[7] = has_gce ? buf[gce_pos+7] : 0;
        fwrite(gce2, 1, 8, outfp);

        if (has_gce) {
            size_t q = gce_pos + 2;
            unsigned char sz = buf[q++];
            while (sz) { q += sz; sz = buf[q++]; }
            p = q;
        }

        fwrite(buf + p, 1, 9, outfp);
        unsigned char idp = buf[p+9];
        p += 10;

        bool used_local = false;
        size_t lb = 0;
        unsigned char op = idp;
        if (i > 2 && first_pal_size) {
            size_t cs;
            unsigned char *cp = extract_palette(buf, buf_size, &cs);
            bool diff = (cs != first_pal_size) || memcmp(cp, first_pal, first_pal_size);
            free(cp);
            if (diff) {
                used_local = true;
                lb = cs;
                int ents = cs / 3;
                int lg = 0;
                while ((1 << (lg + 1)) <= ents) lg++;
                op = (op & ~0x07) | ((lg ? lg-1 : 0) & 0x07) | 0x80;
                fwrite(&op, 1, 1, outfp);
                fwrite(pal, 1, cs, outfp);
            } else {
                fwrite(&op, 1, 1, outfp);
            }
        } else {
            fwrite(&op, 1, 1, outfp);
        }

        if (idp & 0x80) {
            int entries = 1 << ((idp & 0x07) + 1);
            p += 3 * entries;
        }

        unsigned char lzw_min = buf[p++];
        fwrite(&lzw_min, 1, 1, outfp);
        write_blocks(outfp, buf, p, buf_size);

        g_disp_arr[frame_index]  = disp;
        g_local_arr[frame_index] = used_local;
        g_pixel_arr[frame_index] = first_pixel_index;
        frame_index++;

        if (i > 2) free(pal);
        free(buf);

        off_t after = ftello(outfp);
        fprintf(stderr, "Frame %d: %lld bytes added, disposal=%d, delay=%ucs", frame_index-1, (long long)(after-before), disp, delay);
        if (used_local) fprintf(stderr, ", local palette (%zu bytes)", lb);
        fprintf(stderr, "\n");
    }

    // Write GIF trailer
    unsigned char term = 0x3B;
    fwrite(&term, 1, 1, outfp);
    fflush(outfp);
    if (ferror(outfp)) perror("writing trailer");
    return ret;
}
