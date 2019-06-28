/* 
 * generate collisions for truncated md5 hashes
 * e.g., substr(md5($pass), 0, 8)
 * cc -o md5substr md5substr.c -march=native -O4 -funroll-loops -pthread
 *
 * Copyright 2013, epixoip. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS-IS
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <emmintrin.h>

#ifdef __XOP__
#include <x86intrin.h>
#endif

#define INTL 3
#define WIDTH 4
#define COEF (INTL * WIDTH)
#define LENGTH 7
#define START_CHAR 0x21
#define END_CHAR 0x7e
#define CHARS (END_CHAR - START_CHAR)

#if defined(__XOP__) && ! NO_XOP
  #define SIMD  "XOP"
#else
  #define SIMD  "SSE2"
#endif

#if defined(__XOP__) && ! NO_XOP
#define F(x, y, z)                                    \
  tmp[i] = _mm_cmov_si128(y[i], z[i], x[i])

#define G(x, y, z)                                    \
  tmp[i] = _mm_cmov_si128(x[i], y[i], z[i])
#else
#define F(x,y,z)                                      \
  tmp[i] = _mm_xor_si128(y[i], z[i]);                 \
  tmp[i] = _mm_and_si128(x[i], tmp[i]);               \
  tmp[i] = _mm_xor_si128(z[i], tmp[i])

#define G(x,y,z)                                      \
  tmp[i] = _mm_xor_si128(x[i], y[i]);                 \
  tmp[i] = _mm_and_si128(z[i], tmp[i]);               \
  tmp[i] = _mm_xor_si128(y[i], tmp[i])
#endif

#define H(x,y,z)                                      \
  tmp[i] = _mm_xor_si128(x[i], y[i]);                 \
  tmp[i] = _mm_xor_si128(z[i], tmp[i])

#define I(x,y,z)                                      \
  tmp[i] = _mm_or_si128(x[i], ~z[i]);                 \
  tmp[i] = _mm_xor_si128(y[i], tmp[i])

#if ! defined(__XOP__) || NO_XOP
#define _mm_roti_epi32(a, s)                          \
  _mm_or_si128(                                       \
    _mm_slli_epi32(a, s),                             \
    _mm_srli_epi32(a, 32 - s)                         \
  )
#endif

#define STEP_FULL(f, a, b, c, d, x, t, s)             \
  for (i = 0; i < INTL; i++)                          \
  {                                                   \
    f(b, c, d);                                       \
    tmp[i] = _mm_add_epi32(x[i], tmp[i]);             \
    a[i]   = _mm_add_epi32(a[i], _mm_set1_epi32(t));  \
    a[i]   = _mm_add_epi32(tmp[i], a[i]);             \
    a[i]   = _mm_roti_epi32(a[i], s);                 \
    a[i]   = _mm_add_epi32(b[i], a[i]);               \
  }

#define STEP_NULL(f, a, b, c, d, t, s)                \
  for (i = 0; i < INTL; i++)                          \
  {                                                   \
    f(b, c, d);                                       \
    a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(t));    \
    a[i] = _mm_add_epi32(tmp[i], a[i]);               \
    a[i] = _mm_roti_epi32(a[i], s);                   \
    a[i] = _mm_add_epi32(b[i], a[i]);                 \
  }


unsigned char *target;
char *target_str;
int target_len;
int offset;
int np;

const int mod[] = { 0, 8, 16, 24 };

volatile uint64_t counter;
volatile int cracked = 0;

void md5(__m128i md5_block[16][INTL], __m128i md5_digest[4][INTL])
{
    int i = 0;

    __m128i a[INTL], b[INTL], c[INTL], d[INTL];
    __m128i tmp[INTL], length[INTL], init[4];

    init[0] = _mm_set1_epi32(0x67452301);
    init[1] = _mm_set1_epi32(0xefcdab89);
    init[2] = _mm_set1_epi32(0x98badcfe);
    init[3] = _mm_set1_epi32(0x10325476);

    for (i = 0; i < INTL; i++)
    {
        a[i] = init[0];
        b[i] = init[1];
        c[i] = init[2];
        d[i] = init[3];

        length[i] = _mm_set1_epi32(LENGTH * 8);
    }

    STEP_FULL(F, a, b, c, d, md5_block[0], 0xd76aa478,  7);
    STEP_FULL(F, d, a, b, c, md5_block[1], 0xe8c7b756, 12);
    STEP_NULL(F, c, d, a, b,               0x242070db, 17);
    STEP_NULL(F, b, c, d, a,               0xc1bdceee, 22);
    STEP_NULL(F, a, b, c, d,               0xf57c0faf,  7);
    STEP_NULL(F, d, a, b, c,               0x4787c62a, 12);
    STEP_NULL(F, c, d, a, b,               0xa8304613, 17);
    STEP_NULL(F, b, c, d, a,               0xfd469501, 22);
    STEP_NULL(F, a, b, c, d,               0x698098d8,  7);
    STEP_NULL(F, d, a, b, c,               0x8b44f7af, 12);
    STEP_NULL(F, c, d, a, b,               0xffff5bb1, 17);
    STEP_NULL(F, b, c, d, a,               0x895cd7be, 22);
    STEP_NULL(F, a, b, c, d,               0x6b901122,  7);
    STEP_NULL(F, d, a, b, c,               0xfd987193, 12);
    STEP_FULL(F, c, d, a, b, length,       0xa679438e, 17);
    STEP_NULL(F, b, c, d, a,               0x49b40821, 22);
    STEP_FULL(G, a, b, c, d, md5_block[1], 0xf61e2562,  5);
    STEP_NULL(G, d, a, b, c,               0xc040b340,  9);
    STEP_NULL(G, c, d, a, b,               0x265e5a51, 14);
    STEP_FULL(G, b, c, d, a, md5_block[0], 0xe9b6c7aa, 20);
    STEP_NULL(G, a, b, c, d,               0xd62f105d,  5);
    STEP_NULL(G, d, a, b, c,               0x02441453,  9);
    STEP_NULL(G, c, d, a, b,               0xd8a1e681, 14);
    STEP_NULL(G, b, c, d, a,               0xe7d3fbc8, 20);
    STEP_NULL(G, a, b, c, d,               0x21e1cde6,  5);
    STEP_FULL(G, d, a, b, c, length,       0xc33707d6,  9);
    STEP_NULL(G, c, d, a, b,               0xf4d50d87, 14);
    STEP_NULL(G, b, c, d, a,               0x455a14ed, 20);
    STEP_NULL(G, a, b, c, d,               0xa9e3e905,  5);
    STEP_NULL(G, d, a, b, c,               0xfcefa3f8,  9);
    STEP_NULL(G, c, d, a, b,               0x676f02d9, 14);
    STEP_NULL(G, b, c, d, a,               0x8d2a4c8a, 20);
    STEP_NULL(H, a, b, c, d,               0xfffa3942,  4);
    STEP_NULL(H, d, a, b, c,               0x8771f681, 11);
    STEP_NULL(H, c, d, a, b,               0x6d9d6122, 16);
    STEP_FULL(H, b, c, d, a, length,       0xfde5380c, 23);
    STEP_FULL(H, a, b, c, d, md5_block[1], 0xa4beea44,  4);
    STEP_NULL(H, d, a, b, c,               0x4bdecfa9, 11);
    STEP_NULL(H, c, d, a, b,               0xf6bb4b60, 16);
    STEP_NULL(H, b, c, d, a,               0xbebfbc70, 23);
    STEP_NULL(H, a, b, c, d,               0x289b7ec6,  4);
    STEP_FULL(H, d, a, b, c, md5_block[0], 0xeaa127fa, 11);
    STEP_NULL(H, c, d, a, b,               0xd4ef3085, 16);
    STEP_NULL(H, b, c, d, a,               0x04881d05, 23);
    STEP_NULL(H, a, b, c, d,               0xd9d4d039,  4);
    STEP_NULL(H, d, a, b, c,               0xe6db99e5, 11);
    STEP_NULL(H, c, d, a, b,               0x1fa27cf8, 16);
    STEP_NULL(H, b, c, d, a,               0xc4ac5665, 23);
    STEP_FULL(I, a, b, c, d, md5_block[0], 0xf4292244,  6);
    STEP_NULL(I, d, a, b, c,               0x432aff97, 10);
    STEP_FULL(I, c, d, a, b, length,       0xab9423a7, 15);
    STEP_NULL(I, b, c, d, a,               0xfc93a039, 21);
    STEP_NULL(I, a, b, c, d,               0x655b59c3,  6);
    STEP_NULL(I, d, a, b, c,               0x8f0ccc92, 10);
    STEP_NULL(I, c, d, a, b,               0xffeff47d, 15);
    STEP_FULL(I, b, c, d, a, md5_block[1], 0x85845dd1, 21);
    STEP_NULL(I, a, b, c, d,               0x6fa87e4f,  6);
    STEP_NULL(I, d, a, b, c,               0xfe2ce6e0, 10);
    STEP_NULL(I, c, d, a, b,               0xa3014314, 15);
    STEP_NULL(I, b, c, d, a,               0x4e0811a1, 21);
    STEP_NULL(I, a, b, c, d,               0xf7537e82,  6);
    STEP_NULL(I, d, a, b, c,               0xbd3af235, 10);
    STEP_NULL(I, c, d, a, b,               0x2ad7d2bb, 15);
    STEP_NULL(I, b, c, d, a,               0xeb86d391, 21);

    for (i = 0; i < INTL; i++)
    {
        md5_digest[0][i] = _mm_add_epi32(a[i], init[0]);
        md5_digest[1][i] = _mm_add_epi32(b[i], init[1]);
        md5_digest[2][i] = _mm_add_epi32(c[i], init[2]);
        md5_digest[3][i] = _mm_add_epi32(d[i], init[3]);
    }
}

void search(unsigned char *x, int left)
{
    static __thread char plains[COEF][LENGTH + 1];
    static __thread uint64_t plain_count = 0;
    static __thread uint64_t count = 0;

    uint32_t block[16][INTL][WIDTH] __attribute__((aligned(16)));
    uint32_t digest[4][INTL][WIDTH] __attribute__((aligned(16)));
    uint32_t *in_ptr[INTL][WIDTH];

    unsigned char in[INTL][WIDTH][LENGTH + 1];
    unsigned char buf[LENGTH + 1];
    unsigned char c;

    int i, j, p = 0;

    __m128i md5_block[16][INTL], md5_digest[4][INTL];

    for (c = START_CHAR; c <= END_CHAR; c++)
    {
        memcpy(buf, x, LENGTH);

        buf[LENGTH - left] = c;
        buf[LENGTH - left + 1] = 0;

        if (left - 1 > 0)
        {
            search(buf, left - 1);
            continue;
        }

        memcpy(plains[plain_count], buf, LENGTH + 1);

        if (plain_count < COEF - 1)
        {
            plain_count++;
            continue;
        }

        for (i = 0; i < INTL; i++)
            for (j = 0; j < WIDTH; j++)
                in_ptr[i][j] = (uint32_t *) in[i][j];

        p = 0;
        for (i = 0; i < INTL; i++)
            for (j = 0; j < WIDTH; j++)
                memcpy(in[i][j], plains[p++], LENGTH + 1);

        for (i = 0; i < INTL; i++)
            for (j = 0; j < WIDTH; j++)
            {
                block[0][i][j] = in_ptr[i][j][0];
                block[1][i][j] = (in_ptr[i][j][1] & 0x00FFFFFF) | 0x80000000;
            }

        for (i = 0; i < INTL; i++)
        {
            md5_block[0][i] = _mm_load_si128((__m128i *) block[0][i]);
            md5_block[1][i] = _mm_load_si128((__m128i *) block[1][i]);
        }

        md5(md5_block, md5_digest);

        for (i = 0; i < WIDTH; i++)
            for (j = 0; j < INTL; j++)
                _mm_store_si128((__m128i *) digest[i][j], md5_digest[i][j]);

        for (i = 0; i < WIDTH; i++)
        {
            for (j = 0; j < INTL; j++)
            {
                unsigned char hash[16] = {0};
                int byte_count = target_len / 2;
                int word_offset = offset / 2 / 4;
                int byte_offset = offset / 2 % 4;
                int d;

                if (offset % 2 == 0)
                {
                    for (d = 0; d < byte_count; d++, byte_offset++)
                    {
                        if (byte_offset == 4)
                        {
                            byte_offset = 0;
                            word_offset++;
                        }

                        hash[d] = digest[word_offset][j][i] >> mod[byte_offset];
                    }

                    if (target_len % 2)
                    {
                        byte_count++;

                        if (byte_offset == 4)
                        {
                            byte_offset = 0;
                            word_offset++;
                        }

                        hash[d] = digest[word_offset][j][i] >> mod[byte_offset] & 0xf0;
                    }
                }
                else
                {
                    for (d = 0; d < byte_count; d++, byte_offset++)
                    {
                        if (byte_offset == 4)
                        {
                            byte_offset = 0;
                            word_offset++;
                        }

                        hash[d] = digest[word_offset][j][i] >> mod[byte_offset] << 4 & 0xf0;
                    }

                    word_offset = offset / 2 / 4;
                    byte_offset = (offset / 2 % 4) + 1;

                    for (d = 0; d < byte_count; d++, byte_offset++)
                    {
                        if (byte_offset == 4)
                        {
                            byte_offset = 0;
                            word_offset++;
                        }

                        hash[d] |= digest[word_offset][j][i] >> mod[byte_offset] >> 4 & 0x0f;
                    }

                    if (target_len % 2)
                    {
                        byte_count++;
                        byte_offset--;

                        if (byte_offset < 0)
                        {
                            byte_offset = 3;
                            word_offset--;
                        }

                        hash[d] |= digest[word_offset][j][i] >> mod[byte_offset] << 4 & 0xf0;
                    }
                }

                if (memcmp(hash, target, byte_count) == 0)
                {
                    printf("\n%08x%08x%08x%08x:%s\n",
                        (uint32_t) __builtin_bswap32(digest[0][j][i]),
                        (uint32_t) __builtin_bswap32(digest[1][j][i]),
                        (uint32_t) __builtin_bswap32(digest[2][j][i]),
                        (uint32_t) __builtin_bswap32(digest[3][j][i]),
                        in[j][i]
                    );

                    __sync_fetch_and_add(&cracked, 1);
                }
            }
        }

        plain_count = 0;

        if (++count % 500000 == 0)
        {
            __sync_fetch_and_add(&counter, 500000 * COEF);
        }
    }
}

void *dispatch(void *t)
{
    int id = (intptr_t) t;

    int coverage = CHARS / np;
    int start_index = coverage * id;
    int stop_index;

    unsigned char c;

    if (id + 1 < np)
    {
        stop_index = start_index + coverage - 1;
    }
    else
    {
        stop_index = CHARS;
    }

    for (c = START_CHAR + start_index; c < START_CHAR + stop_index; c++)
    {
        search(&c, LENGTH - 1);
    }

    return NULL;
}

void *progress(void *a)
{
    (void) a;

    uint64_t keyspace = pow(CHARS, LENGTH);
    uint64_t elapsed = 0, last = 0;
    uint64_t timer = 15;

    while(1)
    {
        uint64_t current = counter;

        fprintf(stderr, 
            "\nTarget......:  %s\n"
            "Offset......:  %d\n"
            "Found.......:  %d\n"
            "Speed/sec...:  %0.2f MH/s current, %0.2f MH/s average\n"
            "Progress....:  %" PRIu64 "/%" PRIu64 " (%0.2f%%)\n"
            "Running.....:  %" PRIu64 " sec\n",
            target_str, offset, cracked,(float)(current - last) / timer / 1000000,
           (float) counter / elapsed / 1000000, current, keyspace,
           (float) counter / keyspace * 100, elapsed
        );

        fflush(stdout);

        last = current;
        elapsed += timer;

        sleep(timer);
    }
}

int main(int argc, char **argv)
{
    int i = 0, t = 0;

    pthread_attr_t attr_d, attr_p;
    pthread_t progress_t;
    pthread_t *threads;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <target> <offset>\n", argv[0]);
        return(1);
    }

    target_len = strlen(argv[1]);
    assert(target_len < 33);

    target = (unsigned char *) calloc(target_len / 2 + 1, sizeof(char));

    if (target_len % 2)
    {
        for (; i < target_len / 2 + 1; i++)
        {
            sscanf(argv[1] + 2*i, "%02x", (unsigned int *) &target[i]);
        }

        target[target_len / 2] <<= 4;
    }
    else
    {
        for (; i < target_len / 2; i++)
        {
            sscanf(argv[1] + 2*i, "%02x", (unsigned int *) &target[i]);
        }
    }

    target_str = strdup(argv[1]);

    offset = atoi(argv[2]);
    assert(offset >= 0 && offset < 33);
    assert(offset + target_len < 33);

    if ((np = sysconf(_SC_NPROCESSORS_ONLN)) < 0)
        np = 1;

    fprintf(stderr, "\nUsing %d threads, %dx %s\n", np, COEF, SIMD);

    pthread_attr_init(&attr_d);
    pthread_attr_init(&attr_p);

    pthread_attr_setdetachstate(&attr_d, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setdetachstate(&attr_p, PTHREAD_CREATE_DETACHED);

    threads = (pthread_t *) malloc(np * sizeof(pthread_t));

    for (; t < np; t++)
    {
        pthread_create(&threads[t], &attr_d, dispatch, (void *)(intptr_t) t);
    }

    pthread_create(&progress_t, &attr_p, progress, NULL);

    pthread_attr_destroy(&attr_d);
    pthread_attr_destroy(&attr_p);

    for (t = 0; t < np; t++)
    {
        pthread_join(threads[t], NULL);
    }

    free(threads);
    free(target);

    printf("\n");

    return(0);
}
