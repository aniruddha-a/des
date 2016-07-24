/*
 * A simple implementation of DES (Data Encryption Algorithm)
 *
 * Sun Dec 20 14:19:33 IST 2009
 * Aniruddha. A (aniruddha.a@gmail.com)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdbool.h>
#include "flblkread.h"
#include "getopts.h"

/* Rotate a 28 bit value left by N */
#define ROL28(X,N)  ( ((X) << N) | ((X) >> (28 - N)) )
/* test if n-th bit in x is set */
#define B_IS_SET(x, n)   (((x) & (1ULL << (n))) ? 1 : 0)
/* set n-th bit in x */
#define B_SET(x, n)      ((x) |= (1ULL << (n)))
/* unset n-th bit in x */
#define B_UNSET(x, n)    ((x) &= ~(1ULL << (n)))
/* Clear above 28th bit */
#define RETAIN_L28  0x000000000fFFFFFFULL
/* Clear above 48th bit */
#define RETAIN_L48  0x0000FFFFFFFFFFFFULL
/* Clear above 32nd bit */
#define RETAIN_L32  0x00000000FFFFFFFFULL
/* Pick the 6 bit S box address from 48 bits */
#define MASK_B8   0x000000000000003FULL
#define MASK_B7   0x0000000000000FC0ULL
#define MASK_B6   0x000000000003F000ULL
#define MASK_B5   0x0000000000FC0000ULL
#define MASK_B4   0x000000003F000000ULL
#define MASK_B3   0x0000000FC0000000ULL
#define MASK_B2   0x000003F000000000ULL
#define MASK_B1   0x0000FC0000000000ULL
#define GET_B8(X) ((X) & MASK_B8 )
#define GET_B7(X) (((X) & MASK_B7) >> 6)
#define GET_B6(X) (((X) & MASK_B6) >> 12)
#define GET_B5(X) (((X) & MASK_B5) >> 18)
#define GET_B4(X) (((X) & MASK_B4) >> 24)
#define GET_B3(X) (((X) & MASK_B3) >> 30)
#define GET_B2(X) (((X) & MASK_B2) >> 36)
#define GET_B1(X) (((X) & MASK_B1) >> 42)

/* Convert a uint64 to 8 chars */
#define MASK_CHAR8  0x00000000000000FFULL
#define MASK_CHAR7  0x000000000000FF00ULL
#define MASK_CHAR6  0x0000000000FF0000ULL
#define MASK_CHAR5  0x00000000FF000000ULL
#define MASK_CHAR4  0x000000FF00000000ULL
#define MASK_CHAR3  0x0000FF0000000000ULL
#define MASK_CHAR2  0x00FF000000000000ULL
#define MASK_CHAR1  0xFF00000000000000ULL
#define GET_CHAR8(X)  (char)((X & MASK_CHAR8))
#define GET_CHAR7(X)  (char)((X & MASK_CHAR7) >> 8)
#define GET_CHAR6(X)  (char)((X & MASK_CHAR6) >> 16)
#define GET_CHAR5(X)  (char)((X & MASK_CHAR5) >> 24)
#define GET_CHAR4(X)  (char)((X & MASK_CHAR4) >> 32)
#define GET_CHAR3(X)  (char)((X & MASK_CHAR3) >> 40)
#define GET_CHAR2(X)  (char)((X & MASK_CHAR2) >> 48)
#define GET_CHAR1(X)  (char)((X & MASK_CHAR1) >> 56)

uint8_t get_s (int s[][16], uint8_t v)
{
    int r = 0, c;
    /* The first bit (5) and last (0) make up the row to S[][] */
    if (B_IS_SET(v, 5))
        r += 2;
    if (B_IS_SET(v,0))
        r += 1;
    /* Mid 4 bits make up the col to S[][]*/
    c = ((v & 0x1E) >> 1);
    return s[r][c];
}

uint64_t char_to_int64 (char *s)
{
    uint64_t t = 0;
    int i,j;

    for (i = 0, j = 56; i < 8; i++, j-=8)
        t |= ((uint64_t)s[i] << j);
    return t;
}

void int64_to_char (uint64_t v)
{
    printf("%c%c%c%c%c%c%c%c",
            GET_CHAR1(v), GET_CHAR2(v), GET_CHAR3(v),
            GET_CHAR4(v), GET_CHAR5(v), GET_CHAR6(v),
            GET_CHAR7(v), GET_CHAR8(v));
}

/* Permuted choice 1 */
int PC1[]= {
              57,   49,    41,   33,    25,    17,    9,
               1,   58,    50,   42,    34,    26,   18,
              10,    2,    59,   51,    43,    35,   27,
              19,   11,     3,   60,    52,    44,   36,
              63,   55,    47,   39,    31,    23,   15,
               7,   62,    54,   46,    38,    30,   22,
              14,    6,    61,   53,    45,    37,   29,
              21,   13,     5,   28,    20,    12,    4,
};

/* Rotation in Key-Schedule */
int CD_shift[] = {
 999, /* Dummy C0 D0 will be pre computed*/
  1,
  1,
  2,
  2,
  2,
  2,
  2,
  2,
  1,
  2,
  2,
  2,
  2,
  2,
  2,
  1,
};

/* Permuted choice 2 */
int PC2[] = {
                 14,    17,   11,    24,     1,    5,
                  3,    28,   15,     6,    21,   10,
                 23,    19,   12,     4,    26,    8,
                 16,     7,   27,    20,    13,    2,
                 41,    52,   31,    37,    47,   55,
                 30,    40,   51,    45,    33,   48,
                 44,    49,   39,    56,    34,   53,
                 46,    42,   50,    36,    29,   32,
};

/* Initial Permutation */
int IP[] ={
            58,    50,   42,    34,    26,   18,    10,    2,
            60,    52,   44,    36,    28,   20,    12,    4,
            62,    54,   46,    38,    30,   22,    14,    6,
            64,    56,   48,    40,    32,   24,    16,    8,
            57,    49,   41,    33,    25,   17,     9,    1,
            59,    51,   43,    35,    27,   19,    11,    3,
            61,    53,   45,    37,    29,   21,    13,    5,
            63,    55,   47,    39,    31,   23,    15,    7,
};

/* Expansion Function */
int E[] = {
                 32,     1,    2,     3,     4,    5,
                  4,     5,    6,     7,     8,    9,
                  8,     9,   10,    11,    12,   13,
                 12,    13,   14,    15,    16,   17,
                 16,    17,   18,    19,    20,   21,
                 20,    21,   22,    23,    24,   25,
                 24,    25,   26,    27,    28,   29,
                 28,    29,   30,    31,    32,    1,
};

/* The S (Substitution) Boxes */
int S1[4][16]={
  {  14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7 },
  {   0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8 },
  {   4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0 },
  {  15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13 }
};
int S2[4][16]={
  {  15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10 },
  {   3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5 },
  {   0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15 },
  {  13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9 },
};
int S3[4][16]={
  {  10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8 },
  {  13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1 },
  {  13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7 },
  {   1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12 },
};
int S4[4][16]={
  {   7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15 },
  {  13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9 },
  {  10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4 },
  {   3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14 },
};
int S5[4][16]={
  {   2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9 },
  {  14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6 },
  {   4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14 },
  {  11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3 },
};
int S6[4][16]={
  {  12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11 },
  {  10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8 },
  {   9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6 },
  {   4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13 },
};
int S7[4][16] = {
   {  4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1 },
   { 13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6 },
   {  1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2 },
   {  6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12 },
};
int S8[4][16] = {
   { 13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0 , 12,  7 },
   {  1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14 ,  9,  2 },
   {  7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3 ,  5,  8 },
   {  2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5 ,  6, 11 }
};

/* Permutation */
int P[]={
  16,   7,  20,  21,
  29,  12,  28,  17,
  1 ,  15,  23,  26,
  5 ,  18,  31,  10,
  2 ,  8 ,  24,  14,
  32,  27,   3,   9,
  19,  13,  30,   6,
  22,  11,   4,  25,
};

/* IP inverse (Final Permutation) */
int IP1[]={
            40,     8 ,  48 ,   16 ,   56 ,  24 ,   64 ,  32,
            39,     7,   47,    15,    55,   23,    63,   31,
            38,     6,   46,    14,    54,   22,    62,   30,
            37,     5,   45,    13,    53,   21,    61,   29,
            36,     4,   44,    12,    52,   20,    60,   28,
            35,     3,   43,    11,    51,   19,    59,   27,
            34,     2,   42,    10,    50,   18,    58,   26,
            33,     1,   41,     9,    49,   17,    57,   25,
};

int main (int argc, char *argv[])
{
    int i, j, k, l;
    uint64_t key , M=0, C=0;
    uint64_t tmp;
    uint64_t kplus = 0;
    struct {
        uint32_t C,D; /* we only use 28 bits in each of these */
    } CD_set[17] ;
    uint64_t K_set[17] = {0};/* we only use 48 bits in each (K_set[0] unused)*/
    uint64_t CDi = 0;
    uint64_t ip=0;
    struct {
        uint32_t L, R;
    } LR_set[17];
    uint64_t ERi = 0;
    uint8_t  B1, B2, B3, B4, B5, B6, B7, B8;
    uint32_t SBi, f=0;
    uint64_t RL;
    int encode, decode;
    char *file, *keystr;
    char *data ;
    char chunk[17] = {0};
    bool pad = false;

    handle_args (argc, argv, &encode, &decode, &file, &keystr);
    if (encode)
        pad = true;
    if (! (l = flblkread(file, &data, pad)))
        return 1;

    key = char_to_int64 (keystr);

    /*
     * Note: When the standard says bit 'N',
     *       They mean, from left (1 based)
     *       We have to translate it to 0 based
     *       (and from right - obviously, we use C ;-) )
     */
    for ( i = 0; i < (sizeof PC1 / sizeof PC1[0]); i++)
    {
        /* K+ has only 56 bits from K */
        if (B_IS_SET(key, 64 - PC1[i] ))
            B_SET(kplus, 56 - (i+1) );
        else
            B_UNSET(kplus, 56 - (i+1) );
    }

    /*
     * Now we have the permuted key kplus
     * and we have to split into 2 halves with 28 bits
     */
    CD_set[0].C = (kplus >> 28 ); /* C0 is the left part of key (kplus) (MSB)*/
    CD_set[0].D = (kplus & RETAIN_L28 );

    /* Compute C1 D1 .. C16 D16*/
    for (i = 1; i < (sizeof CD_shift / sizeof CD_shift[0]) ;i++) {
        CD_set[i].C = ROL28(CD_set[i - 1].C, CD_shift[i]);
        CD_set[i].D = ROL28(CD_set[i - 1].D, CD_shift[i]);
        CD_set[i].C &= RETAIN_L28;
        CD_set[i].D &= RETAIN_L28;
    }

    /* Concat the C D sets and for each, apply PC2 to get K_sets 1 .. 16 */
    for (i = 1; i < (sizeof K_set / sizeof K_set[0]) ; i++) {
        CDi = (((uint64_t)CD_set[i].C << 28 ) | CD_set[i].D );
        /* Create Ki by permuting bits from CDi */
        for (j = 0; j < (sizeof PC2 / sizeof PC2[0]);j++)
        {
            /*  Ki set has only 48 bits from CDi */
            if (B_IS_SET(CDi, 56 - PC2[j] ))
                B_SET(K_set[i], 48 - (j+1) );
            else
                B_UNSET(K_set[i], 48 - (j+1) );
        }
    }

    /* Now for the message */
    while (l >= 8) {
        if (decode) {
            strncpy(chunk, data, 16);
            chunk[16] = '\0';
            M = strtoull(chunk, NULL, 16);
        } else {
            strncpy(chunk, data, 8);
            chunk[8] = '\0';
            M = char_to_int64 (chunk);
        }

        for (i = 0; i < (sizeof IP / sizeof IP[0]); i++)
        {
            if (B_IS_SET(M, 64 - IP[i] ))
                B_SET(ip, 64 - (i+1) );
            else
                B_UNSET(ip, 64 - (i+1) );
        }
        LR_set[0].L = (ip >> 32);
        LR_set[0].R = (ip & RETAIN_L32);

        for (i = 1; i < 17; i++) {
            for (j = 0; j < (sizeof E / sizeof E[0]); j++)
            {
                /* By Applying E we are converting R from 32 to 48 (ERi) */
                if (B_IS_SET( LR_set[i - 1].R, 32 - E[j] ))
                    B_SET(ERi, 48 - (j+1) );
                else
                    B_UNSET(ERi, 48 - (j+1) );
            }
            LR_set[i].L = LR_set[i - 1].R;

            /* Compute f(Ri-1, ki) */
            if (encode)
                tmp = K_set[i] ^ ERi; /* Apply 1 .. 16 */
            else
                tmp = K_set[17 - i] ^ ERi; /* Apply 16 .. 1 */

            /* Break up Ki ^ ERi into 6 bit pieces */
            B1 = GET_B1(tmp);
            B2 = GET_B2(tmp);
            B3 = GET_B3(tmp);
            B4 = GET_B4(tmp);
            B5 = GET_B5(tmp);
            B6 = GET_B6(tmp);
            B7 = GET_B7(tmp);
            B8 = GET_B8(tmp);

            /*
             * Run the 6 bit chunks through S boxes ... i.e,
             * Get a 32 bit value SB from K ^ ER (which is 48 bit)
             */
            SBi =
                (get_s(S1,B1) << 28) |
                (get_s(S2,B2) << 24) |
                (get_s(S3,B3) << 20) |
                (get_s(S4,B4) << 16) |
                (get_s(S5,B5) << 12) |
                (get_s(S6,B6) <<  8) |
                (get_s(S7,B7) <<  4) |
                (get_s(S8,B8)      ) ;

            for (k = 0; k < (sizeof P / sizeof P[0]); k++)
            {
                if (B_IS_SET(SBi, 32 - P[k] ))
                    B_SET(f, 32 - (k+1) );
                else
                    B_UNSET(f, 32 - (k+1) );
            }

            /* Compute  Ri = Li-1 ^ f */
            LR_set[i].R = (LR_set[i - 1].L ^ f);
        }

        RL = ( ((uint64_t)LR_set[16].R << 32) | LR_set[16].L);

        /* Apply IP inverse */
        for (i = 0; i < (sizeof IP1 / sizeof IP1[0]); i++)
        {
            if (B_IS_SET(RL, 64 - IP1[i] ))
                B_SET(C, 64 - (i+1) );
            else
                B_UNSET(C, 64 - (i+1) );
        }
        if (encode) {
            printf("%016"PRIX64, C);
            l -= 8;
            data += 8;
        } else {
            int64_to_char(C);
            l -= 16;
            data += 16;
        }
    } /* for each 8 byte chunk of message*/
    printf("\n");
    //free(data); // I cant free data as I have moved the ptr ;-)
    return 0;
}
