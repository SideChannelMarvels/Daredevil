/* ===================================================================== */
/* This file is part of Daredevil                                        */
/* Daredevil is a side-channel analysis tool                             */
/* Copyright (C) 2016                                                    */
/* Original author:   Paul Bottinelli <paulbottinelli@hotmail.com>       */
/* Contributors:      Joppe Bos <joppe_bos@hotmail.com>                  */
/*                    Philippe Teuwen <phil@teuwen.org>                  */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#include "utils.h"
#include "des.h"
#include "aes.h"

/* The following was largely inspired from
 * - Andrey Panin's implementation for Dovecot under the
 *    GNU Lesser General Public License (LGPL), itself
 *    inspired from
 * - the DES implementation by Phil Karn
 * - The SMB implementation by Christopher R. Hertel:
 *   http://www.ubiqx.org/proj/libcifs/source/Auth/DES.c
 */


/* DES initial permutation
 */
static const uint8_t InitialPermutation[64] = {
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
  56, 48, 40, 32, 24, 16, 8, 0,
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6
};


static const uint8_t KeyPermutation[56] = {
  49, 42, 35, 28, 21, 14,  7,  0,
  50, 43, 36, 29, 22, 15,  8,  1,
  51, 44, 37, 30, 23, 16,  9,  2,
  52, 45, 38, 31, 55, 48, 41, 34,
  27, 20, 13,  6, 54, 47, 40, 33,
  26, 19, 12,  5, 53, 46, 39, 32,
  25, 18, 11,  4, 24, 17, 10,  3
};

static const uint8_t KeyRotation[16] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t KeyRotationAtRound[16] = {
  1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

static const uint8_t KeyCompression[48] = {
  13, 16, 10, 23,  0,  4,  2, 27,
  14,  5, 20,  9, 22, 18, 11,  3,
  25,  7, 15,  6, 26, 19, 12,  1,
  40, 51, 30, 36, 46, 54, 29, 39,
  50, 44, 32, 47, 43, 48, 38, 55,
  33, 52, 45, 41, 49, 35, 28, 31
};

static const uint8_t DataExpansion[48] = {
  31,  0,  1,  2,  3,  4,  3,  4,
  5,  6,  7,  8,  7,  8,  9, 10,
  11, 12, 11, 12, 13, 14, 15, 16,
  15, 16, 17, 18, 19, 20, 19, 20,
  21, 22, 23, 24, 23, 24, 25, 26,
  27, 28, 27, 28, 29, 30, 31,  0
};

/* PC1 with entries -1 as indexed starting at 0 in c.
 */
static const uint8_t PC1[56] = {
  56, 48, 40, 32, 24, 16, 8, 0,
  57, 49, 41, 33, 25, 17, 9, 1,
  58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 62, 54, 46, 38,
  30, 22, 14, 6, 61, 53, 45, 37,
  31, 21, 13, 5, 60, 52, 44, 36,
  28, 20, 12, 4, 27, 20, 11, 3
};

/* P with entries -1 as indexed starting at 0 in c.
 */
static const uint8_t P[32] = {
  15, 6, 19, 20, 28, 11, 27, 16,
  0, 14, 22, 25, 4, 17, 30, 9,
  1, 7, 23, 13, 31, 26, 2, 8,
  18, 12, 29, 5, 21, 10, 3, 24
};

/* Macros to work on individual bits
 */
#define CLRBIT(STR, IDX) ((STR)[(IDX)/8] &= ~(0x01 << (7 - ((IDX)%8))))
#define SETBIT( STR, IDX ) ( (STR)[(IDX)/8] |= (0x01 << (7 - ((IDX)%8))) )
#define GETBIT( STR, IDX ) (( ((STR)[(IDX)/8]) >> (7 - ((IDX)%8)) ) & 0x01)


/* Converts the round key (which is an array of 6 bytes) into into an array
 * of 8 6-bit values. Store this array in an array of 8 bytes.
 * This is not part of the DES algorithm, but is used when printing the
 * target key parts.
 */
void convert_rkey(uint8_t rkey[6], uint8_t dst[8])
{
  dst[0] = rkey[0] >> 2;
  dst[1] = ((rkey[0] & 0x03) << 4) | (rkey[1] >> 4);
  dst[2] = ((rkey[1] & 0x0f) << 2) | (rkey[2] >> 6);
  dst[3] = rkey[2] & 0x3f;

  dst[4] = rkey[3] >> 2;
  dst[5] = ((rkey[3] & 0x03) << 4) | (rkey[4] >> 4);
  dst[6] = ((rkey[4] & 0x0f) << 2) | (rkey[5] >> 6);
  dst[7] = rkey[5] & 0x3f;

}

/* This function returns the offset required for the small sboxes, i.e.
 * the first and the last of the 6 bits value val
 */
static uint8_t get_offset(uint8_t val)
{
  return (val & 0x20) >> 4 | (val & 0x1);
}

/* Returns the 4 midlle bits of the 6-bit value val
 */
uint8_t get_4_middle_bits(uint8_t val)
{
  return (val & 0x1E) >> 1;
}

static void permute(uint8_t *dst, const uint8_t *src,
    const uint8_t * map, const int mapsize)
{
  int bitcount;
  int i;

  /* Clear all bits in the destination. */
  for (i = 0; i < mapsize; i++)
    dst[i] = 0;

  /* Set destination bit if the mapped source bit it set. */
  bitcount = mapsize * 8;
  for (i = 0; i < bitcount; i++) {
    if (GETBIT(src, map[i]))
      SETBIT(dst, i);
  }
}
static void permuteinv(uint8_t *dst, const uint8_t *src,
    const uint8_t * map, const int mapsize)
{
  int bitcount;
  int i;

  /* Clear all bits in the destination. */
  for (i = 0; i < mapsize; i++)
    dst[i] = 0;

  /* Set destination bit if the mapped source bit it set. */
  bitcount = mapsize * 8;
  for (i = 0; i < bitcount; i++) {
    if (GETBIT(src, i))
      SETBIT(dst, map[i]);
  }
}
/*
 * Split the 56-bit key in half & left rotate each half by <numbits> bits.
 */
static void keyshift( uint8_t * key, const int numbits )
{
  int   i;
  uint8_t keep = key[0];  /* Copy the highest order bits of the key. */

  /* Repeat the shift process <numbits> times.
   */
  for( i = 0; i < numbits; i++ )
  {
    int j;

    /* Shift the entire thing, byte by byte.
     */
    for( j = 0; j < 7; j++ )
    {
      if( j && (key[j] & 0x80) )  /* If the top bit of this byte is set. */
        key[j-1] |=  0x01;        /* ...shift it to last byte's low bit. */
      key[j] <<= 1;               /* Then left-shift the whole byte.     */
    }

    /* Now move the high-order bits of each 28-bit half-key to their
     * correct locations.
     * Bit 27 is the lowest order bit of the first half-key.
     * Before the shift, it was the highest order bit of the 2nd half-key.
     */
    if( GETBIT( key, 27 ) )     /* If bit 27 is set... */
    {
      CLRBIT( key, 27 );        /* ...clear bit 27. */
      SETBIT( key, 55 );        /* ...set lowest order bit of 2nd half-key. */
    }

    /* We kept the highest order bit of the first half-key in <keep>.
     * If it's set, copy it to bit 27.
     */
    if( keep & 0x80 )
      SETBIT( key, 27 );

    /* Rotate the <keep> byte too, in case <numbits> is 2 and there's
     * a second round coming.
     */
    keep <<= 1;
  }
}

int gen_inverse_key_bit_map(int round, uint8_t map[48])
{
  int rotation = KeyRotationAtRound[round];
  int i, j;
  uint8_t pc1[56];

  /* We copy the static array PC1 into the temporary array pc1
   */
  for (i = 0; i < 56; i++) pc1[i] = PC1[i];

  /* We rotate by the correct number according to the key schedule
   */
  for (i = 0; i < rotation; i++){
    uint8_t tmp1 = pc1[0];
    uint8_t tmp2 = pc1[28];
    for (j = 0; j < 27; j++){
      pc1[j] = pc1[j+1];
      pc1[j + 28] = pc1[j+29];
    }
    pc1[27] = pc1[tmp1];
    pc1[55] = pc1[tmp2];
  }

  /* We generate the final mapping. This means that the bit at position
   * i in the 48 internal key bits corresponds to map[i] of the original
   * key.
   */
  for (i = 0; i < 48; i++) map[i] = pc1[KeyCompression[i]];

  return 0;
}

/* Given the secret key and the corresponding round, computes the round key
 * and stores it into dst
 */
int get_round_key(uint8_t * key, uint8_t * dst, uint8_t round)
{
  uint8_t i;
  uint8_t tmp[7];
  uint8_t K[7];       /* Holds the key, as we manipulate it.          */
  uint8_t SubK[6];
  static const uint8_t map8to7[56] =
  {
    0,  1,  2,  3,  4,  5,  6,
    8,  9, 10, 11, 12, 13, 14,
    16, 17, 18, 19, 20, 21, 22,
    24, 25, 26, 27, 28, 29, 30,
    32, 33, 34, 35, 36, 37, 38,
    40, 41, 42, 43, 44, 45, 46,
    48, 49, 50, 51, 52, 53, 54,
    56, 57, 58, 59, 60, 61, 62
  };

  if( (NULL == dst) || (NULL == key) )
    return -1;

  /* We first convert the 8-byte key to the 7-byte used in DES
   */
  permute( tmp, key, map8to7, 7 );

  /* Initial Key permutation
   */
  permute( K, tmp, KeyPermutation, 7 );

  for (i = 0; i < round + 1; i++){
    /* Generate the subkey for this round. */
    keyshift(K, KeyRotation[i]);
    permute(SubK, K, KeyCompression, 6);

  }
  for(i = 0; i < 6; i++) dst[i] = SubK[i];
  return 0;
}

template <class TypeGuess> int construct_guess_DES (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t pos, uint16_t * sbox, uint32_t n_keys, int8_t bit)
{

  TypeGuess **mem = NULL;
  uint32_t i, nrows = 0;
  uint8_t j;

  if (R != 0) {
    fprintf (stderr, "[ERROR]: construct_guess_DES: Currently only round 0 is supported.\n");
    return -1;
  }

  for (i=0; i < n_m; i++) {
    if (m[i].n_columns <= bytenum) {
      fprintf (stderr, "[ERROR]: construct_guess_DES: ncolumns (%d) <= bytenum (%d).\n", m[i].n_columns, bytenum);
      return -1;
    }
    nrows += m[i].n_rows;
  }

  if (import_matrices(&mem, m, n_m, 0) < 0) {
    fprintf (stderr, "[ERROR]: import matrix.\n");
    return -1;
  }

  if (*guess == NULL) {
    if (allocate_matrix<TypeGuess> (guess, n_keys, nrows) < 0) {
      fprintf (stderr, "[ERROR]: memory problem.\n");
      free_matrix (&mem, nrows);
      return -1;
    }
  }


  uint8_t D[8]; /* The data block, as we manipulate it. */

  for (i = 0; i < nrows; i++) {

    /* Initial permutation of the data block */
    permute(D, mem[i], InitialPermutation, 8);

    uint8_t LP_1[4];    /* Left half pushed across P */

    /* Push the left half of the data across P */
    if (pos == DES_8_64_ROUND) {
        permuteinv(LP_1, D, P, 4);
    }

    /* The right half of the ciphertext block. */
    uint8_t *R = &(D[4]);
    uint8_t Rexp[6];    /* Expanded right half. */

    /* Expand the right half (R) of the data */
    permute(Rexp, R, DataExpansion, 6);

    /* Extract the 6-bit integer from the Rexp
     */
    int k;
    uint8_t Snum;
    int bitnum = bytenum * 6;
    for (Snum = k = 0; k < 6; k++, bitnum++) {
      Snum <<= 1;
      Snum |= GETBIT(Rexp, bitnum);
    }

    for (j=0; j < n_keys; j++) {

      /* We attack 6 bits of the key. Data is 6*8 bits. We thus need to get
       * the correct 6 bits according to bytenum.
       */
      switch (pos) {
        case DES_8_64:
          if (bit == -1) {
            (*guess)[j][i] = HW (sbox[(uint8_t) bytenum*64 + (Snum ^ j)]);
          } else if (bit >= 0) {
            (*guess)[j][i] = (((sbox[(uint8_t) bytenum*64 + (Snum ^ j)])>>bit)&1);
          }
          break;
        case DES_8_64_ROUND:
          if (bit == -1) {
            (*guess)[j][i] = HW (sbox[(uint8_t) bytenum*64 + (Snum ^ j)] ^ ((LP_1[bytenum >> 1]>>((1-(bytenum & 1))*4))&0xf));
          } else if (bit >= 0) {
            (*guess)[j][i] = (((sbox[(uint8_t) bytenum*64 + (Snum ^ j)] ^ ((LP_1[bytenum >> 1]>>((1-(bytenum & 1))*4))&0xf))>>bit)&1);
          }
          break;
        case DES_32_16:
          if (bit == -1) {
            (*guess)[j][i] = HW(sbox[(bytenum*4+get_offset(Snum^j))*16 + get_4_middle_bits(Snum ^ j)]);
          } else if (bit >= 0) {
            (*guess)[j][i] = (((sbox[(bytenum*4+get_offset(Snum^j))*16 + get_4_middle_bits(Snum ^ j)])>>bit)&1);
          }
          break;
        case DES_4_BITS:
          if (bit == -1) {
            (*guess)[j][i] = HW(get_4_middle_bits(Snum) ^ j);
          } else if (bit >= 0) {
            (*guess)[j][i] = (((get_4_middle_bits(Snum) ^ j)>>bit)&1);
          }
          break;
        case DES_6_BITS:
          if (bit == -1) {
            (*guess)[j][i] = HW(Snum ^ j);
          } else if (bit >= 0) {
            (*guess)[j][i] = (((Snum ^ j)>>bit)&1);
          }
          break;
        default:
          fprintf (stderr, "Error: construct_guess_DES: position %d is not supported.\n", pos);
          free_matrix (&mem, nrows);
          return -1;
      }
    }
  }
  free_matrix (&mem, nrows);
  return 0;
}

template int construct_guess_DES (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t pos, uint16_t * sbox, uint32_t n_keys, int8_t bit);
