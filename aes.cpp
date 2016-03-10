/* ===================================================================== */
/* This file is part of Daredevil                                        */
/* Daredevil is a side-channel analysis tool                             */
/* Copyright (C) 2016                                                    */
/* Original author:   Paul Bottinelli <paulbottinelli@hotmail.com>       */
/* Contributors:      Joppe Bos <joppe_bos@hotmail.com>                  */
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
#include "aes.h"

/* Compute the number of bits set (Hamming weight or poulation count) in a
 * 16 bit integer. See the Bit Twiddling Hacks page:
 * http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
 */
uint8_t HW(uint16_t v)
{
  uint8_t c;                      // c accumulates the total bits set in v
  for (c = 0; v; c++) v &= v - 1; // clear the least significant bit set
  return c;
}

/* Given the messages (m), use the bytenum-th byte to construct
 * the guesses for round R with the specified sbox.
 */
  template <class TypeGuess>
int construct_guess_AES (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit) {
  TypeGuess **mem = NULL;
  uint32_t i, j, nrows = 0;

  if (R != 0) {
    fprintf (stderr, "[ERROR]: construct_guess_AES: Currently only round 0 is supported.\n");
    return -1;
  }

  for (i=0; i < n_m; i++) {
    if (m[i].n_columns <= bytenum) {
      fprintf (stderr, "[ERROR]: construct_guess_AES: ncolumns (%d) <= bytenum (%d).\n", m[i].n_columns, bytenum);
      return -1;
    }
    nrows += m[i].n_rows;
  }

  if (import_matrices(&mem, m, n_m, 0) < 0) {
    fprintf (stderr, "[ERROR]: Importing matrix.\n");
    return -1;
  }
  if (*guess == NULL) {
    if (allocate_matrix<TypeGuess> (guess, n_keys, nrows) < 0) {
      fprintf (stderr, "[ERROR]: Allocating memory for guesses.\n");
      free_matrix (&mem, nrows);
      return -1;
    }
  }

  for (i=0; i < nrows; i++) {
    for (j=0; j < n_keys; j++) {
        if (bit == -1) { /* No individual bits. */
          (*guess)[j][i] = HW ((TypeGuess) sbox[ (uint8_t) mem[i][bytenum] ^ j ]);
        } else if (bit >= 0 && bit < 8) {
          (*guess)[j][i] = (TypeGuess) ((sbox[ (uint8_t) mem[i][bytenum] ^ j ] >> bit)&1);
        }
    }
  }
  free_matrix (&mem, nrows);
  return 0;
}


template int construct_guess_AES (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);
template int construct_guess_AES ( int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

