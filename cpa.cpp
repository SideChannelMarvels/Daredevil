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
#include <iostream>
#include "cpa.h"
#include "omp.h"


/* Given the messages stored in m, use the bytenum-th byte to construct
 * the guesses for round R for algorithm alg and store the guesses in guess.
 * des_switch is only used by DES
 */
template <class TypeGuess>
int construct_guess (TypeGuess ***guess, uint32_t alg, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t des_switch, uint16_t * sbox, uint32_t n_keys, int8_t bit) {
  int ret;

  switch (alg) {
    case ALG_AES:
      ret = construct_guess_AES (guess, m, n_m, bytenum, R, sbox, n_keys, bit);
      if (ret < 0) return -1;
      break;
    case ALG_DES:
      ret = construct_guess_DES (guess, m, n_m, bytenum, R, des_switch, sbox, n_keys, bit);
      if (ret < 0) return -1;
      break;
    default:
      fprintf (stderr, "Algorithm is not supported (yet).\n");
      return -1;
  }
  return 1;

}

template int construct_guess (uint8_t ***guess, uint32_t alg, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t des_switch, uint16_t * sbox, uint32_t n_keys, int8_t bit);

