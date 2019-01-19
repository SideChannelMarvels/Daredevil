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
#ifndef DES_H
#define DES_H

#define DES_8_64       0
#define DES_8_64_ROUND 1
#define DES_32_16      2
#define DES_4_BITS     3
#define DES_6_BITS     4

template <class TypeGuess> int construct_guess_DES (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t pos, uint16_t * sbox, uint32_t n_keys, int8_t bit);

void convert_rkey(uint8_t rkey[6], uint8_t dst[8]);

uint8_t get_4_middle_bits(uint8_t val);

int get_round_key(uint8_t * key, uint8_t * dst, uint8_t round);

int gen_inverse_key_bit_map(int round, uint8_t map[48]);

#endif
