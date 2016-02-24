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
#ifndef CPA_H
#define CPA_H

#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include "utils.h"
#include "aes.h"
#include "des.h"
#include "pearson.h"


#define ALG_AES                 0
#define ALG_DES                 1
/*
#define ALG_DES_AFTER           2
#define ALG_DES_BEFORE_SMALL    3
#define ALG_DES_AFTER_SMALL     4
*/

/* Given the messages stored in m, use the bytenum-th byte to construct
 * the guesses for round R at position pos for algorithm alg and store the guesses in guess.
 */
template <class TypeGuess> int construct_guess (TypeGuess ***guess, uint32_t alg, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint32_t pos, uint16_t * sbox, uint32_t n_keys, int8_t bit);

#endif
