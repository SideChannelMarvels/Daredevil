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
#ifndef FOCPA_H
#define FOCPA_H

/* First order cpa for large files
 */
template <class TypeTrace, class TypeReturn, class TypeGuess>
int first_order(Config & conf);


/* Implements first order CPA in a faster and multithreaded way on big files,
 * using the horizontal partitioning approach.
 */
//  template <class TypeTrace, class TypeReturn, class TypeGuess>
//int first_order_big_files_HP(Config & conf);

/* This function computes the first order correlation between a subset
 * of the traces defined in the structure passed as argument and all the
 * key guesses.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
void * correlation_first_order(void * args_in);

#endif
