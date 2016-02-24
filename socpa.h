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
#ifndef SOCPA_H
#define SOCPA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <omp.h>
#include "utils.h"
#include "pearson.h"

template <typename TypeTrace, typename TypeReturn, typename TypeGuess>
struct General {

  int start;
  int length;
  int n_traces;
  int global_offset;
  /* The number of columns that we can store in memory. Needed to know when to
   * stop computing correlations in the last slice when computing on big files.
   */
  int n_samples;
  TypeReturn ** precomp_guesses;
  FinalConfig<TypeTrace, TypeReturn, TypeGuess> * fin_conf;

  General(int st, int len, int nt, int go, int nc, TypeReturn ** pg, FinalConfig<TypeTrace, TypeReturn, TypeGuess> * s):
    start(st), length(len), n_traces(nt), global_offset(go), n_samples(nc), precomp_guesses(pg), fin_conf(s){
  }
};


template <typename TypeTrace>
struct PrecompTraces {

  int start;
  int end;
  int length;
  TypeTrace ** trace;

  PrecompTraces(int st, int en, int nt, TypeTrace ** tr):
    start(st), end(en), length(nt), trace(tr) {
  }
};

template <typename TypeGuess, typename TypeReturn>
struct PrecompGuesses {

  int start;
  int end;
  int n_traces;
  TypeGuess ** guess;
  TypeReturn ** precomp_k;

  PrecompGuesses(int st, int en, int n_t, TypeGuess ** gu, TypeReturn ** pk):
    start(st), end(en), n_traces(n_t), guess(gu), precomp_k(pk) {
  }
};

/* Second order and higher order moments cpa for large files
 */
template <class TypeTrace, class TypeReturn, class TypeGuess>
int second_order(Config & conf);

/* Correlation function used when computing second order
 */
template <class TypeTrace, class TypeReturn, class TypeGuess>
void * second_order_correlation(void * args_in);


template <class TypeTrace, class TypeReturn, class TypeGuess>
void * higher_moments_correlation(void * args_in);

/* This function precomputes the mean for the traces and subtract this mean
 * from every element of the traces. This is to be used by the newer v_5 of
 * SOCPA.
 */
  template <class TypeTrace, class TypeReturn>
void * precomp_traces_v_2(void * args_in);

template <class TypeTrace, class TypeReturn, class TypeGuess>
void * precomp_guesses(void * args_in);

/* This functions simply splits the total work (n_rows) into an equal number of
 * threads, creates this amount of threads and starts them to precompute the
 * distance of means for each row of the matrix trace.
 * ! We expect a matrix where the number of traces is n_rows
 */
  template <class TypeTrace, class TypeReturn>
int p_precomp_traces(TypeTrace ** trace, int n_rows, int n_columns, int n_threads, int offset=0);


template <class TypeTrace, class TypeReturn, class TypeGuess>
int split_work(FinalConfig<TypeTrace, TypeReturn, TypeGuess> & fin_conf, void * (*fct)(void *), TypeReturn ** precomp_k, int total_work, int offset=0);

#endif
