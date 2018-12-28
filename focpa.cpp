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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <omp.h>
#include <sstream>
#include "pearson.h"
#include "cpa.h"
#include "utils.h"
#include "string.h"
#include "focpa.h"
#include "socpa.h"

extern pthread_mutex_t pt_lock;

/* Implements first order CPA in a faster and multithreaded way on big files,
 * using the vertical partitioning approach.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
int first_order(Config & conf)
{

  long int memory = conf.memory;

  double start, end;

  int res,
      n_keys = conf.total_n_keys,
      n_samples = conf.n_samples,
      nmat = conf.n_file_trace,
      nrows = conf.total_n_traces,
      ncol = min(get_ncol<TypeTrace>(memory-(nrows*n_keys*sizeof(TypeGuess)), nrows), n_samples),
      col_incr = ncol,
      col_offset = 0,
      row_offset = 0,
      sample_offset = 0,
      cur_n_rows, cur_n_cols,
      samples_loaded = 0,
      to_load = ncol;

  uint8_t is_last_iter = 0;
  unsigned int max_n_rows = 0;


  TypeTrace ** traces = NULL;
  TypeTrace ** tmp = NULL;
  TypeGuess ** guesses = NULL;
  TypeReturn ** precomp_k;

  if (col_incr <= 0) {
    fprintf(stderr, "[ERROR] Invalid parameters ncol(=%i).\n", ncol);
    return -1;
  }

  /* We determine the size of the file having the largest number of rows, to
   * allocate memory for tmp.
   */
  for (int i = 0; i < nmat; i++){
    if(conf.traces[i].n_rows > max_n_rows)
      max_n_rows = conf.traces[i].n_rows;
  }

  res = allocate_matrix(&tmp, max_n_rows, ncol);
  if (res != 0) {
    fprintf (stderr, "[ERROR] Allocating matrix in focpa vp.\n");
    return -1;
  }

  res = allocate_matrix(&traces, ncol, nrows);
  if (res != 0) {
    fprintf (stderr, "[ERROR] Allocating matrix in focpa vp.\n");
    return -1;
  }

  res = allocate_matrix(&precomp_k, n_keys, 2);
  if (res != 0){
    fprintf(stderr, "[ERROR] Memory allocation failed in focpa vp\n");
    return -1;
  }

  /* We initialize the priority queues to store the highest correlations.
   */
  PriorityQueue<CorrFirstOrder <TypeReturn> > * pqueue = new PriorityQueue<CorrFirstOrder <TypeReturn> >;
  (*pqueue).init(conf.top);

  CorrFirstOrder <TypeReturn> * top_r_by_key;

  /* If we initialize with malloc, the default constructor is not called,
   * leading to possible issued when inserting/comparing elements.
   */
  top_r_by_key = new CorrFirstOrder <TypeReturn> [n_keys];
  if (top_r_by_key == NULL){
    fprintf(stderr, "[ERROR] Allocating memory for top correlations.\n");
    return -1;
  }


  MatArgs<TypeTrace, TypeReturn, TypeGuess> mat_args = MatArgs<TypeTrace, TypeReturn, TypeGuess> (traces, guesses, NULL);

  FirstOrderQueues<TypeReturn>* queues = new FirstOrderQueues<TypeReturn>(pqueue, top_r_by_key);
  if(queues == NULL){
    fprintf(stderr, "[ERROR] Allocating memory for the priority queues.\n");
    return -1;
  }

  FinalConfig<TypeTrace, TypeReturn, TypeGuess> fin_conf = FinalConfig<TypeTrace, TypeReturn, TypeGuess>(&mat_args, &conf, (void*)queues);
  pthread_mutex_init(&pt_lock, NULL);

  vector<CorrFirstOrder<TypeReturn>*> sum_bit_corels;
  vector<CorrFirstOrder<TypeReturn>*> peak_bit_corels;
  /* We loop over all the key bytes.
   */
  for (int bn = 0; bn < conf.key_size; bn++){
    ostringstream best_out;
    int lowest_rank = 16;
    sum_bit_corels.push_back(new CorrFirstOrder<TypeReturn>[256]);
    peak_bit_corels.push_back(new CorrFirstOrder<TypeReturn>[256]);
    for (size_t i = 0; i < 256; i++) {
      sum_bit_corels.back()[i].key = i;
      peak_bit_corels.back()[i].key = i;
    }
    /* We keep time each key byte individually;
     */
    start = omp_get_wtime();

    if (conf.bytenum != -1 && conf.bytenum != bn){
      continue;
    }

    if (conf.sep == "") printf("[ATTACK] Key byte number %i\n\n", bn);
    else if (conf.key_size > 1) printf("%i%s", bn, conf.sep.c_str());

    /* Potentially attack each bit individually. */
    int bitsperbyte;

    if (conf.algo == ALG_AES) bitsperbyte = 8;
    else if (conf.algo == ALG_DES) bitsperbyte = 4;

    for (int bit=0; bit >= 0 && bit < bitsperbyte; bit=(bit!=-1)?bit+1:bit) {
      if (conf.bitnum == -2) bit = -1;
      else if (conf.bitnum >= 0 && conf.bitnum != bit) continue;

      if (conf.bitnum != -2) {
        if (conf.sep == "") printf("[ATTACK] Target bit number %i\n\n", bit);
        else if (conf.key_size > 1) printf("%i%s", bit, conf.sep.c_str());
      }

      res = construct_guess (&fin_conf.mat_args->guess, conf.algo, conf.guesses, conf.n_file_guess, bn, conf.round, conf.des_switch, conf.sbox, conf.total_n_keys, bit);
      if (res < 0) {
        fprintf (stderr, "[ERROR] Constructing guess.\n");
        return -1;
      }

      res = split_work(fin_conf, precomp_guesses<TypeTrace, TypeReturn, TypeGuess>, precomp_k, n_keys);
      if (res != 0) {
        fprintf(stderr, "[ERROR] Precomputing sum and sum of square for the guesses.\n");
        return -1;
      }


      /* We iterate over the all the files, loading ncol columns to memory at a
       * time.
       */
      while (!is_last_iter) {

        /* If the number of samples loaded so far + what we will load in this
         * iteration is larger than the number of samples, it's the last iter.
         */
        if (samples_loaded + to_load >= n_samples){
          is_last_iter = 1;
          to_load = n_samples - samples_loaded;
        }

        /* We iterate over all the files, loading to_load samples at a time and
         * starting at offset 'conf.index_sample + sample_offset + row_offset'
         * in the files. This offset depends on the iteration and the variable
         * to_load depends on whether it is the first iteration or not
         * (we have to load more in the first iteration)
         */
        for (int i = 0; i < nmat; i++){
          cur_n_rows = conf.traces[i].n_rows;
          cur_n_cols = conf.traces[i].n_columns;

          res = load_file_v_1(conf.traces[i].filename, &tmp, cur_n_rows, to_load, conf.index_sample + sample_offset + row_offset, cur_n_cols);
          if (res != 0) {
            fprintf (stderr, "[ERROR] Loading file.\n");
            return -1;
          }

          /* We copy the array tmp in the array traces at the good offset, and we
           * transpose it at the same time.
           * row_offset is used to make the distinction between the first iteration
           * and the following.
           */
          for (int j = 0; j < cur_n_rows; j++){
            for (int k = 0; k < to_load; k++){
              fin_conf.mat_args->trace[k + row_offset][j + col_offset] = tmp[j][k];
            }
          }
          col_offset += conf.traces[i].n_rows;
        }

        samples_loaded += to_load;

        /* We set to_load to col_incr. So that only in the very first iteration
         * we load ncol.
         */
        to_load = col_incr;

        /* Same principle for row_offset
         */
        row_offset = 0;

        col_offset = 0;

        res = split_work(fin_conf, correlation_first_order<TypeTrace, TypeReturn, TypeGuess>, precomp_k, is_last_iter ? (n_samples - sample_offset) : col_incr, sample_offset);
        if (res != 0) {
          fprintf(stderr, "[ERROR] Computing correlations.\n");
          return -1;
        }
        sample_offset += col_incr;

        /* If we are at the last iteration at that point, no need to do more
         * work.
         */
        if (is_last_iter)
          break;
      }

      /* Warning, when using DES, the correct key doesn't correspond to the actual
       * good key, as we are predicting the input state based on a round key.
       */
      int correct_key = -1;
      if (conf.key_size == 1 && conf.correct_key != -1) {
        if (conf.des_switch == DES_4_BITS && conf.correct_key != -1) correct_key = get_4_middle_bits(conf.correct_key);
        else correct_key = conf.correct_key;
        pqueue->print(conf.top, correct_key);
        print_top_r(top_r_by_key, n_keys, correct_key);
      } else if (conf.complete_correct_key != NULL) {
        if (conf.des_switch == DES_4_BITS) correct_key = get_4_middle_bits(conf.complete_correct_key[bn]);
        else correct_key = conf.complete_correct_key[bn];

        if (conf.bitnum == -1) {
          sort(top_r_by_key, top_r_by_key + n_keys);
          for (int i = n_keys - 1; i >= 0; i--) {
            if (top_r_by_key[i] == correct_key) {
              if (n_keys - i - 1 < lowest_rank) {
                lowest_rank = n_keys - i - 1;
                best_out.str(std::string());  /* Clear best_out. */
                best_out << "Best bit: " << bit << " rank: " << n_keys - i - 1 << "." << setw(-2) << top_r_by_key[i] << endl;
              }
            }
          }
        } else {
          print_top_r(top_r_by_key, n_keys, correct_key, conf.sep);
        }
      }

      int key_guess_used[256] = {0};
      for (int i = 0; i < n_keys; i++) {
        if (key_guess_used[top_r_by_key[i].key] == 0) {
          key_guess_used[top_r_by_key[i].key] = 1;
          sum_bit_corels.back()[top_r_by_key[i].key].corr += abs(top_r_by_key[i].corr);
          if (abs(top_r_by_key[i].corr) > peak_bit_corels.back()[top_r_by_key[i].key].corr)
            peak_bit_corels.back()[top_r_by_key[i].key].corr = abs(top_r_by_key[i].corr);
        }
      }

    if ( ((conf.bitnum == -1) && (bit == bitsperbyte-1))      // 'all' case
	      || ((conf.bitnum != -1) && (bit >= 0))    // single bit case
	      || (conf.bitnum == -2))                   // 'none' case
    {
        int nbest=10; // TODO: make it a config parameter
        sort (sum_bit_corels.back(), sum_bit_corels.back() + n_keys);
        sort (peak_bit_corels.back(), peak_bit_corels.back() + n_keys);
        cout << "Best " << nbest << " candidates for key byte #" << bn << " according to sum(abs(bit_correlations)):" << endl;
        for (int i = 1; i <= nbest; i++) {
          cout << setfill(' ') << setw(2) << i << ": 0x" << setfill('0') << setw(2) << hex << sum_bit_corels.back()[n_keys-i].key;
          cout << setfill(' ') << dec << "  sum: " << setw(8) << left << sum_bit_corels.back()[n_keys-i].corr << right;
          if (sum_bit_corels.back()[n_keys-i].key == correct_key)
            cout << "  <==";
          cout << endl;
        }
        cout << endl;
        cout << "Best " << nbest << " candidates for key byte #" << bn << " according to highest abs(bit_correlations):" << endl;
        for (int i = 1; i <= nbest; i++) {
          cout << setfill(' ') << setw(2) << i << ": 0x" << setfill('0') << setw(2) << hex << peak_bit_corels.back()[n_keys-i].key;
          cout << setfill(' ') << dec << "  peak: " << setw(8) << left << peak_bit_corels.back()[n_keys-i].corr << right;
          if (peak_bit_corels.back()[n_keys-i].key == correct_key)
            cout << "  <==";
          cout << endl;
        }
        cout << endl;
      }


      /* We reset the variables and arrays.
       */
      for (int k = 0; k < n_keys; k++){
        precomp_k[k][0] = 0;
        precomp_k[k][1] = 0;
        top_r_by_key[k].corr = 0.0;
      }

      end = omp_get_wtime();

      is_last_iter = 0;
      col_offset = 0;
      row_offset = 0;
      sample_offset = 0;
      samples_loaded = 0;
      to_load = ncol;
    }
    if (conf.sep == ""){
      printf("[INFO] Attack of byte number %i done in %lf seconds.\n", bn, end - start);
      fflush(stdout);
    }
    if (conf.bitnum == -1) {
      cout << best_out.str() << endl;
    }
  }

  /* If the key is unknown, display the likely candidates.
  */
  if (conf.complete_correct_key == NULL) {
      cout << "Most probable key sum(abs):" << endl;
      vector<pair<TypeReturn, string>> top_keys = getTopFullKeys(sum_bit_corels, n_keys, 10);
      for (size_t i = 0; i < top_keys.size(); i++) {
          cout << i+1 << ": " << top_keys[i].first << ": " << top_keys[i].second << endl;
      }
      cout << endl;
      cout << "Most probable key max(abs):" << endl;
      top_keys = getTopFullKeys(peak_bit_corels, n_keys, 10);
      for (size_t i = 0; i < top_keys.size(); i++) {
          cout << i+1 << ": " << top_keys[i].first << ": " << top_keys[i].second << endl;
      }
}

  for (size_t i = 0; i < sum_bit_corels.size(); i++) {
      delete sum_bit_corels[i];
      delete peak_bit_corels[i];
  }

  delete[] top_r_by_key;
  delete pqueue;
  delete queues;
  free_matrix(&precomp_k, n_keys);
  free_matrix(&traces, ncol);
  free_matrix(&tmp, max_n_rows);
  free_matrix(&fin_conf.mat_args->guess, n_keys);
  pthread_mutex_destroy(&pt_lock);
  return 0;
}


/* This function computes the first order correlation between a subset
 * of the traces defined in the structure passed as argument and all the
 * key guesses.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
void * correlation_first_order(void * args_in)
{
  General<TypeTrace, TypeReturn, TypeGuess> * G = (General<TypeTrace, TypeReturn, TypeGuess> *) args_in;
  FirstOrderQueues<TypeReturn> * queues = (FirstOrderQueues<TypeReturn> *)(G->fin_conf->queues);
  int i, k, j,
      n_keys = G->fin_conf->conf->total_n_keys,
      n_traces = G->fin_conf->conf->n_traces,
      first_sample = G->fin_conf->conf->index_sample,
      offset = G->global_offset;
  TypeReturn corr,
    sum_trace,
    sum_sq_trace,
    tmp;
  CorrFirstOrder<TypeReturn> * q = (CorrFirstOrder<TypeReturn> *) malloc(n_keys * sizeof(CorrFirstOrder<TypeReturn>));
  if (q == NULL){
    fprintf (stderr, "[ERROR] Allocating memory for q in correlation\n");
  }

  for (i = G->start; i < G->start + G->length; i++) {
    sum_trace = 0.0;
    sum_sq_trace = 0.0;
    for (j = 0; j < n_traces; j++){
      tmp = G->fin_conf->mat_args->trace[i][j];
      sum_trace += tmp;
      sum_sq_trace += tmp*tmp;
    }

    sum_sq_trace = sqrt(n_traces*sum_sq_trace - sum_trace*sum_trace);

    for (k = 0; k < n_keys; k++) {
      tmp = sqrt(n_traces * G->precomp_guesses[k][1] - G->precomp_guesses[k][0] * G->precomp_guesses[k][0]);

      corr = pearson_v_2_2<TypeReturn, TypeTrace, TypeGuess>(G->fin_conf->mat_args->guess[k],\
        G->precomp_guesses[k][0], tmp, G->fin_conf->mat_args->trace[i], sum_trace, sum_sq_trace, n_traces);

      if (!isnormal(corr)) corr = (TypeReturn) 0;

      q[k].corr  = corr;
      q[k].time  = i + first_sample + offset;
      q[k].key   = k;
    }

    pthread_mutex_lock(&pt_lock);
    for (int key=0; key < n_keys; key++) {
      if (G->fin_conf->conf->key_size == 1)
        queues->pqueue->insert(q[key]);
      if (queues->top_corr[key] < q[key]){
        queues->top_corr[key] = q[key];
      }
    }
    pthread_mutex_unlock(&pt_lock);
  }
  free (q);
  return NULL;
}

template <class T> T productReduce(vector<T> &xs) {
    T acc = 1;
    for(const T &x: xs) {
        acc *= x;
    }
    return acc;
}

template <class T>
vector<pair<T,string>> getTopFullKeys(vector<CorrFirstOrder<T>*> &candidates, size_t n_keys, size_t topn) {
    vector<size_t> limit = vector<size_t>(candidates.size(), 1);
    vector<pair<T,string>> top_keys;
    // Find the smallest set of high probability candidates which result in a key space of at least topn
    while(productReduce(limit) <= topn) {
        // Find the lowest correlation drop across all key bytes
        T lowest_drop = 1000000;
        size_t lowest_drop_idx = candidates.size();
        for(size_t i = 0; i < candidates.size(); i++) {
            if(limit[i] < n_keys) {
                // Evaluate the correlation drop of the next candidate of this key byte
                T drop = candidates[i][n_keys - 1].corr - candidates[i][n_keys - limit[i] - 1].corr;
                if(drop < lowest_drop) {
                    lowest_drop = drop;
                    lowest_drop_idx = i;
                }
            }
        }
        // Augment the limit by one on the lowest correlation drop
        if(lowest_drop_idx < candidates.size()) {
            limit[lowest_drop_idx] += 1;
        }
    }
    // Compute all the key possibilities for this key space
    vector<size_t> idx = vector<size_t>(limit.size(), 0);
    bool exhausted = false;
    while(!exhausted) {
        // Compute a full key and its correlation sum
        T correlation = 0;
        string full_key;
        full_key.reserve(candidates.size() * 2 + 1);
        for(size_t i = 0; i < candidates.size(); i++) {
            char buf[8];
            correlation += candidates[i][n_keys - idx[i] - 1].corr;
            snprintf(buf, 8, "%02hhx", (unsigned char) candidates[i][n_keys - idx[i] - 1].key);
            full_key.append(buf);
        }
        top_keys.push_back(make_pair(correlation, full_key));
        // Increment to the next full key in the restricted key space
        for(size_t i = 0; i < idx.size(); i++) {
            idx[i] += 1;
            // If overflow limit, carry to the next key byte
            if(idx[i] >= limit[i]) {
                idx[i] = 0;
                // If overflow last key byte, restricted key space exhausted
                if(i == idx.size() - 1) {
                    exhausted = true;
                }
            }
            // No carry, we stop the increment
            else {
                break;
            }
        }
    }
    // Finally we sort the candidates and keep the topn
    sort(top_keys.begin(), top_keys.end(), [](const pair<T,string> &a, const pair<T,string> &b) {
        return a.first > b.first;
    });
    top_keys.resize(topn);

    return top_keys;
}

template int first_order<float, double, uint8_t>(Config & conf);
template int first_order<double, double, uint8_t>(Config & conf);
template int first_order<int8_t, double, uint8_t>(Config & conf);
template int first_order<int8_t, float, uint8_t>(Config & conf);

template void * correlation_first_order<int8_t, double, uint8_t> (void * args_in);
template void * correlation_first_order<int8_t, float, uint8_t> (void * args_in);
template void * correlation_first_order<float, double, uint8_t> (void * args_in);
template void * correlation_first_order<double, double, uint8_t> (void * args_in);
