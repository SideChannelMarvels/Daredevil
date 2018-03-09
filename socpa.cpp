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
#include "socpa.h"
#include "cpa.h"
#include "utils.h"
#include "string.h"

pthread_mutex_t pt_lock;

/* Implements second order CPA in a faster and multithreaded way on big files.
 *
 * TODO:
 *  Overlapping use of some variables: sample_offset, samples_loaded, col_incr?
 *  Could be made much faster when attacking a whole key IFF we have enough
 *  memory to keep the traces in mem. In such a case, we wouldn't have to read
 *  multiple times, and we could only do the precomputations once.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
int second_order(Config & conf)
{

  double start, end;

  int res,
      n_keys = conf.total_n_keys,
      n_samples = conf.n_samples,
      nmat = conf.n_file_trace,
      nrows = conf.total_n_traces,
      window = conf.window,
      ncol = min(\
        get_ncol<TypeReturn>(conf.memory -(nrows*n_keys*sizeof(TypeGuess)), nrows),\
        n_samples),
      col_incr = ncol - window + 1,
      col_offset = 0,
      row_offset = 0,
      sample_offset = 0,
      cur_n_rows, cur_n_cols,
      samples_loaded = 0,
      to_load = ncol;

  uint8_t is_last_iter = 0;
  unsigned int max_n_rows = 0;


  /* As we'll have to subtract the mean (TypeReturn) from the traces, we
   * need to have the traces in the correct type as well.
   */
  TypeReturn ** traces = NULL;
  TypeTrace ** tmp = NULL;
  TypeGuess ** guesses = NULL;
  TypeReturn ** precomp_k;

  /* Some checks before actually running the attack
   */
  if (!window){
    fprintf(stderr, "[ERROR] window == 0 unsupported.\n");
    return -1;
  }
  if (col_incr <= 0) {
    fprintf(stderr, "[ERROR] Invalid parameters window(=%i) and ncol(=%i).\n", window, ncol);
    return -1;
  }

  /* Simple check */
 /* printf("Memory allows to load %i samples at a time out of %i total samples.\n",\
      ncol, n_samples);
*/
  /* We determine the size of the file having the largest number of rows, to
   * allocate memory for tmp.
   */
  for (int i = 0; i < nmat; i++){
    if(conf.traces[i].n_rows > max_n_rows)
      max_n_rows = conf.traces[i].n_rows;
  }

  /* We allocate the different arrays that we use during the computations
   */
  res = allocate_matrix(&tmp, max_n_rows, ncol);
  if (res != 0) {
    fprintf (stderr, "[ERROR] allocating matrix in test.\n");
    return -1;
  }

  res = allocate_matrix(&traces, ncol, nrows);
  if (res != 0) {
    fprintf (stderr, "[ERROR] allocating matrix in test.\n");
    return -1;
  }

  res = allocate_matrix(&precomp_k, n_keys, 2);
  if (res != 0){
    fprintf(stderr, "[ERROR] Memory allocation failed in CPA_v_5 function\n");
    return -1;
  }

  /* We initialize the priority queues to store the highest correlations.
   */
  PriorityQueue<CorrSecondOrder <TypeReturn> > * pqueue = new PriorityQueue<CorrSecondOrder <TypeReturn> >;
  (*pqueue).init(conf.top);

  CorrSecondOrder <TypeReturn> * top_r_by_key;

  /* If we initialize with malloc, the default constructor is not called,
   * leading to possible issued when inserting/comparing elements.
   */
  top_r_by_key = new CorrSecondOrder <TypeReturn> [n_keys];
  if (top_r_by_key == NULL){
    fprintf(stderr, "[ERROR] Allocating memory for top correlations.\n");
    return -1;
  }

  /* We declare and initialize the structures that points to the multiple
   * variables used during the computations
   */
  MatArgs<TypeReturn, TypeReturn, TypeGuess> mat_args = MatArgs<TypeReturn, TypeReturn, TypeGuess> (traces, guesses, NULL);

  SecondOrderQueues<TypeReturn>* queues = new SecondOrderQueues<TypeReturn>(pqueue, top_r_by_key);
  if(queues == NULL){
    fprintf(stderr, "[ERROR] Allocating memory for the priority queues.\n");
    return -1;
  }

  FinalConfig<TypeReturn, TypeReturn, TypeGuess> fin_conf = FinalConfig<TypeReturn, TypeReturn, TypeGuess>(&mat_args, &conf, (void*)queues);
  pthread_mutex_init(&pt_lock, NULL);


  /* We loop over all the key bytes.
   */
  for (int bn = 0; bn < conf.key_size; bn++){

    /* We keep the time of each key byte individually
     */
    start = omp_get_wtime();

    if (conf.key_size == 1)
      bn = conf.bytenum;
    else if (conf.bytenum != -1 && conf.bytenum != bn)
      continue;

    if (conf.sep == "") printf("[ATTACK] Key byte number %i\n\n", bn);
    else if (conf.key_size > 1) printf("%i%s", bn, conf.sep.c_str());

    /* Constructs the hypothetical power consumption values for the current
     * key bytes attacked.
     */
    res = construct_guess (&fin_conf.mat_args->guess, conf.algo, conf.guesses, conf.n_file_guess, bn, conf.round, conf.des_switch, conf.sbox, conf.total_n_keys, -1);
    if (res < 0) {
      fprintf (stderr, "[ERROR] Constructing guess.\n");
      return -1;
    }

    /* Multithreaded precomputations for the guesses
     */
    res = split_work(fin_conf, precomp_guesses<TypeReturn, TypeReturn, TypeGuess>, precomp_k, n_keys);
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
          fprintf (stderr, "[ERROR] loading file.\n");
          return -1;
        }

        /* We copy the array tmp in the array traces at the good offset, and we
         * transpose it AND typecast to TypeReturn at the same time.
         * row_offset is used to make the distinction between the first iteration
         * and the following.
         */
        for (int j = 0; j < cur_n_rows; j++){
          for (int k = 0; k < to_load; k++){
            fin_conf.mat_args->trace[k + row_offset][j + col_offset] = (TypeReturn) tmp[j][k];
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
      row_offset = window - 1;

      /* We compute the difference from the mean.
       * WARNING: Unnecessary work is done at the last iteration.
       * To avoid that, should introduce a variable n_work in
       * p_precomp_traces in order to only treat the n_work rows after offset.
       */
      res = p_precomp_traces<TypeReturn, TypeReturn>(fin_conf.mat_args->trace, sample_offset ? col_incr : ncol, nrows, conf.n_threads, sample_offset ? window - 1 : 0);
      if (res != 0) {
        fprintf(stderr, "[ERROR] Precomputing distance from mean for the traces.\n");
        return -1;
      }
      col_offset = 0;

      /* If the order of the attack is larger than 2, we compute the attack_order-th moment
       */
      if (conf.attack_order > 2){
        res = split_work(fin_conf, higher_moments_correlation<TypeReturn, TypeReturn, TypeGuess>, precomp_k, is_last_iter ? (n_samples - sample_offset) : col_incr, sample_offset);
      }else{
        res = split_work(fin_conf, second_order_correlation<TypeReturn, TypeReturn, TypeGuess>, precomp_k, is_last_iter ? (n_samples - sample_offset) : col_incr, sample_offset);
      }if (res != 0) {
        fprintf(stderr, "[ERROR] Computing correlations.\n");
        return -1;
      }

      sample_offset += col_incr;

      /* If we are at the last iteration at that point, no need to do more
       * work.
       */
      if (is_last_iter)
        break;

      /* And here we have to shift the (window - 1) last columns in the first
       * position in the array traces.
       */
      for (int j = 0; j < window - 1; j++){
        // To test if faster:
        // traces[j] = traces[j + col_incr];
        // But then have to free col_incr otherwise SegFault
        for (int k = 0; k < nrows; k++)
          fin_conf.mat_args->trace[j][k] = fin_conf.mat_args->trace[j + col_incr][k];
      }
    }

    int correct_key;
    if (conf.key_size == 1) {
      if (conf.des_switch == DES_4_BITS && conf.correct_key != -1) correct_key = get_4_middle_bits(conf.correct_key);
      else correct_key = conf.correct_key;
      pqueue->print(conf.top, correct_key);
      print_top_r(top_r_by_key, n_keys, correct_key);
    }else if (conf.correct_key != -1) {
      if (conf.des_switch == DES_4_BITS) correct_key = get_4_middle_bits(conf.complete_correct_key[bn]);
      else correct_key = conf.complete_correct_key[bn];
      print_top_r(top_r_by_key, n_keys, correct_key, conf.sep);
    }
    else {
      correct_key = conf.correct_key;
      print_top_r(top_r_by_key, n_keys, correct_key, conf.sep);
    }

    /* We reset the variables and arrays.
     */
    for (int k = 0; k < n_keys; k++){
      precomp_k[k][0] = 0;
      precomp_k[k][1] = 0;
      top_r_by_key[k].corr = 0.0;
    }

    end = omp_get_wtime();
    if (conf.sep == ""){
        printf("[INFO] Attack of byte number %i done in %lf seconds.\n", bn, end - start);
        fflush(stdout);
    }
    is_last_iter = 0;
    col_offset = 0;
    row_offset = 0;
    sample_offset = 0;
    samples_loaded = 0;
    to_load = ncol;
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

/* This functions simply splits the total work (n_rows) into an equal number of
 * threads, creates this amount of threads and starts them to precompute the
 * distance of means for each row of the matrix trace. If the offset value is
 * specified, we start splitting the work starting at offset.
 *
 * ! We expect a matrix where the number of traces is n_rows
 */
  template <class TypeTrace, class TypeReturn>
int p_precomp_traces(TypeTrace ** trace, int n_rows, int n_columns, int n_threads, int offset/*, int n_traces_from_offset*/)
{
  int n, rc,
      workload = 0,
      n_traces = n_columns;

  //printf("Offset: %i\n", offset);

  /* If the total work by thread is smaller than 1, only the last thread would
   * work, which is against the sole principle of multithreading. Thus, we
   * reduce the number of threads until the workload is larger than 1.
   */
  workload = ((n_rows-offset)/n_threads);
  while (workload < 1) {
    n_threads -= 1;
    workload = ((n_rows-offset)/n_threads);
  }

  pthread_t threads[n_threads];
  PrecompTraces<TypeTrace> *ta = NULL;

  ta = (PrecompTraces<TypeTrace>*) malloc(n_threads * sizeof(PrecompTraces<TypeTrace>));
  if (ta == NULL) {
    fprintf (stderr, "[ERROR] Memory alloc failed.\n");
    return -1;
  }

  for (n = 0; n < n_threads; n++) {
    //printf(" Thread_%i [%i-%i]\n",n , offset+ n*workload, offset+n*workload + workload + ((n + 1) / n_threads)*(n_rows % n_threads));
    ta[n] = PrecompTraces<TypeTrace>(offset + n*workload, workload + ((n + 1) / n_threads) * (n_rows % n_threads), n_traces, trace);
    rc = pthread_create(&threads[n], NULL, precomp_traces_v_2<TypeTrace, TypeReturn>, (void *) &ta[n]);
    if (rc != 0) {
      fprintf(stderr, "[ERROR] Creating thread.\n");
      free (ta);
      return -1;
    }
  }

  for (n = 0; n < n_threads; n++) {
    rc = pthread_join(threads[n], NULL);
    if (rc != 0) {
      fprintf(stderr, "[ERROR] Joining thread.\n");
      free (ta);
      return -1;
    }
  }
  free (ta);
  return 0;
}

/* This functions simply splits the total_work (usually represents the number
 * of columns of the matrix we're processing) into an equal number of threads,
 * creates this amount of threads and starts them with the function fct.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
int split_work(FinalConfig<TypeTrace, TypeReturn, TypeGuess> & fin_conf, void * (*fct)(void *), TypeReturn ** precomp_k, int total_work, int offset)
{
  int n, rc,
      workload = 0,
      n_threads = fin_conf.conf->n_threads,
      /* Can be changed later in order to compute on less traces.
       */
      n_traces = fin_conf.conf->total_n_traces;


  /* If the total work by thread is smaller than 1, only the last thread would
   * work, which is against the sole principle of multithreading. Thus, we
   * reduce the number of threads until the workload is larger than 1.
   *
   * This is quite a naive approach, and it would be better to look into more
   * efficient load balancing algorithms.
   *
   */
  workload = (total_work/n_threads);
  while (workload < 1) {
    n_threads -= 1;
    workload = (total_work/n_threads);
  }

  pthread_t threads[n_threads];
  General<TypeTrace, TypeReturn, TypeGuess> *ta = NULL;

  ta = (General<TypeTrace, TypeReturn, TypeGuess> *) malloc(n_threads * sizeof(General<TypeTrace, TypeReturn, TypeGuess>));
  if (ta == NULL) {
    fprintf (stderr, "[ERROR] Memory alloc failed.\n");
    return -1;
  }

  for (n = 0; n < n_threads; n++) {
    //printf(" Thread_%i [%i-%i]\n", n, n*workload + offset, offset + n*workload + workload + ((n + 1) / n_threads)*(total_work % n_threads));
    ta[n] = General<TypeTrace, TypeReturn, TypeGuess>(n*workload, workload + ((n + 1) / n_threads) * (total_work % n_threads), n_traces, offset, total_work, precomp_k, &fin_conf);
    rc = pthread_create(&threads[n], NULL, (*fct), (void *) &ta[n]);
    if (rc != 0) {
      fprintf(stderr, "[ERROR] Creating thread.\n");
      free (ta);
      return -1;
    }
  }

  for (n = 0; n < n_threads; n++) {
    rc = pthread_join(threads[n], NULL);
    if (rc != 0) {
      fprintf(stderr, "[ERROR] Joining thread.\n");
      free (ta);
      return -1;
    }
  }
  free (ta);
  return 0;
}

/* This function computes the second order correlation between a subset
 * of the traces defined in the structure passed as argument and all the
 * key guesses.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
void * second_order_correlation(void * args_in)
{

  General<TypeTrace, TypeReturn, TypeGuess> * G = (General<TypeTrace, TypeReturn, TypeGuess> *) args_in;
  SecondOrderQueues<TypeReturn> * queues = (SecondOrderQueues<TypeReturn> *)(G->fin_conf->queues);
  int i, j, k,
      n_keys = G->fin_conf->conf->total_n_keys,
      n_traces = G->fin_conf->conf->n_traces,
      n_samples = G->fin_conf->conf->n_samples,
      first_sample = G->fin_conf->conf->index_sample,
      offset = G->global_offset,
      window = G->fin_conf->conf->window ? G->fin_conf->conf->window : n_samples,
      up_bound;


  TypeReturn corr, s_t, ss_t, tmp, std_dev_t;
  TypeReturn * t = (TypeReturn *) malloc(n_traces * sizeof(TypeReturn));
  if (t == NULL){
    fprintf (stderr, "[ERROR] Allocating memory for t in correlation\n");
  }

  CorrSecondOrder<TypeReturn> * q = (CorrSecondOrder<TypeReturn> *) malloc(n_keys * sizeof(CorrSecondOrder<TypeReturn>));
  if (q == NULL){
    fprintf (stderr, "[ERROR] Allocating memory for q in correlation\n");
  }


  for (i = G->start; i < G->start + G->length; i++) {
    up_bound = min(n_samples - offset, i+window);
    for (j = i; j < up_bound; j++) {
      s_t = 0.0;
      ss_t = 0.0;
      for (k = 0; k < n_traces; k++) {
        tmp = G->fin_conf->mat_args->trace[i][k] * G->fin_conf->mat_args->trace[j][k];
        t[k] = tmp;
        s_t += tmp;
        ss_t += tmp*tmp;
      }
      std_dev_t = sqrt(n_traces*ss_t - s_t*s_t);
      for (k = 0; k < n_keys; k++) {
        corr = pearson_v_2_2<TypeReturn, TypeReturn, TypeGuess>(G->fin_conf->mat_args->guess[k], G->precomp_guesses[k][0], sqrt(n_traces * G->precomp_guesses[k][1] - G->precomp_guesses[k][0] * G->precomp_guesses[k][0]), t, s_t, std_dev_t, n_traces);

        if (!isnormal(corr)) corr = (TypeReturn) 0;

        q[k].corr  = corr;
        q[k].time1 = i + first_sample + offset;
        q[k].time2 = j + first_sample + offset;
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
  }
  free (t);
  free (q);
  return NULL;
}

/* This function computes the higher order moments correlation between a subset
 * of the traces defined in the structure passed as argument and all the
 * key guesses.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
void * higher_moments_correlation(void * args_in)
{

  General<TypeTrace, TypeReturn, TypeGuess> * G = (General<TypeTrace, TypeReturn, TypeGuess> *) args_in;
  SecondOrderQueues<TypeReturn> * queues = (SecondOrderQueues<TypeReturn> *)(G->fin_conf->queues);
  int i, k,
      n_keys = G->fin_conf->conf->total_n_keys,
      n_traces = G->fin_conf->conf->n_traces,
      first_sample = G->fin_conf->conf->index_sample,
      offset = G->global_offset,
      exponent = G->fin_conf->conf->attack_order;


  TypeReturn corr, s_t, ss_t, tmp, std_dev_t, mean_t, sigma_n;
  TypeReturn * t = (TypeReturn *) malloc(n_traces * sizeof(TypeReturn));
  if (t == NULL){
    fprintf (stderr, "[ERROR] Allocating memory for t in correlation\n");
  }

  CorrSecondOrder<TypeReturn> * q = (CorrSecondOrder<TypeReturn> *) malloc(n_keys * sizeof(CorrSecondOrder<TypeReturn>));
  if (q == NULL){
    fprintf (stderr, "[ERROR] Allocating memory for q in correlation\n");
  }


  for (i = G->start; i < G->start + G->length; i++) {
      s_t = 0.0;
      ss_t = 0.0;
      mean_t = 0.0;
      sigma_n = 0.0;
      for (k = 0; k < n_traces; k++) {
        tmp = G->fin_conf->mat_args->trace[i][k];
        mean_t += tmp;
        sigma_n += tmp*tmp;
      }
      mean_t /= n_traces;
      sigma_n = pow(sqrt(sigma_n/n_traces - mean_t*mean_t), exponent);
      for (k = 0; k < n_traces; k++) {
        tmp = pow((G->fin_conf->mat_args->trace[i][k] - mean_t), exponent)/sigma_n;
        t[k] = tmp;
        s_t += tmp;
        ss_t += tmp*tmp;
      }
      std_dev_t = sqrt(n_traces*ss_t - s_t*s_t);
      for (k = 0; k < n_keys; k++) {
        corr = pearson_v_2_2<TypeReturn, TypeReturn, TypeGuess>(G->fin_conf->mat_args->guess[k], G->precomp_guesses[k][0], sqrt(n_traces * G->precomp_guesses[k][1] - G->precomp_guesses[k][0] * G->precomp_guesses[k][0]), t, s_t, std_dev_t, n_traces);

        if (!isnormal(corr)) corr = (TypeReturn) 0;

        q[k].corr  = corr;
        q[k].time1 = i + first_sample + offset;
        q[k].time2 = i + first_sample + offset;
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
  free (t);
  free (q);
  return NULL;
}

/* This function precomputes the mean for the traces and subtract this mean
 * from every element of the traces. This is to be used by the newer v_5 of
 * SOCPA.
 */
  template <class TypeTrace, class TypeReturn>
void * precomp_traces_v_2(void * args_in)
{

  int i, j;
  TypeReturn mean = 0.0;

  PrecompTraces<TypeTrace> * G = (PrecompTraces<TypeTrace> *) args_in;

  for (i = G->start; i < G->start + G->end; i++) {
    for (j = 0; j < G->length; j++) {
      mean += G->trace[i][j];
    }
    mean /= G->length;
    for (j = 0; j < G->length; j++) {
      G->trace[i][j] -= mean;
    }
  }
  return NULL;
}


/* This function precomputes the sum and the sum of squares for all guesses
 * which will later be used in the correlation computation.
 */
  template <class TypeTrace, class TypeReturn, class TypeGuess>
void * precomp_guesses(void * args_in)
{
  int i, j;
  TypeReturn tmp;
  General<TypeTrace, TypeReturn, TypeGuess> * G = (General<TypeTrace, TypeReturn, TypeGuess> *) args_in;

  for (i = G->start; i < G->start + G->length; i++) {
    for (j = 0; j < G->n_traces; j++) {
      tmp = G->fin_conf->mat_args->guess[i][j];
      G->precomp_guesses[i][0] += tmp;
      G->precomp_guesses[i][1] += tmp*tmp;
    }
  }
  return NULL;
}


template int second_order<float, double, uint8_t>(Config & conf);
template int second_order<double, double, uint8_t>(Config & conf);
template int second_order<int8_t, double, uint8_t>(Config & conf);
template int second_order<int8_t, float, uint8_t>(Config & conf);

template void * second_order_correlation<int8_t, double, uint8_t>(void * args_in);
template void * second_order_correlation<double, double, uint8_t>(void * args_in);

template void * higher_moments_correlation<int8_t, double, uint8_t>(void * args_in);
template void * higher_moments_correlation<double, double, uint8_t>(void * args_in);

template void * precomp_guesses<int8_t, double, uint8_t>(void * args_in);
template void * precomp_guesses<float, double, uint8_t>(void * args_in);
template void * precomp_guesses<int8_t, float, uint8_t>(void * args_in);
template void * precomp_guesses<float, float, uint8_t>(void * args_in);

template int p_precomp_traces<int8_t, double>(int8_t ** trace, int n_rows, int n_columns, int n_threads, int offset);
template int p_precomp_traces<double, double>(double ** trace, int n_rows, int n_columns, int n_threads, int offset);

template int split_work<float, double, uint8_t>(FinalConfig<float, double, uint8_t> & fin_conf, void * (*fct)(void *), double ** precomp_k, int total_work, int offset);
template int split_work<int8_t, double, uint8_t>(FinalConfig<int8_t, double, uint8_t> & fin_conf, void * (*fct)(void *), double ** precomp_k, int total_work, int offset);
template int split_work<float, float, uint8_t>(FinalConfig<float, float, uint8_t> & fin_conf, void * (*fct)(void *), float ** precomp_k, int total_work, int offset);
template int split_work<int8_t, float, uint8_t>(FinalConfig<int8_t, float, uint8_t> & fin_conf, void * (*fct)(void *), float ** precomp_k, int total_work, int offset);
