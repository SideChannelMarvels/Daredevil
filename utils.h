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
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <queue>
#include <vector>
#include <iostream>
#include <algorithm>
#include <iomanip>

#ifndef RESOURCES
#define RESOURCES "/usr/share/daredevil"
#endif //RESOURCES

#define QUEUE_INIT 1024
#define QUEUE_PRINT 100


#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define RESET "\033[0m"

#define GIGA 1e9
#define MEGA 1e6
/*
#define ALG_AES                 0
#define ALG_DES_BEFORE          1
#define ALG_DES_AFTER           2
#define ALG_DES_BEFORE_SMALL    3
#define ALG_DES_AFTER_SMALL     4
*/

using namespace std;


/* Structure used to stores all the arrays.
 */
template <typename TypeTrace, typename TypeReturn, typename TypeGuess>
struct MatArgs {

  TypeTrace ** trace;
  TypeGuess ** guess;
  TypeReturn ** results;

  MatArgs(TypeTrace ** tr, TypeGuess ** gues, TypeReturn ** res):
    trace(tr), guess(gues), results(res) {
    }
};

/* Structures used to stores all the *common* information needed by the
 * threads to compute the correlation, like the pointers to the traces
 * and guesses arrays and their sizes.
 */
template <typename TypeTrace, typename TypeReturn, typename TypeGuess>
struct Args {

  TypeTrace ** trace;
  int n_samples;
  TypeGuess ** guess;
  int n_keys;
  TypeReturn ** results;
  int n_traces;
  int nsqr;

  Args(TypeTrace ** tr, int n_s, TypeGuess ** gues, int nk, TypeReturn ** res, int nt, int ns):
    trace(tr), n_samples(n_s), guess(gues), n_keys(nk), results(res), n_traces(nt), nsqr(ns) {
    }
};

/* Structure used by threads to access the common information, and the
 * indices in the array of traces where every individual thread will start
 * and stop computing correlations.
 */
template <typename TypeTrace, typename TypeReturn, typename TypeGuess>
struct ThreadArgs {

    Args<TypeTrace, TypeReturn, TypeGuess> * args;
    int start;
    int length;

    ThreadArgs(Args<TypeTrace, TypeReturn, TypeGuess> * a, int st, int len):
      args(a), start(st), length(len) {
    }
};

/* Stucture to store a first order correlation element to be put in the
 * priority queue. Such an element is defined by its correlation, and
 * the two time sample and key that led to this correlation.
 */
template <typename Type>
struct CorrSecondOrder {

  Type corr;
  int time1;
  int time2;
  int key;

  CorrSecondOrder(Type c, int t1, int t2, int k) : corr(c), time1(t1), time2(t2), key(k) {
  }

  CorrSecondOrder() : corr(0), time1(0), time2(0), key(0) {
  }

  bool operator<(const struct CorrSecondOrder<Type> & other) const {
    return fabs(this->corr) < fabs(other.corr);
  }

  /* Not really correct in a logical PoV, but this is to get the rank
   * of the highest correct key in the PriorityQueue.
   */
  bool operator==(const int other_key) const {
    return this->key == other_key;
  }

  friend std::ostream& operator<<( std::ostream& out, const CorrSecondOrder& b ){
    return out << setw(16) << b.corr << setw(6) << "0x" << setw(4) << left << hex << b.key << right << setw(8) << dec << b.time1 <<setw(8) << dec << b.time2;
  }

  void corr2str(string sep){
    cout << time1 << sep << time2 << sep << "0x" << hex << key << dec << sep << corr << endl;
  }

};

/* Stucture to store a first order correlation element to be put in the
 * priority queue. Such an element is defined by its correlation, and
 * the time sample and key that led to this correlation.
 */
template <typename Type>
struct CorrFirstOrder {

  Type corr;
  int time;
  int key;

  CorrFirstOrder() : corr(0), time(0), key(0) {
  }

  CorrFirstOrder(Type c, int t, int k) : corr(c), time(t), key(k) {
  }

  bool operator<(const struct CorrFirstOrder & other) const {
    return fabs(this->corr) < fabs(other.corr);
  }

  bool operator==(const int other_key) const {
    return this->key == other_key;
  }

  friend std::ostream& operator<<( std::ostream& out, const CorrFirstOrder& b ){
    return out << setw(16) << b.corr << setw(6) << "0x" << setfill('0') << setw(2) << hex << b.key << setw(6) << setfill(' ') << right << setw(8) << dec << b.time;
  }

  void corr2str(string sep){
    cout << time << sep << "0x" << hex << key << dec << sep << corr << endl;
  }

};

/* Homemade Priority Queue used to store the best correlations
 */
template <typename Type>
class PriorityQueue
{
  Type * array;
  int size, max_size, index_min, total;

  public:
  PriorityQueue(int s)
  {
    init(s);
  }
  PriorityQueue(){}

  void init(int s)
  {
    max_size = s;
    array = (Type *) malloc(max_size * sizeof(Type));
    size = 0;
    index_min = 0;
    total = 0;
  }
  void insert(const Type& elem)
  {
    if (size == max_size) {
      if(array[index_min] < elem) {
        array[index_min] = elem;
        update_smallest_ind();
      }
    }else {
      array[size] = elem;
      if (elem < array[index_min]) {
        index_min = size;
      }
      size += 1;
    }
    total++;
  }

  void print(int length = -1, int key = -1)
  {
    int i;
    uint8_t seen_key = 0;

    if (length == -1 || length > size)
      length = size;

    cout << "[INFO]\t" << total <<" correlations computed in total." << endl;
    cout << "[INFO]\tGlobal top " << length << " correlations." << endl;
    sort(array, array + size);
    update_smallest_ind();
    cout << endl;
    for (i = size - 1; i >= (size-length); i--) {
      if (array[i] == key){
        seen_key = 1;
        cout << KGRN << array[i] << RESET << endl;
      }else
        cout << array[i] << endl;
    }

    if(length != size && !seen_key){
      while (i > 0){
        if (array[i] == key){
          seen_key = 1;
          for(int j = 0; j < 3; j++)
            cout << setw(13) << '.' << setw(10) << '.' <<  setw(10) << '.' <<setw(8) << '.' << endl;
          cout << KGRN << array[i] << RESET << "\tat rank " << size-i << "." << endl;
          break;
        }
        i--;
      }
    }
    if (!seen_key && key != -1 && size != 0){
      cout << endl;
      cout << "Key 0x" << hex << key << " does not appear in the top " << dec << size << " correlations." << endl;
    }
    cout << endl;
  }
  private:
  void update_smallest_ind()
  {
    int i;
    for (i = 0; i < size; i++) {
      if (array[i] < array[index_min]) {
        index_min = i;
      }
    }
  }

};


/* Used to store the filename and dimensions of the matrix for loading them
 * in files later on.
 */
struct Matrix {

  const char * filename;
  unsigned int n_rows, n_columns;

  Matrix(const char * f_name, unsigned int rows, unsigned int columns):
    filename(f_name), n_rows(rows), n_columns(columns) {
    }
};

/* Structure used to store all the configuration information, used by the
 * config file at the moment.
 */
struct Config {

  /* The number of threads
   */
  int n_threads;

  /* The index of the first sample to start computing from. Useful when we
   * want to target only a subset of the time samples.
   */
  int index_sample;

  /* The number of samples after index_sample we want to correlate.
   */
  int n_samples;

  /* The number of traces we want to analyze, in case we don't want to
   * compute correlation on all of them.
   */
  int n_traces;

  /* The total number of traces, might be useless. To be removed if this is
   * the case.
   */
  int total_n_traces;

  /* The total number of samples, might be useless. To be removed if this is
   * the case.
   */
  int total_n_samples;

  /* The total number of keys, might be useless. To be removed if this is
   * the case.
   */
  int total_n_keys;

  /* The total number of columns of the keys guesses
   */
  int n_col_keys;

  /* Whether we want to transpose the array of traces and guesses.
   */
  bool transpose_traces;
  bool transpose_guesses;

  /* The number of trace and guess files.
   */
  int n_file_trace;
  int n_file_guess;

  /* The type of the traces and guesses, represented by a char.
   * u: uint8_t
   * f: float
   * d: double
   * i: int8_t
   */
  char type_trace;
  char type_guess;
  char type_return;

  /* The matrices structures containing file informations.
   */
  Matrix * traces;
  Matrix * guesses;

  /* The order of the attack
   */
  uint8_t attack_order;

  /* The algorithm to attack.
   * A: AES
   * D: DES
   */
  uint8_t algo;

  /* The round of the algorithm to attack.
   */
  uint32_t round;

  /* The position where to attack.
   */
  uint32_t position;

  /* The list of all position we want to attack.
   */
  vector<uint32_t> all_positions;

  /* The bytenumber to contruct the guesses.
   */
  int bytenum;

  /* The window size when computing higher order attacks.
   */
  int window;

  /* The correct key byte. If specified, the correct key will be highlighted when
   * displaying the results. Could also serve later on when doing known key
   * attack.
   */
  int correct_key;

  /* The complete correct key, in bytes.
   */
  uint8_t * complete_correct_key;

  /* The original correct key, in bytes. This is used for DES as we correlate
   * to the round key and not to the input key directly. However, this is only
   * when printing the configuration.
   */
  uint8_t * original_correct_key;

  /* The key size in bytes.
   */
  int key_size;

  /* The memory dedicated to the attack.
   */
  long int memory;

  /* The number of top element we keep track of globally.
   */
  int top;

  /* The SBOX is specified.
   */
  uint16_t * sbox;

  /* Array to store the multiple sboxes.
   */
  vector<string> all_sboxes;

  /* Switch to specify what des layout for the sboxes we want
   * des_switch = 0 => [8][64]
   * des_switch = 1 => [32][16]
   */
  uint8_t des_switch;

  /* Separator for printing
   */
  string sep;

  /* Do we want to target an individual bit?
   * If so, what bit?
   * -2 = none
   * -1 = all
   */
  int8_t bitnum;

};

/* Structure used to store ALL the general and common information
 */
template <typename TypeTrace, typename TypeReturn, typename TypeGuess>
struct FinalConfig {

  MatArgs<TypeTrace, TypeReturn, TypeGuess> * mat_args;
  Config * conf;
  void * queues;

  FinalConfig(MatArgs<TypeTrace, TypeReturn, TypeGuess> * m_a, Config * c, void * q):
    mat_args(m_a), conf(c), queues(q){
    }
};

template <typename Type>
struct SecondOrderQueues {
  PriorityQueue<CorrSecondOrder<Type> > * pqueue;
  CorrSecondOrder<Type> * top_corr;

  SecondOrderQueues(PriorityQueue<CorrSecondOrder<Type> > * q, CorrSecondOrder<Type> * t):
    pqueue(q), top_corr(t) {
    }
};


template <typename Type>
struct FirstOrderQueues {
  PriorityQueue<CorrFirstOrder<Type> > * pqueue;
  CorrFirstOrder<Type> * top_corr;

  FirstOrderQueues(PriorityQueue<CorrFirstOrder<Type> > * q, CorrFirstOrder<Type> * t):
    pqueue(q), top_corr(t) {
    }
};

/* Parse a file describing an SBOX
 */
int parse_sbox_file(const char * fname, uint16_t ** sbox);

/* Parse the command line arguments. For now, only supports the path to the
 * configuration file.
 */
int parse_args(int argc, char * argv[], char ** config_file);

/* Loads the configuration from a config file.
 */
int load_config(Config & conf, const char * conf_file);

/* Prints the current configuration
 */
void print_config(Config &conf);


/* Frees a matrix
 */
template <class Type>
void free_matrix(Type *** matrix, int n_rows);

/* Allocates memory for a matrix
 */
template <class Type>
int allocate_matrix(Type *** matrix, int n_rows, int n_columns);

  /* Latest version of load file. This function is used to load chunks in the
   * chunk partitioning approach.
   *
   * @param str           Path to the file to be loaded
   * @param mem           Pointer to the array in which to load the chunk
   * @param chunk_size    Number of rows to load
   * @param chunk_offset  Initial position in the rows from which we start loading
   * @param n_columns     Number of columns to load
   * @param col_offset    Initial position in the columns from which we start loading
   * @param tot_n_cols    Total number of columns in the file
   *
   * @return The number of lines read
   */
  template <class Type>
size_t fload(const char str[], Type *** mem, int chunk_size, long int chunk_offset, int n_columns, long int col_offset, int tot_n_cols);

  /* Like load_file but doens't allocate new memory each time.
   */
  template <class Type>
int load_file_v_1(const char str[], Type *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);

/* Loads the file located at str in the 2D array mem, whose dimensions
 * are specified by n_rows and n_columns
 */
template <class Type>
int load_file(const char str[], Type *** mem, int n_rows, int n_columns, long int offset=0, int total_n_columns=0);

/*
 * Loads in the array mem the matrices contained in the array of Matrix
 * matrices (which represent files). A smaller subset can be selected by
 * setting the parameters first_sample and n_samples.
 * We assume that n_columns among all matrices is equal, or that n_rows
 * is equal (or both), but it makes no sense if they're both unequal.
 *
 * Warning: No check is done on the bounds if a smaller subset is selected!
 *
 * @param n_matrices: length of the array matrices
 * @param transpose: If set to true, the resulting array "mem"  will be transposed
 * @param first_sample: Index of the first time_sample we want
 * @param n_samples: number of time samples we want
 */
template <class Type>
int import_matrices(Type *** mem, Matrix * matrices,
    unsigned int n_matrices, bool transpose,
    int first_sample = 0, int n_samples = 0);

template <typename Type>
int get_ncol(long int memsize, int ntraces);

/* Prints the top correlations by key, ranked by the correlation value. If the
 * correct key is specified, colors it :).
 */
template <class Type>
void print_top_r(Type corrs[], int n_keys, int correct_key=-1, string csv = "");


#endif
