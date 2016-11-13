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
#include <vector>
#include <typeinfo>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <queue>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "utils.h"
#include "aes.h"
#include "des.h"
#include "cpa.h"

// TODO: fix trailing spaces problem in parsing config file


  template <class Type>
int import_matrices(Type *** mem, Matrix * matrices,
    unsigned int n_matrices, bool transpose,
    int first_sample, int n_samples)
{

  unsigned int i, j, k, res,
               cur_n_rows, cur_n_columns, n_col_1,
               tmp_i = 0,
               tmp_j = 0,
               total_n_rows = 0,
               total_n_columns = 0;

  bool n_col_equal = true;

  Type ** cur_matrix = NULL;

  /* First we need to know how large the matrices are all together and which
   * of the dimension is constant among all matrices.
   */
  n_col_1 = matrices[0].n_columns;
  total_n_rows += matrices[0].n_rows;
  total_n_columns += matrices[0].n_columns;

  for(i = 1; i < n_matrices; i++) {
    total_n_rows += matrices[i].n_rows;
    total_n_columns += matrices[i].n_columns;
    if(n_col_1 != matrices[i].n_columns)
      n_col_equal = false;
  }

  /* Then we allocate the right amount of memory, depending on the value of
   * transpose.
   */
  if (*mem == NULL) {
    if (n_col_equal)
      total_n_columns = n_col_1;
    else
      total_n_rows = matrices[0].n_rows;
    if(transpose)
      res = allocate_matrix(mem, total_n_columns, total_n_rows);
    else
      res = allocate_matrix(mem, total_n_rows, total_n_columns);
    if(res != 0)
      return -1;
  }

  /* Finally, we iterate over all matrices, load them in memory, and copy
   * their content to the final array mem. The multiple ifs are to distinguish
   * between when the result need to be transposed, and whether the rows or
   * columns are constant.
   */
  for(i = 0; i < n_matrices; i++) {
    cur_n_rows = matrices[i].n_rows;
    cur_n_columns = matrices[i].n_columns;
    res = load_file(matrices[i].filename, &cur_matrix, cur_n_rows, cur_n_columns);
    if(res != 0){
      fprintf (stderr, "Error: loading trace file.\n");
      return res;
    }


    if(n_col_equal) {
      if(n_samples == 0)
        n_samples = cur_n_columns;
      if(transpose) {
        for(j = 0; j < cur_n_rows; j++) {
          tmp_j = j + tmp_i;

          for(k = 0; k < (unsigned int) n_samples; k++) {
            (*mem)[k][tmp_j] = cur_matrix[j][k + first_sample];
          }
        }
      } else {
        for(j = 0; j < cur_n_rows; j++) {
          tmp_j = j + tmp_i;

          for(k = 0; k < (unsigned int) n_samples; k++) {
            (*mem)[tmp_j][k] = cur_matrix[j][k + first_sample];
          }
        }
      }
      tmp_i += cur_n_rows;
    } else {
      if(n_samples == 0)
        n_samples = cur_n_rows;
      if(transpose) {
        for(j = 0; j < (unsigned int) n_samples; j++) {

          for(k = 0; k < cur_n_columns; k++) {
            (*mem)[k + tmp_i][j] = cur_matrix[j + first_sample][k];
          }
        }
      } else {
        for(j = 0; j < (unsigned int) n_samples; j++) {

          for(k = 0; k < cur_n_columns; k++) {
            (*mem)[j][k + tmp_i] = cur_matrix[j + first_sample][k];
          }
        }
      }
      tmp_i += cur_n_columns;
    }
    free_matrix(&cur_matrix, cur_n_rows);
  }
  return 0;
}


/* Latest version of load file. This function is used to load chunks in the
 * chunk partitioning approach.
 *
 * This function is awesome, very cleverly designed, etc.. (Here you have your funny
 * comment Joppe :-) )
 * But seriously it is, but the chunk partitioning approach was not implemented
 * yet, so this function was never used. I left it just in case :D
 *
 * @param str           Path to the file to be loaded
 * @param mem           Pointer to the array in which to load the chunk
 * @param chunk_size    Number of rows to load
 * @param chunk_offset  Initial position in the rows from which we start loading
 * @param n_columns     Number of columns to load
 * @param col_offset    Initial position in the columns from which we start loading
 * @param tot_n_cols    Total number of columns in the file
 *
 * @return The number of bytes read
 */
  template <class Type>
size_t fload(const char str[], Type *** mem, int chunk_size, long int chunk_offset, int n_columns, long int col_offset, int tot_n_cols)
{
  FILE * file = NULL;
  int i, res;
  size_t total = 0;

  if (n_columns <= 0){
    fprintf (stderr, "Error: Invalid parameters: n_columns <= 0.\n");
    return -1;
  }

  if (n_columns + col_offset > tot_n_cols){
    fprintf (stderr, "Error: Invalid parameters: tot_n_cols < n_columns + col_offset.\n");
    return -1;
  }

  if (n_columns <= 0)
    return 0;

  file = fopen (str, "rb");
  if (file == NULL) {
    fprintf (stderr, "Error: opening %s failed.\n", str);
    return -1;
  }

  if (*mem == NULL) {
    fprintf (stderr, "Error: The array must be allocated beforehand.\n");
    return -1;
  }

  res = fseek(file, chunk_offset*tot_n_cols*sizeof(Type) + col_offset*sizeof(Type), SEEK_SET);
  if (res != 0) {
    fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
    return -1;
  }

  for (i=0; i < chunk_size; i++) {

    if ((*mem)[i] == NULL) {
      fprintf (stderr, "Error: The array must be allocated beforehand.\n");
      return -1;
    }

    res = fread ((*mem)[i], sizeof(Type), n_columns, file);
    if (res < n_columns) {
      fprintf (stderr, "Error: fread < 0 when reading file %s\n", str);
      return -1;
    }
    total += res;

    /* Used when importing a subset of the time samples.
     */
    res = fseek(file, (tot_n_cols - n_columns)*sizeof(Type), SEEK_CUR);
    if (res != 0) {
      fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
      return -1;
    }
  }

  fclose (file);

  return total;
}

/* Loads the file at path str to mem. The file must represent a matrix with
 * n_rows rows and n_columns columns. The offset represents where in the
 * columns we start loading the file (in case of large files) and sub_col
 * is the number of columns we want to load from the file. Finally, line_pos
 * is the line number of the array mem in which we will copy the content of
 * the file (this is in case of multiple files), in order not to have to load
 * a small matrix, then copy it afterwards like we used to do before.
 *
 */
 /*
  template <class Type>
int load_file_v_2(const char str[], Type *** mem, int n_rows, int n_columns, long int offset, int sub_col, int line_pos, int mem_offset)
{
  FILE * file = NULL;
  int i, res;
  //printf("Rows: %i, n_cols: %i, Offset: %lu, Sub_cols: %i, Line_pos: %i, Mem_Offset: %i\n", n_rows, n_columns, offset, sub_col, line_pos, mem_offset);

  if (sub_col + offset > n_columns){
    fprintf (stderr, "Error: Invalid parameters: total_n_columns < n_columns + offset.\n");
    return -1;
  }

  file = fopen (str, "rb");
  if (file == NULL) {
    fprintf (stderr, "Error: opening %s failed.\n", str);
    return -1;
  }

  if (*mem == NULL) {
    fprintf (stderr, "Error: the matrix must be allocated beforehand.\n");
    return -1;
  }

  res = fseek(file, offset*sizeof(Type), SEEK_CUR);
  if (res != 0) {
    fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
    return -1;
  }

  for (i = 0; i < n_rows; i++) {
    //printf("Rows: %i, n_cols: %i, Offset: %lu, Sub_cols: %i, Line_pos: %i, Mem_Offset: %i\n", n_rows, n_columns, offset, sub_col, line_pos, mem_offset);
    res = fread ((*mem)[i + line_pos] + mem_offset*sizeof(Type), sizeof(Type), sub_col, file);
    if (res < sub_col) {
      fprintf (stderr, "Error: fread < 0 when reading file %s\n", str);
      return -1;
    }
    // Used when importing a subset of the time samples.

    res = fseek(file, (n_columns - sub_col)*sizeof(Type), SEEK_CUR);
    //fprintf (stderr, "Error: %i\n", i);
    if (res != 0) {
      fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
      return -1;
    }
  }

  //printf ("Done reading file: %s\n", str);
  fclose (file);

  return 0;
}
*/
/* Like load_file but doens't allocate new memory each time.
 */
  template <class Type>
int load_file_v_1(const char str[], Type *** mem, int n_rows, int n_columns, long int offset, int total_n_columns)
{
  FILE * file = NULL;
  int i, res;

  if (n_columns <= 0){
    fprintf (stderr, "Error: Invalid parameters: n_columns <= 0.\n");
    return -1;
  }
  if (total_n_columns == 0)
    total_n_columns = n_columns;

  if (n_columns + offset > total_n_columns){
    fprintf (stderr, "Error: Invalid parameters: total_n_columns < n_columns + offset.\n");
    return -1;
  }

  if (n_columns <= 0)
    return 0;

  //printf("Rows: %i, n_cols: %i, Offset: %lu, tot_cols: %i\n", n_rows, n_columns, offset, total_n_columns);
  //std::cout << "HERE >>> "  << typeid((*mem)[0][0]).name() << " <<<" << endl;

  file = fopen (str, "rb");
  if (file == NULL) {
    fprintf (stderr, "Error: opening %s failed.\n", str);
    return -1;
  }

  if (*mem == NULL) {
    fprintf (stderr, "Error: The array must be allocated beforehand.\n");
    return -1;
  }

  //res = fseek(file, offset, SEEK_SET);
  res = fseek(file, offset*sizeof(Type), SEEK_CUR);
  if (res != 0) {
    fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
    return -1;
  }

  for (i=0; i < n_rows; i++) {
    if ((*mem)[i] == NULL) {
      fprintf (stderr, "Error: The array must be allocated beforehand.\n");
      return -1;
    }

    res = fread ((*mem)[i], sizeof(Type), n_columns, file);
    //res = fread ((*mem + i), sizeof(Type), n_columns, file);
    if (res < n_columns) {
      fprintf (stderr, "Error: fread < 0 when reading file %s\n", str);
      return -1;
    }

    /* Used when importing a subset of the time samples.
     */
    res = fseek(file, (total_n_columns - n_columns)*sizeof(Type), SEEK_CUR);
    if (res != 0) {
      fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
      return -1;
    }
  }

  //printf ("Done reading file: %s\n", str);
  fclose (file);
  /*
     for (int j = 0; j < n_rows; j++){
     for (int k = 0; k < n_columns; k++){
     fprintf(stderr, "%i\n", (*mem)[j][k]);
     }
     }
   */
  return 0;
}


  template <class Type>
int load_file(const char str[], Type *** mem, int n_rows, int n_columns, long int offset, int total_n_columns)
{
  FILE * file = NULL;
  int i, res;

  if (total_n_columns == 0)
    total_n_columns = n_columns;

  if (n_columns + offset > total_n_columns){
    fprintf (stderr, "Error: Invalid parameters: total_n_columns < n_columns + offset.\n");
    return -1;
  }

  file = fopen (str, "rb");
  if (file == NULL) {
    fprintf (stderr, "Error: opening %s failed.\n", str);
    return -1;
  }

  *mem = (Type **) malloc (n_rows * sizeof(Type *));
  if (*mem == NULL) {
    fprintf (stderr, "Error: allocating memory failed.\n");
    return -1;
  }

  res = fseek(file, offset*sizeof(Type), SEEK_CUR);
  if (res != 0) {
    fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
    return -1;
  }

  for (i=0; i < n_rows; i++) {
    (*mem)[i] = (Type *) malloc (n_columns * sizeof(Type));
    if ((*mem)[i] == NULL) {
      fprintf (stderr, "Error: allocating memory failed.\n");
      return -1;
    }

    res = fread ((*mem)[i], sizeof(Type), n_columns, file);
    if (res < n_columns) {
      fprintf (stderr, "Error: fread < 0 when reading file %s\n", str);
      return -1;
    }

    /* Used when importing a subset of the time samples.
     */
    res = fseek(file, (total_n_columns - n_columns)*sizeof(Type), SEEK_CUR);
    if (res != 0) {
      fprintf (stderr, "Error: fseek != 0 when reading file %s\n", str);
      return -1;
    }
  }

  //printf ("Done reading file: %s\n", str); fflush (stdout);
  fclose (file);

  return 0;
}

/* Returns the number of columns that can be loaded in memory.
 */
  template <typename Type>
int get_ncol(long int memsize, int ntraces)
{
  // We use 60% of the available memory. We never know what can happen :)
  return (0.6*memsize)/(sizeof(Type)*ntraces);
}


  template <class Type>
void free_matrix(Type *** matrix, int n_rows)
{
  for (int i=0; i < n_rows; i++) {
    free((*matrix)[i]);
  }
  free(*matrix);
}

/* Allocates the array matrix
 */
  template <class Type>
int allocate_matrix(Type *** matrix, int n_rows, int n_columns)
{
  *matrix = (Type **)malloc(n_rows * sizeof(Type *));
  if(*matrix == NULL)
    return -1;

  for (int i=0; i < n_rows; i++) {
    (*matrix)[i] = (Type *) malloc (n_columns * sizeof(Type));
    if((*matrix)[i] == NULL)
      return -1;
  }
  return 0;
}


/* Removes hading and trailing optional argument whitespace from the string str
 */
string trim(const string& str,
                 const string& whitespace = " \t")
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

/* Parse the sbox file at location fname and store it at sbox.
 * The format of the sbox file can be seen in the multiple example
 * files provided.
 */
int parse_sbox_file(const char * fname, uint16_t ** sbox)
{
  vector <uint16_t> data;
  char altfname [1024];
  if (access( fname, F_OK ) != -1)
  {
    strncpy(altfname, fname, sizeof(altfname));
    altfname[sizeof(altfname)-1]=0;
  } else {
    strncpy(altfname, RESOURCES, sizeof(altfname));
    strncat(altfname, fname, sizeof(altfname)-strlen(altfname)-1);
    altfname[sizeof(altfname)-1]=0;
    cout << "[INFO] File " << fname << " not found, using " << altfname << " instead." <<  endl;
    if (access( altfname, F_OK ) == -1)
    {
      cerr << "[ERROR]: Can't access file " << fname << endl;
      cerr << "[ERROR]: Can't access file " << altfname << endl;
      return -1;
    }
  }
  ifstream infile( altfname );
  *sbox = NULL;
  while (infile)
  {
    string s;
    if (!getline( infile, s )) break;

    istringstream ss( s );

    while (ss)
    {
      string s;
      string trm;
      if (!getline( ss, s, ',' )) break;
      trm = trim(s);
      if (!trm.compare("{") || !trm.compare("}")) continue;
      data.push_back( strtol(trm.c_str(), NULL, 0) );
    }

  }
  if (!infile.eof())
  {
    cerr << "[ERROR]: Reading file " << altfname << endl;
    return -1;
  }

  *sbox = (uint16_t *) malloc(data.size()*sizeof(uint16_t));

  if (*sbox == NULL){
    cerr << "[ERROR]: Allocating memory for lookup table" << endl;
    free(*sbox);
    return -1;
  }
  int j = 0;
  for( std::vector<uint16_t>::const_iterator i = data.begin(); i != data.end(); ++i){
     (*sbox)[j] = *i;
     j++;
     //cout << *i << endl;
  }
  // ADD COLOR
  int x = data.size();
  if (x & (x - 1)) cerr << KRED << "[WARNING]" << RESET " The size of the lookup table parsed is not a power of two." << endl;
  //cout << "[Size:]" << data.size() << endl;
  return 0;
}

/* Parse the command line arguments, only two supported
 * -c for the config file location
 * -h for help
 */
int parse_args(int argc, char * argv[], char ** config_file)
{

  // char * config_file = NULL;
  const char * opts = "c:h";
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, opts)) != -1){
    switch (c)
    {
      case 'c':
        (*config_file) = optarg;
        break;
      case 'h':
        printf("Usage: %s -c config_file\n", argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
        //return 1;
      default:
        //fprintf (stderr, "?? getopt returned character code 0%o ??\n", c);
        break;
    }
  }
  if (config_file == NULL) {
    printf("Mandatory argument configuration file unspecified.\n");
    return -1;
  }

  return 0;
}

int load_config(Config & config, const char * conf_file)
{

  ifstream fin(conf_file, ifstream::in);
  if (!fin.good()) {
    fprintf(stderr, "Error: could not open config file %s\n", conf_file);
    return -1;
  }
  string line;
  bool traces = true;
  int i_traces = 0;

  int n_rows, n_columns;

  /* Variables to deduct the total number of rows and columns.
   */
  int tot_row_traces = 0,
      tot_col_traces = 0,
      tot_row_guesses = 0,
      tot_col_guesses = 0;

  config.n_threads = 4;
  config.index_sample = 0;
  config.n_samples = 0;
  config.attack_order = 1;
  config.total_n_keys = 256;
  config.correct_key = -1;
  config.type_return = 'd';
  config.type_guess = 'u';
  config.type_trace = 'f';
  config.window = 0;
  config.algo = ALG_AES;
  config.position = -1;
  config.round = 0;
  config.bytenum = 0;
  config.n_traces = 0;
  config.transpose_traces = true;
  config.transpose_guesses = true;
  config.memory = 4*GIGA;
  config.key_size = 0;
  config.top = 50;
  config.des_switch = DES_8_64;
  config.sep = "";
  config.sbox = NULL;
  config.bitnum = -2;
  config.complete_correct_key = NULL;
  config.original_correct_key = NULL;

  while (getline(fin, line)) {
    if (line[0] == '#'){
      // The line is a comment so we just skip it.
      continue;
    }
    if (line.find("[Traces]") != string::npos) {
      traces = true;
      i_traces = 0;
    }else if (line.find("ntraces") != string::npos) {
      config.n_traces = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("[Guesses]") != string::npos) {
      traces = false;
      i_traces = 0;
    }else if (line.find("type") != string::npos) {

      if (line.find("return_type") != string::npos) {
        string type = line.substr(line.find("=") + 1);
        config.type_return = type[0];
      }else if (line.find("trace_type") != string::npos) {
        string type = line.substr(line.find("=") + 1);
        config.type_trace = type[0];
      }else if (line.find("guess_type") != string::npos) {
        string type = line.substr(line.find("=") + 1);
        config.type_guess = type[0];
      }
    }else if (line.find("files") != string::npos) {
      if (traces){
        config.n_file_trace = atoi(line.substr(line.find("=") + 1).c_str());
        config.traces = (Matrix *) malloc(config.n_file_trace * sizeof(Matrix));
      }else {
        config.n_file_guess = atoi(line.substr(line.find("=") + 1).c_str());
        config.guesses = (Matrix *) malloc(config.n_file_guess * sizeof(Matrix));
      }
    }else if (line.find("trace") != string::npos || line.find("guess") != string::npos) {
      if (traces){
        if (i_traces >= config.n_file_trace)
          continue;
      }else{
        if (i_traces >= config.n_file_guess)
          continue;
      }
      string tmp = line.substr(line.find("=") + 1);
      string path = tmp.substr(0, tmp.find(" "));
      char * p = (char*)malloc((path.size()+1)*sizeof(char));
      if (p == NULL){
        fprintf(stderr, "Error: allocating memory for path name.\n");
        return -1;
      }
      strncpy(p, path.c_str(), path.size());
      p[path.size()] = '\0';
      tmp = tmp.substr(tmp.find(" ") + 1);
      n_rows = atoi(tmp.substr(0, tmp.find(" ")).c_str());
      tmp = tmp.substr(tmp.find(" ") + 1);
      n_columns = atoi(tmp.c_str());
      if (traces) {
        config.traces[i_traces] = Matrix(p, n_rows, n_columns);
        tot_row_traces += n_rows;
        tot_col_traces += n_columns;
      }else{
        config.guesses[i_traces] = Matrix(p, n_rows, n_columns);
        tot_row_guesses += n_rows;
        tot_col_guesses += n_columns;
      }
      i_traces += 1;
    }
    else if (line.find("threads") != string::npos) {
      config.n_threads = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("index") != string::npos) {
      config.index_sample = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("nsamples") != string::npos) {
      config.n_samples = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("transpose") != string::npos) {
      string tmp = line.substr(line.find("=") + 1);
      if(traces)
        config.transpose_traces = (tmp[0] == 't' ? true : false);
      else
        config.transpose_guesses = (tmp[0] == 't' ? true : false);
    }else if (line.find("order") != string::npos) {
      config.attack_order = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("nkeys") != string::npos) {
      config.total_n_keys = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("window") != string::npos) {
      config.window = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("algorithm") != string::npos) {
      string tmp_algo = line.substr(line.find("=") + 1).c_str();
      if (!tmp_algo.compare("AES")){
        config.algo = ALG_AES;
        config.total_n_keys = 256;
      }else if (!tmp_algo.compare("DES")){
        config.algo = ALG_DES;
        config.total_n_keys = 64;
      }else
          fprintf(stderr, "[WARNING]\tUnknown algorithm %s\n", tmp_algo.c_str());
    }else if (line.find("des_switch") != string::npos) {
      string tmp_switch = line.substr(line.find("=") + 1).c_str();
      if (!tmp_switch.compare("DES_8_64")){
        config.des_switch = DES_8_64;
      }else if (!tmp_switch.compare("DES_8_64_ROUND")){
        config.des_switch = DES_8_64_ROUND;
      }else if (!tmp_switch.compare("DES_32_16")){
        config.des_switch = DES_32_16;
      }else if (!tmp_switch.compare("DES_4_BITS")){
        config.des_switch = DES_4_BITS;
        config.total_n_keys = 16;
      }else if (!tmp_switch.compare("DES_6_BITS")){
         config.des_switch = DES_6_BITS;
      }else
          fprintf(stderr, "[WARNING]\tUnknown DES lookup table layout %s\n", tmp_switch.c_str());
    }else if (line.find("round") != string::npos) {
      config.round = atoi(line.substr(line.find("=") + 1).c_str());

    }else if (line.find("correct_key") != string::npos) {
      string tmp = line.substr(line.find("=") + 1);
      if (tmp.size() > 4) { // A single key byte will be at most 4 in length
        if (tmp.compare(0, 2, "0x")){
          fprintf(stderr, "Error: Invalid key format for %s.\nComplete key must start with 0x.\n", tmp.c_str());
          return -1;
        }
        tmp.erase(remove_if(tmp.begin(), tmp.end(), ::isspace), tmp.end());
        config.key_size = (tmp.size()-2)/2;
        config.complete_correct_key  = (uint8_t *)malloc(config.key_size*sizeof(uint8_t));
        for (int i = 0; i < config.key_size; i++){
          config.complete_correct_key[i] = (uint8_t) strtoul(tmp.substr(2+i*2, 2).c_str(), NULL, 16);
        }

      }else {

        if (!tmp.compare(0, 2, "0x"))
          config.correct_key = (int) strtol(tmp.c_str(), NULL, 16);
        else
          config.correct_key = atoi(tmp.c_str());
      }
    }else if (line.find("separator") != string::npos) {
      config.sep = line.substr(line.find("=") + 1);
    }else if (line.find("position") != string::npos) {
      string tmp_pos = line.substr(line.find("=") + 1).c_str();
      config.all_sboxes.push_back(tmp_pos);

    }else if (line.find("bytenum") != string::npos) {
      string tmp = line.substr(line.find("=") + 1);
      if (!tmp.compare("all"))
        config.bytenum = -1;
      else
        config.bytenum = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("bitnum") != string::npos) {
      string tmp = line.substr(line.find("=") + 1);
      if (!tmp.compare("all"))
        config.bitnum = -1;
      else if (!tmp.compare("none"))
        config.bitnum = -2;
      else
        config.bitnum = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("top") != string::npos) {
      config.top = atoi(line.substr(line.find("=") + 1).c_str());
    }else if (line.find("memory") != string::npos) {
      string tmp = line.substr(line.find("=") + 1);
      long int suffix;
      if (tmp[tmp.size()-1] == 'G')
        suffix = GIGA;
      else if (tmp[tmp.size()-1] == 'M')
        suffix = MEGA;
      else{
        fprintf(stderr, "Error: Unsupported memory size, using default instead.\n");
        continue;
      }
      //printf("%s %li %f\n", tmp.c_str(), tmp.size(), atof(tmp.substr(0, tmp.size() - 1).c_str()));
      config.memory = (long int)(atof(tmp.substr(0, tmp.size() - 1).c_str())*suffix);
    }

  }

  /* config.correct = -1 is the default value. It stays -1 if no key is
   * specified or if the complete key is specified. But if only one byte
   * is set, we artificially set it to -1. I don't know why..
   * EDIT. In fact I do. In DES, it's impossible to correlate to only one
   * part of the secret key, as it is going to be completely split into
   * pieces.
   */
  if (config.algo == ALG_DES && config.correct_key != -1){
    config.correct_key = -1;
    printf("[WARNING] Cannot provide information on a single key byte with DES. Assuming it was unspecified instead.\n");
  }

  /* If it's DES, we update the key to the round key. But we express the round
   * key as an array of size 8 of 6-bit values.
   */
  if (config.algo == ALG_DES && config.key_size == 8){
    uint8_t tmp_round_key[6];
    config.original_correct_key = config.complete_correct_key;
    config.complete_correct_key  = (uint8_t *)malloc(config.key_size*sizeof(uint8_t));
    if (config.complete_correct_key == NULL) {
      fprintf(stderr, "Error: Allocating memory for correct key.\n");
      return -1;
    }
    get_round_key(config.original_correct_key, tmp_round_key, config.round);
    convert_rkey(tmp_round_key, config.complete_correct_key);

  }

  /* Make sure that if a single bit is attacked, the parameter is not greater
   * than the number of bits of the target algorithm.
   */
  if ((config.algo == ALG_DES && config.bitnum > 3) || (config.algo == ALG_AES &&
              config.bitnum > 7)){
    fprintf(stderr, "Error: Invalid target bit, value too large for %s.\n",
            config.algo ? "DES" : "AES");
    return -1;
  }

  /* If the correct key is unknown then we set the key size to the algorithm default.
   */
  if (config.key_size == 0) {
    if(config.algo == ALG_DES) {
        config.key_size = 8;
    }
    if(config.algo == ALG_AES) {
        config.key_size = 16;
    }
  }

  /* Logic to compute the total number of traces, time samples and key guesses.
   */
  if (tot_row_traces == tot_row_guesses) {
    config.total_n_traces = tot_row_traces;
    config.total_n_samples = config.traces[0].n_columns;
    config.n_col_keys = config.guesses[0].n_columns;
  }else if (tot_col_traces == tot_col_guesses){
    /* Thus we assume that the number of columns are equal.
     */
    config.total_n_traces = tot_col_traces;
    config.total_n_samples = config.traces[0].n_rows;
    config.n_col_keys = config.guesses[0].n_rows;
  }else{
    fprintf(stderr, "Error: the dimensions do not match.\n");
    return -1;
  }

  /* If we don't specify a smaller subset fot the target number of traces,
   * we automatically treat the whole set.
   */
  if (config.n_traces == 0)
    config.n_traces = config.total_n_traces;

  /* For the number of samples, if we don't specify the number of samples, but
   * we specify the index of the first, we adjust the total, otherwise, we
   * treat the whole set.
   */
  if (config.n_samples == 0){
    if (config.index_sample != 0)
      config.n_samples = config.total_n_samples - config.index_sample;
    else
      config.n_samples = config.total_n_samples;
  }
  /* If the specified window is larger than the number of samples, we
   * set its value to n_samples.
   */
  if (config.window > config.n_samples)
    config.window = config.n_samples;

  return 0;
}


void print_config(Config &conf)
{
  printf("\n[CONFIGURATION]\n");
  printf("\n  [GENERAL]\n");

  printf("\tNumber of threads:\t %i\n", conf.n_threads);
  printf("\tIndex first sample:\t %i\n", conf.index_sample);
  if (conf.n_samples)
    printf("\tNumber of samples:\t %i\n", conf.n_samples);
  else
    printf("\tNumber of samples:\t %s\n", "all");
  printf("\tTotal number traces:\t %i\n", conf.total_n_traces);
  printf("\tTarget number traces:\t %i\n", conf.n_traces);
  printf("\tTotal number keys:\t %i\n", conf.total_n_keys);

  printf("\tAttack order:\t\t %i\n", conf.attack_order);

  printf("\tReturn Type:\t\t %c\n", conf.type_return);
  printf("\tWindow size:\t\t %i\n", conf.window);
  printf("\tAlgorithm:\t\t %s\n", conf.algo ? "DES" : "AES");

  printf("\tRound:\t\t\t %i\n", conf.round);
  if (conf.bytenum == -1)
    printf("\tBytenum:\t\t all\n");
  else
    printf("\tBytenum:\t\t %i\n", conf.bytenum);
  if (conf.bitnum == -1)
    printf ("\tTarget all bits individually.\n");
  else if (conf.bitnum >= 0 && conf.bitnum < 8)
    printf ("\tTarget bit number:\t %d\n", conf.bitnum);
  else conf.bitnum = -2;

  printf("\tSecret Key:\t\t ");

  if (conf.key_size == 1 && conf.correct_key != -1)
    printf("%#x\n", conf.correct_key);
  else if (conf.complete_correct_key != NULL) {
    printf("0x");
    for(int i = 0; i < conf.key_size; i++) {
      printf("%02x ", conf.algo ? conf.original_correct_key[i] : conf.complete_correct_key[i]);
    }
    printf("\n");
  }
  else
    printf("Unspecified\n");

  if (conf.algo == ALG_DES){
    if(conf.key_size > 1 && conf.complete_correct_key != NULL) {
    printf("\tRound Key:\t\t 0x");
    for(int i = 0; i < conf.key_size; i++) {
      printf("%02x ", conf.complete_correct_key[i]);
    }
    printf("\n");
    }
    if ((conf.des_switch == DES_8_64)||(conf.des_switch == DES_8_64_ROUND)) printf("\tLookup table layout:\t [8x64]\n");
    else if (conf.des_switch == DES_32_16) printf("\tLookup table layout:\t [32x16]\n");
    else if (conf.des_switch == DES_4_BITS) printf("\tLookup table layout:\t [4]\n");
    else if (conf.des_switch == DES_6_BITS) printf("\tLookup table layout:\t [6]\n");
  }

  if(conf.memory > GIGA)
    printf("\tMemory:\t\t\t %.2fGB\n", conf.memory/GIGA);
  else if(conf.memory > MEGA)
    printf("\tMemory:\t\t\t %.2fMB\n", conf.memory/MEGA);
  printf("\tKeep track of:\t\t %i\n", conf.top);


  if (conf.sep == "") printf("\tSeparator :\t\t STANDARD\n");
  else printf("\tSeparator :\t\t %s\n", conf.sep.c_str());
  printf("\n  [TRACES]\n");
  printf("\tTraces files:\t\t %i\n", conf.n_file_trace);
  printf("\tTraces type:\t\t %c\n", conf.type_trace);
  printf("\tTranspose traces:\t %s\n", conf.transpose_traces ? "True" : "False");
  printf("\tTotal number samples:\t %i\n", conf.total_n_samples);
  printf("\tTraces:\n");
  for (int i = 0; i < conf.n_file_trace; i++)
    printf("\t%d. %s\t [%ix%i]\n", i+1, conf.traces[i].filename, conf.traces[i].n_rows, conf.traces[i].n_columns);

  printf("\n  [GUESSES]\n");
  printf("\tGuesses files:\t\t %i\n", conf.n_file_guess);
  printf("\tGuesses type:\t\t %c\n", conf.type_guess);
  printf("\tTranspose guesses:\t %s\n", conf.transpose_guesses ? "True" : "False");
  printf("\tTotal columns guesses:\t %i\n", conf.n_col_keys);
  printf("\tGuesses:\n");
  for (int i = 0; i < conf.n_file_guess; i++)
    printf("\t\t%d. %s\t [%ix%i]\n", i+1, conf.guesses[i].filename, conf.guesses[i].n_rows, conf.guesses[i].n_columns);
  printf("\n[/CONFIGURATION]\n\n");
}


  template <class Type>
void print_top_r(Type corrs[], int n_keys, int correct_key, string csv)
{
  sort(corrs, corrs + n_keys);
  if (csv == ""){
  cout << "Rank" << setw(14) << "Correlation" << setw(7) << "Key" << setw(16) << "Sample(s)" << endl;
  int nbest = 20; // TODO: make it a config parameter
  for (int i = n_keys - 1; i >= 0; i--) {
    // We start ranking at 0, to be consistant with inspector, otherwise n_keys-i
    if ((correct_key == -1) &&( i > n_keys -1 - nbest))
      cout << setw(2) << n_keys - i - 1 << "." << corrs[i] << endl;
    else if (corrs[i] == correct_key)
      cout << setw(2) << n_keys - i - 1 << "." << setw(-2) << corrs[i] << endl;
  }
  cout << endl;
  cout << flush;
  }else{
    for (int i = n_keys - 1; i >= 0; i--) {
      if (corrs[i] == correct_key){
        cout << n_keys - i - 1 << csv;
        corrs[i].corr2str(csv);
      }
    }

  }
}

/* Template instantiations
 */
template int import_matrices(float *** mem, Matrix * matrices, unsigned int n_matrices, bool transpose, int first_sample = 0, int n_samples = 0);
template int import_matrices(double *** mem, Matrix * matrices, unsigned int n_matrices, bool transpose, int first_sample = 0, int n_samples = 0);
template int import_matrices(int8_t *** mem, Matrix * matrices, unsigned int n_matrices, bool transpose, int first_sample = 0, int n_samples = 0);
template int import_matrices(uint8_t *** mem, Matrix * matrices, unsigned int n_matrices, bool transpose, int first_sample = 0, int n_samples = 0);

template size_t fload(const char str[], float *** mem, int chunk_size, long int chunk_offset, int n_columns, long int col_offset, int tot_n_cols);
template size_t fload(const char str[], int8_t *** mem, int chunk_size, long int chunk_offset, int n_columns, long int col_offset, int tot_n_cols);

template int load_file_v_1(const char str[], float *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file_v_1(const char str[], double *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file_v_1(const char str[], int8_t *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file_v_1(const char str[], uint8_t *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file_v_1(const char str[], int *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);

template int load_file(const char str[], float *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file(const char str[], double *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file(const char str[], int8_t *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);
template int load_file(const char str[], uint8_t *** mem, int n_rows, int n_columns, long int offset, int total_n_columns);

template int get_ncol<int8_t>(long int memsize, int ntraces);
template int get_ncol<float>(long int memsize, int ntraces);
template int get_ncol<double>(long int memsize, int ntraces);

template void free_matrix(float *** matrix, int n_rows);
template void free_matrix(double *** matrix, int n_rows);
template void free_matrix(uint8_t *** matrix, int n_rows);
template void free_matrix(int8_t *** matrix, int n_rows);
template void free_matrix(int *** matrix, int n_rows);

template void print_top_r(CorrSecondOrder <double> corrs[], int n_keys, int correct_key, string csv);
template void print_top_r(CorrSecondOrder <float> corrs[], int n_keys, int correct_key, string csv);
template void print_top_r(CorrFirstOrder <double> corrs[], int n_keys, int correct_key, string csv);
template void print_top_r(CorrFirstOrder <float> corrs[], int n_keys, int correct_key, string csv);

template int allocate_matrix(float *** matrix, int n_rows, int n_columns);
template int allocate_matrix(double *** matrix, int n_rows, int n_columns);
template int allocate_matrix(uint8_t *** matrix, int n_rows, int n_columns);
template int allocate_matrix(int8_t *** matrix, int n_rows, int n_columns);
template int allocate_matrix(int *** matrix, int n_rows, int n_columns);

