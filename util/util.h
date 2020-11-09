/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#ifndef UTIL_H
#define UTIL_H

#include <iomanip>
#include <time.h>   // To initialize the random generator
#include <stdlib.h> // rand
#include <algorithm>

#include "../external/emp-tool.h"
#include "../external/emp-ot.h"
#include "../external/emp-sh2pc.h"

using namespace emp;
using namespace std;
using namespace std::chrono;

const static int N_THREADS = 4;   // Number of cores used in the parallelizable steps
const static int COMPRESSION = 0; // compression on ec elements

const static int MAX_LINE_LEN = 1000;  // used to read files
const static int MAX_NUM_LINES = 100;  // used to read files


/* Functions for printing elapsed times */

int ndigits(long int n)
{
  int count = 0;

  while (n != 0) {
    n = n / 10;
    ++count;
  }

  return count;
};

auto programStart = high_resolution_clock::now();
auto lastStamp    = high_resolution_clock::now();
bool startSet = false;

void tstamp(std::string msg)
{
  if (!startSet) {
    programStart = high_resolution_clock::now();
    lastStamp = programStart;
    startSet = true;
  }

  auto stop = high_resolution_clock::now();
  auto timeFromStart = duration_cast<microseconds>(stop - programStart);
  long int delta = duration_cast<microseconds>(stop - lastStamp).count();
  lastStamp = stop;

  cout << "[***] " << timeFromStart.count() << " us from start (+" << delta
       << ")" << std::string( 7 - ndigits(delta), ' ' ) << "\"" << msg << "\"" <<  endl;

};

long int arithmetic_time = 0;
long int algebraic_time = 0;
long int io_time = 0;

auto arithmetic_start = high_resolution_clock::now();
auto algebraic_start  = high_resolution_clock::now();
auto io_start         = high_resolution_clock::now();

void arithmetic_clock_start()
{
  arithmetic_start = high_resolution_clock::now();
};

void algebraic_clock_start()
{
  algebraic_start  = high_resolution_clock::now();
};

void io_clock_start()
{
  io_start         = high_resolution_clock::now();
};

void arithmetic_clock_stop(std::string msg)
{
  auto stop = high_resolution_clock::now();
  auto interval = duration_cast<microseconds>(stop - arithmetic_start);
  arithmetic_time += interval.count();
  cout << msg << ": ";
  printf("%ld us\n", interval.count());
};

void algebraic_clock_stop(std::string msg)
{
  auto stop = high_resolution_clock::now();
  auto interval = duration_cast<microseconds>(stop - algebraic_start);
  algebraic_time += interval.count();
  cout << msg << ": ";
  printf("%ld us\n", interval.count());
};

void io_clock_stop(std::string msg)
{
  auto stop = high_resolution_clock::now();
  auto interval = duration_cast<microseconds>(stop - io_start);
  io_time += interval.count();
  cout << msg << ": ";
  printf("%ld us\n", interval.count());
};


/* Functions for printing the size of transmitted data */

unsigned long total_size = 0;

void print_size_of_transmitted_dat(std::string dat_name, unsigned long bytes_size)
{
  total_size += bytes_size;
  std::cout << "[+] Sent " << dat_name << " of size (in bytes): " << bytes_size << endl;
};

void print_total_size()
{
  std::cout << "[+] Total bytes sent : " << total_size << endl;
};


/* Shorcuts for relic instructions */

inline void ec_init(ec_t A)
{
  ec_null(A);
  ec_new(A);
};

void ec_init_vector(ec_t* V, int length)
{
  for (int i = 0; i < length; ++i) {
    ec_init(V[i]);
  }
};

inline void bn_init(bn_t n)
{
  bn_null(n);
  bn_new(n);
};

void bn_init_vector(bn_t* v, int length)
{
  for_each (v, v + length, [&](bn_t elt) { bn_init(elt); });
};

void sample_Zp(bn_t out)
{
  bn_t ord;
  bn_null(ord);
  bn_new(ord);
  ec_curve_get_ord(ord);

  bn_rand_mod(out, ord);
  bn_free(ord);
};

void sample_Zp_out_labels(const CPCircuit& zkr, bn_t* zs, const bn_t& DELTA, const bn_t& ord)
{
  #pragma omp parallel default(none) shared(zs, DELTA, ord, zkr) num_threads(N_THREADS)
  {
    #pragma omp for schedule(guided, 2)

    for (int i = 0; i < zkr.num_outputs; ++i)
      {
        // Sample z0's and set z1's to be z0's + DELTA

        sample_Zp(zs[2 * i]);
        bn_add(zs[2 * i + 1], zs[2 * i], DELTA);
        bn_mod(zs[2 * i + 1], zs[2 * i + 1], ord);
      }
  };
}


/* Functions for dealing with char data and input/output files */

const char* bin_of_hex_char(char c)
{
  switch(toupper(c)) {
  case '0':  return "0000";
  case '1':  return "0001";
  case '2':  return "0010";
  case '3':  return "0011";
  case '4':  return "0100";
  case '5':  return "0101";
  case '6':  return "0110";
  case '7':  return "0111";
  case '8':  return "1000";
  case '9':  return "1001";
  case 'A':  return "1010";
  case 'B':  return "1011";
  case 'C':  return "1100";
  case 'D':  return "1101";
  case 'E':  return "1110";
  case 'F':  return "1111";
  }

  assert(false);
}

char* bin_of_hex(const char* hex)
{
  char* bin = (char*) malloc(4 * strlen(hex) * sizeof(char) +1);

  for (unsigned i = 0; i < strlen(hex); i++) {
    strcpy(bin + 4 * i, bin_of_hex_char(hex[i]));
  }

  return bin;
}

std::string uint8_to_hex_string(const uint8_t* v, int s)
{
  std::stringstream ss;

  ss << std::hex << std::setfill('0');

  for (int i = 0; i < s; i++) {
    ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
  }

  return ss.str();
}

std::string hex_str_of_bin_array(const bool* in, int len)
{
  // for simplicity, we assert that the len is a multiple of 4
  assert(len % 4 == 0);

  int byte_len = len / 8;
  uint8_t* byte_arr = new uint8_t[byte_len];
  uint8_t byte_value = 0;

  for (int i = 0; i < byte_len; ++i)
  {
    // get 4 bits at a time and convert them to int value
    for (int j = 0; j < 8; ++j)
    {
      byte_value += (int)in[8*i + j] * (1 << (7 - j));
    }
    byte_arr[i] = byte_value;

    byte_value = 0;
  }

  return uint8_to_hex_string(byte_arr, byte_len);
}

std::vector<uint8_t> hex_str_to_uint8(std::string input)
{
  std::vector<unsigned char> ending;
  ending.reserve( input.size());

  for (unsigned i = 0 ; i < input.length() ; i += 2) {
    std::string pair = input.substr( i, 2 );
    ending.push_back(::strtol( pair.c_str(), 0, 16 ));
  }

  return ending;
}

void rand_uint8_stream(uint8_t* output, int n_bytes)
{
  srand (time(NULL)); // init the generator

  for (int i = 0; i < n_bytes; ++i) {
    output[i] = rand();  // rand() produces an int (4 bytes?) this assignment truncates it to 1 byte
  }
};

// convert a uint8_t array of size 8 to an int64_t
// we create an init 0-value uint64 v
// then read the first byte, then left-shift v by 8
// then continue
int64_t bytesToInt64(uint8_t bytes[8])
{
  uint64_t v = 0;
  v |= bytes[0];  v <<= 8;
  v |= bytes[1];  v <<= 8;
  v |= bytes[3];  v <<= 8;
  v |= bytes[4];  v <<= 8;
  v |= bytes[5];  v <<= 8;
  v |= bytes[6];  v <<= 8;
  v |= bytes[7];
  return (int64_t)v;
}

inline void blockToUint8(uint8_t* out, block in)
{
  unsigned char* in_bytes = (unsigned char*) &in;
  memcpy(out, in_bytes, 16); // block is of type __mm128i == 128 bits
};

void read_hex(uint8_t* output, int len, std::string hex_str)
{
  std::vector<unsigned char> tmp = hex_str_to_uint8(hex_str);

  for (int i = 0; i < len; ++i) {
    output[i] = tmp[i];
  }
};

std::string read_str_from_file(std::ifstream& in)
{
  std::stringstream sstr;
  sstr << in.rdbuf();
  return sstr.str();
};

void ec_to_bytes(uint8_t* bytes, ec_t A)
{
  bn_t x;
  ec_null(x);
  ec_new(x);

  ec_norm(A, A);
  ec_get_x(x, A);

  int len = bn_size_bin(x);
  bn_write_bin(bytes, len, x);

  for (int i = len; i < 32; ++i) {
    bytes[i] = 0;
  }
};

void bool_of_uint8_stream(bool* output, uint8_t* input, int len)
{
  std::string input_string;
  input_string = uint8_to_hex_string(input, len);
  char* bin = bin_of_hex(input_string.c_str()); // of length 8*len

  for (int i = 0; i < len; ++i) {
    for (int j = 0; j < 8; ++j) {
      output[8 * i + j] = (bin[8 * i + j] == '0' ? false : true);
    }
  }
};

void bool_of_bn(bool* output, bn_t input, int len_in_bytes)
{
  uint8_t* bytes = new uint8_t[8 * len_in_bytes];
  bn_write_bin(bytes, len_in_bytes, input);
  bool_of_uint8_stream(output, bytes, len_in_bytes);
};

void bool_of_concat_uint8(bool* output, uint8_t* list1, int len1, uint8_t* list2, int len2)
{
  std::string list1_string, list2_string;

  list1_string = uint8_to_hex_string(list1, len1);
  list2_string = uint8_to_hex_string(list2, len2);

  char* bin1 = bin_of_hex(list1_string.c_str()); // of length 8*len1
  char* bin2 = bin_of_hex(list2_string.c_str()); // of length 8*len2

  for (int i = 0; i < len1; ++i) {
    for (int j = 0; j < 8; ++j) {
      output[8 * i + j] = (bin1[8 * i + j] == '0' ? false : true);
    }
  }

  for (int i = 0; i < len2; ++i) {
    for (int j = 0; j < 8; ++j) {
      output[8 * len1 + 8 * i + j] = (bin2[8 * i + j] == '0' ? false : true);
    }
  }

  free(bin1);
  free(bin2);
}

void find_line(char *line, const string ID, string filename){
  FILE* inp_f;
  char id[MAX_LINE_LEN];

  inp_f = fopen(filename.c_str(), "r");

  if (inp_f == NULL) {
    perror("[-] Cannot open input file");
    exit (EXIT_FAILURE);
  }

  // scan until the line starting with ID is found
  for (int i = 0; i < MAX_NUM_LINES; ++i)
  {
    assert(fscanf(inp_f, "%s %s\n", id, line) > 0);
    if (strcmp(id, ID.c_str()) == 0)  break;
  }
  fclose(inp_f);
}

void read_inp_bn(bn_t priv_in, const string ID, string filename)
{
  char priv_in_hex[MAX_LINE_LEN];

  find_line(priv_in_hex, ID, filename);
  int len = strlen(priv_in_hex) / 2; // we need the length in bytes
  uint8_t* inp_f_bytes = new uint8_t[len];
  std::string priv_in_hex_str(priv_in_hex);
  read_hex(inp_f_bytes, len, priv_in_hex_str);

  bn_read_bin(priv_in, inp_f_bytes, len);
};

void read_inp_ec(ec_t point, const string ID, string filename)
{
  char point_hex[MAX_LINE_LEN];

  find_line(point_hex, ID, filename);
  int len = strlen(point_hex) / 2; // we need the length in bytes
  uint8_t* point_bytes = new uint8_t[len];
  std::string point_hex_str(point_hex); // initialize a hex string from the hex data read for K
  read_hex(point_bytes, len, point_hex_str);

  ec_read_bin(point, point_bytes, len);
}

// Read a binary array from line 'order', of length 'len'

void read_inp_bin(bool* inp, int len, const string ID, string filename)
{
  char* tmp = new char[len];
  char inp_hex[MAX_LINE_LEN];

  find_line(inp_hex, ID, filename);
  tmp = bin_of_hex(inp_hex);
  for (int i = 0; i < len; ++i)
  {
    inp[i] = (tmp[i] == '0') ? false : true;
  }

  delete[] tmp;
}

void hex_str_to_uint8(uint8_t* data, const char* string) {

  if (string == NULL)
      return;

  size_t slength = strlen(string);
  if ((slength % 2) != 0) // must be even
      return;

  // size_t dlength = slength / 2;

  // uint8_t* data = (uint8_t*)malloc(dlength);

  // memset(data, 0, dlength);

  size_t index = 0;
  while (index < slength) {
      char c = string[index];
      int value = 0;
      if (c >= '0' && c <= '9')
          value = (c - '0');
      else if (c >= 'A' && c <= 'F')
          value = (10 + (c - 'A'));
      else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
      else
          return;

      data[(index / 2)] += value << (((index + 1) % 2) * 4);

      index++;
  }

}

void read_inp_uint8(uint8_t* data, const string ID, string filename)
{
  char inp_hex[MAX_LINE_LEN];

  find_line(inp_hex, ID, filename);
  hex_str_to_uint8(data, inp_hex);
};


/* Util functions for the zkCG protocol */

void simpleOT_blk_aes_cbc_enc(uint8_t* out, block key,
                              block* msg, int n_blocks, int counter_iterator)
{
  uint8_t* key_bytes = new uint8_t[16];
  uint8_t* msg_bytes = new uint8_t[16 * n_blocks]; // label(s) to be encrypted

  int* out_aes_len = new int; // will be passed as an input to bc_aes_cbc_enc
  // note that we encrypt blk of size 16, which will be padded by 16 inside AES
  // bn_aes_cbc_enc
  int in_len = 16 * n_blocks;
  int pad_len = 16; // 16  - (in_len - 16 * (in_len/ 16));
  *out_aes_len = in_len + pad_len;

  // the value of IV is set based on counter_iterator
  uint8_t* IV = new uint8_t[16];
  memcpy(IV, &counter_iterator, 4);// store the counter to the first 4 bytes of IV

  for (int i = 4; i < 16; ++i)  {
    IV[i] = 0;  // set the rest to 0
  }


  blockToUint8(key_bytes, key);

  for (int n = 0; n < n_blocks; ++n) {
    blockToUint8(msg_bytes + 16 * n, msg[n]);
  };

  assert(bc_aes_cbc_enc(out, out_aes_len, msg_bytes, 16 * n_blocks, key_bytes, 16, IV) == RLC_OK);
}

void simpleOT_blk_aes_cbc_dec(block* out, block key,
                              uint8_t* ciph, int n_blocks, int counter_iterator)
{
  uint8_t* key_bytes = new uint8_t[16];

  // remember that we concat all n_blocks blks together and treat them as the plain data
  // so the pad is computed only once (which doesnt make the len of out_ciph being double of plain)
  int* out_dec_len = new int;
  int in_len = 16 * n_blocks;
  int pad_len = 16; // 16 - (in_len - 16 * (in_len/ 16));
  *out_dec_len = in_len + pad_len;
  uint8_t* plain = new uint8_t[*out_dec_len];

  uint8_t* IV = new uint8_t[16];
  memcpy(IV, &counter_iterator, 4);

  for (int i = 4; i < 16; ++i)  {
    IV[i] = 0;
  }

  blockToUint8(key_bytes, key);

  assert(bc_aes_cbc_dec(plain, out_dec_len, ciph, *out_dec_len, key_bytes, 16, IV) == RLC_OK);

  // copy the first 16 bytes from the plaintext, omit the padding
  // assert *out_dec_len / 16 = in_len + 1
  for (int i = 0; i < n_blocks; ++i) {
    memcpy(out + i, plain + 16 * i, 16);
  }
}

void bn_add_repeated_squaring_outLink(bn_t out, bn_t* bases, int n)
{
  // computes out = \sum_{i = 0}^{n-1} 2^i bases_[n-i-1]
  // (note that we reverse the order of the bases)

  bn_copy(out, bases[0]);

  for (int i = 1; i < n; ++i) {
    bn_lsh(out, out, 1);
    bn_add(out, out, bases[i]);
  };

};

int send_bn(NetIO* netio, bn_t n)
{
  int len = bn_size_bin(n);
  netio->send_data(&len, sizeof(int));

  uint8_t* bytes = new uint8_t[len];
  bn_write_bin(bytes, len, n);
  netio->send_data(bytes, len * sizeof(uint8_t));
  free(bytes);
  return (len * sizeof(uint8_t) + sizeof(int));
};

void recv_bn(NetIO* netio, bn_t n)
{
  int len;
  netio->recv_data(&len, sizeof(int));

  uint8_t* bytes = new uint8_t[len];
  netio->recv_data(bytes, len * sizeof(uint8_t));
  bn_read_bin(n, bytes, len);
  free(bytes);
};


#endif // UTIL_H



