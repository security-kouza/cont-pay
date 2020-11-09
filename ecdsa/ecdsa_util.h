/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#ifndef ECDSA_UTIL_H
#define ECDSA_UTIL_H

/* Constants for data processing */

const static string PKFILE = "data/public.key";
const static string SKFILE = "data/private.key";

const static string MSGFILE = "data/msg.txt";
const static string CIRCUIT = "data/XOR_SHA.txt";
const static string PUBFILE = "data/pub_input.txt";
const static string PRVFILE = "data/prv_input.txt";

const static int EXTRA_BN_LEN = 1; // sk (the verifier won't use it)
const static int EXTRA_EC_LEN = 2; // PK, K
const static int EXTRA_BYTES_LEN = RLC_MD_LEN; // msg_hash

const static int Y_BYTES_LEN = 32;          // y is a SHA2 image
const static int CT_BYTES_LEN = 32;         // we OPT the signature with a 32 bytes key
const static int SIG_BYTES_LEN = 32;        // the signature is 32 bytes long (EC order is 256-bits)
const static int PADDED_SIG_BYTES_LEN = 48; // input to SHA (sig || pad) = (32 bytes || 16 bytes)
const static int PRV_INPUT_BITS_LEN = 512;  // we define the private input as sig || pad || 0x180


ExtraInput init_extra_input(){
  ExtraInput extra;
  extra.bn_len = EXTRA_BN_LEN;
  extra.ec_len = EXTRA_EC_LEN;
  extra.bytes_len = EXTRA_BYTES_LEN;

  bn_t *bn_list = (EXTRA_BN_LEN > 0) ? new bn_t[EXTRA_BN_LEN] : NULL; // do not free here
  ec_t *ec_list = (EXTRA_EC_LEN > 0) ? new ec_t[EXTRA_EC_LEN] : NULL; // do not free here
  uint8_t *bytes_list = new uint8_t[EXTRA_BYTES_LEN]; // do not free here
  extra.bn_list = bn_list;
  extra.ec_list = ec_list;
  extra.bytes_list = bytes_list;
  return extra;
};

void read_pk(ec_t PK, string filename)
{

  FILE* pub;
  char pk_hex[MAX_LINE_LEN];

  pub = fopen(filename.c_str(), "r");

  if (pub == NULL) {
    perror("[-] Cannot open PK file");
    exit (EXIT_FAILURE);
  }

  assert(fscanf(pub, "%s\n", pk_hex) > 0);

  int len = strlen(pk_hex) / 2; // we need the length in bytes
  uint8_t* pk_bytes = new uint8_t[len];
  std::string pk_hex_str(pk_hex);
  read_hex(pk_bytes, len, pk_hex_str);

  ec_read_bin(PK, pk_bytes, len);
  fclose(pub);
};

void read_sk(bn_t sk, string filename)
{

  FILE* priv;
  char sk_hex[MAX_LINE_LEN];

  priv = fopen(filename.c_str(), "r");

  if (priv == NULL) {
    perror("[-] Cannot open SK file");
    exit (EXIT_FAILURE);
  }

  assert(fscanf(priv, "%s\n", sk_hex) > 0);

  int len = strlen(sk_hex) / 2; // we need the length in bytes
  uint8_t* sk_bytes = new uint8_t[len];
  std::string sk_hex_str(sk_hex);
  read_hex(sk_bytes, len, sk_hex_str);

  bn_read_bin(sk, sk_bytes, len);
  fclose(priv);
};


void keygen()
{

  FILE* pub, *priv;
  bn_t sk;
  ec_t PK;

  pub  = fopen(PKFILE.c_str(), "w");
  priv = fopen(SKFILE.c_str(), "w");

  if (pub == NULL || priv == NULL) {
    printf("Error opening key files");
    exit(1);
  }

  bn_new(sk);
  ec_new(PK);
  assert(cp_ecdsa_gen(sk, PK) == RLC_OK);

  printf("Generated PK:\n");
  ec_print(PK);

  // Print the public key

  int len = ec_size_bin(PK, COMPRESSION);
  uint8_t* pk_bytes = new uint8_t[len];

  ec_write_bin(pk_bytes, len, PK, COMPRESSION);
  fprintf(pub, "%s\n", uint8_to_hex_string(pk_bytes, len).c_str());
  fclose(pub);

  // Print the private key

  len = bn_size_bin(sk);
  uint8_t* sk_bytes = new uint8_t[len];

  bn_write_bin(sk_bytes, len, sk);
  fprintf(priv, "%s\n", uint8_to_hex_string(sk_bytes, len).c_str());
  fclose(priv);
};


void adjustMsg(bn_t e, int len, bn_t ord, uint8_t* msg_hash)
{
  if (8 * len > bn_bits(ord)) {
    len = RLC_CEIL(bn_bits(ord), 8);
    bn_read_bin(e, msg_hash, len);
    bn_rsh(e, e, 8 * len - bn_bits(ord));
  } else {
    bn_read_bin(e, msg_hash, len);
  }
}

void ecdsa_read_pub_instance(bool* pub_input, ExtraInput extra)
{

  printf("[+] Reading public input from file ...\n");

  int pub_input_len = (CT_BYTES_LEN + Y_BYTES_LEN) * 8; // in bits

  read_pk(extra.ec_list[0], PKFILE);
  read_inp_bin(pub_input, pub_input_len, "(ct,y)", PUBFILE);
  read_inp_uint8(extra.bytes_list, "msg_hash", PUBFILE);
  read_inp_ec(extra.ec_list[1], "K", PUBFILE);
};


void ecdsa_read_priv_instance(bn_t secret, bool* priv_input, ExtraInput extra)
{

  printf("[+] Reading private input from file ...\n");

  read_sk(extra.bn_list[0], SKFILE);
  read_inp_bn(secret, "s_inv", PRVFILE);
  read_inp_bin(priv_input, PRV_INPUT_BITS_LEN, "key", PRVFILE);
};


void setup(){

  // Read the msg to be signed

  uint8_t *msg_hash = new uint8_t[RLC_MD_LEN];

  ifstream in;
  in.open(MSGFILE);
  string msg = read_str_from_file(in);
  unsigned char* msg_uint8 = new unsigned char[msg.length()];
  std::copy(msg.begin(), msg.end(), msg_uint8);
  md_map(msg_hash, msg_uint8, sizeof(msg_uint8));
  // for (int i = 0; i < 32; ++i)
  // {
  //   if (i < 32) printf("%d\n", msg_hash[i]); 
  // }

  // Compute an ECDSA signature on msg_hash

  bn_t s, s_inv, r, sk;
  bn_init(s);
  bn_init(s_inv);
  bn_init(r);
  bn_init(sk);

  ec_t K;
  ec_init(K);

  read_sk(sk, SKFILE);
  assert(ecdsa_sig(r, s, K, msg_hash, sk) == RLC_OK);

  // prepare the public input (ct, y) and the secret input (s, k) for the GC

  bn_t ord, aux;
  bn_init(ord);
  bn_init(aux);
  ec_curve_get_ord(ord);
  bn_gcd_ext(aux, s_inv, NULL, s, ord);  // compute s_inv = s^{-1} (over Zp)

  if (bn_sign(s_inv) == RLC_NEG) {
    bn_add(s_inv, s_inv, ord);
  }

  assert(bn_size_bin(s_inv) == SIG_BYTES_LEN);
  uint8_t* s_inv_bytes = new uint8_t[SIG_BYTES_LEN];
  uint8_t* y_bytes = new uint8_t[Y_BYTES_LEN]; // SHA256 produces 32 bytes

  bn_write_bin(s_inv_bytes, SIG_BYTES_LEN, s_inv);

  // We produce ct with One-Time-Pad  (ct = s_inv \xor k1)

  uint8_t* ct = new uint8_t[SIG_BYTES_LEN];
  uint8_t* k1 = new uint8_t[SIG_BYTES_LEN];
  rand_uint8_stream(k1, SIG_BYTES_LEN);

  for (int i = 0; i < SIG_BYTES_LEN; ++i) {
    ct[i] = s_inv_bytes[i] ^ k1[i];
  }

  // k1 || k_padding will be the SHA input

  uint8_t* k_padding = new uint8_t[PADDED_SIG_BYTES_LEN - SIG_BYTES_LEN];
  rand_uint8_stream(k_padding, PADDED_SIG_BYTES_LEN - SIG_BYTES_LEN);

  uint8_t* sha_input = new uint8_t[PADDED_SIG_BYTES_LEN];

  // compute y = SHA(k1 || k)

  for (int i = 0; i < PADDED_SIG_BYTES_LEN; ++i) {
    if (i < SIG_BYTES_LEN) { sha_input[i] = k1[i]; }
    else                   { sha_input[i] = k_padding[i - SIG_BYTES_LEN]; }
  }

  md_map_sh256(y_bytes, sha_input, PADDED_SIG_BYTES_LEN);

  // cast a uint8_t* to bool arrays and concat them

  bool* pub_input = new bool[512];
  bool* priv_input = new bool[512];

  bool_of_concat_uint8(pub_input, ct, SIG_BYTES_LEN, y_bytes, Y_BYTES_LEN);
  bool_of_uint8_stream(priv_input, sha_input, PADDED_SIG_BYTES_LEN);

  // extra hex data appended to SHA2's input so as to complete one full execution
  // k is 256 + 128 bits long, 0x180 in hex

  char k_extra[] = "80000000000000000000000000000180";
  char* bin_k_extra = bin_of_hex(k_extra);

  for (int i = 0; i < (512 - 8 * PADDED_SIG_BYTES_LEN); ++i) {
    priv_input[8 * PADDED_SIG_BYTES_LEN + i] = (bin_k_extra[i] == '0' ? false : true);
  }

  // Write input data to file for future reading

  FILE* pub_f = fopen(PUBFILE.c_str(), "w");
  FILE* priv_f = fopen(PRVFILE.c_str(), "w");

  if (pub_f == NULL){ printf("[-] Cannot open public input file\n"); exit(EXIT_FAILURE); }
  if (priv_f == NULL){ printf("[-] Cannot open private input file\n"); exit(EXIT_FAILURE); }

  int len = ec_size_bin(K, COMPRESSION);
  uint8_t* K_bytes = new uint8_t[len];
  uint8_t* r_bytes = new uint8_t[bn_size_bin(r)];

  std::string pub_inp_circ_str = hex_str_of_bin_array(pub_input, 512);
  std::string priv_inp_circ_str = hex_str_of_bin_array(priv_input, 512);

  ec_write_bin(K_bytes, len, K, COMPRESSION);
  bn_write_bin(r_bytes, bn_size_bin(r), r);

  fprintf(priv_f, "s_inv %s\n", uint8_to_hex_string(s_inv_bytes, SIG_BYTES_LEN).c_str());
  fprintf(priv_f, "key %s\n", priv_inp_circ_str.c_str());
  fprintf(pub_f, "(ct,y) %s\n", pub_inp_circ_str.c_str());
  fprintf(pub_f, "msg_hash %s\n", uint8_to_hex_string(msg_hash, RLC_MD_LEN).c_str());

  // Extra inputs:
  fprintf(pub_f, "K %s\n", uint8_to_hex_string(K_bytes, len).c_str());

  fclose(pub_f);
  fclose(priv_f);

  bn_free(s);
  bn_free(ord);
  bn_free(aux);
  delete[] K_bytes;
  delete[] r_bytes;
};

#endif // ECDSA_UTIL_H



