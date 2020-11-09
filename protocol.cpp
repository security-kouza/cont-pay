/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#include "zkGC.h"
#include "zkGC_algebraic.hpp"
#include "util/gc_and_ot.hpp"
#include "ecdsa/ecdsa_util.h"

#include <iostream>

using namespace std;
using namespace emp;

template<template<typename>class OTE>
void prover(NetIO* netio, Commitment* c, CPCircuit zkr, bool* pub_input, bn_t secret, bool* priv_input, ExtraInput extra)
{
  OTE<NetIO>* ote = new OTE<NetIO>(netio, true);  // 'true' for commited OTE
  zkGC<NetIO, OTE>* zk = new zkGC<NetIO, OTE>(static_cast<Parties>(PROVER), netio, c, ote);

  auto start = std::chrono::high_resolution_clock::now();

  zk->zkGC_prover(zkr, secret, pub_input, priv_input, extra);

  auto stop = std::chrono::high_resolution_clock::now();
  auto interval = std::chrono::duration_cast<microseconds>(stop - start);
  printf("[**] prover_exec: %ld us\n", interval.count());

  delete zk;
  ec_free(PK);
}

template<template<typename>class OTE>
void verifier(NetIO* netio, Commitment* c, CPCircuit zkr, bool* pub_input, ExtraInput extra)
{
  OTE<NetIO>* ote = new OTE<NetIO>(netio, true);
  zkGC<NetIO, OTE>* zk = new zkGC<NetIO, OTE>(static_cast<Parties>(VERIFIER), netio, c, ote);

  auto start = std::chrono::high_resolution_clock::now();

  zk->zkGC_verifier(zkr, pub_input, extra);

  auto stop = std::chrono::high_resolution_clock::now();
  auto interval = std::chrono::duration_cast<microseconds>(stop - start);
  printf("[**] verifier_exec: %ld us\n", interval.count());

  delete zk;
  ec_free(PK);
}

int main(int argc, char** argv)
{
  // Init relic:

  if (core_init() != RLC_OK) {
    core_clean();
    return 1;
  }

  if (pc_param_set_any() != RLC_OK) {
    core_clean();
    return 1;
  }

  string KEYGEN = "keygen";
  string SETUP = "setup";
  string PROVER_STR = "prover";
  string VERIFIER_STR = "verifier";

  string PKFILE = "data/public.key";
  string SKFILE = "data/private.key";

  string MSGFILE = "data/msg.txt";
  string CIRCUIT = "data/XOR_SHA.txt";
  string INPFILE = "data/input.txt";


  if (strcmp(argv[1], KEYGEN.c_str()) == 0) {
    keygen();
    return 0;
  };

  if (strcmp(argv[1], SETUP.c_str()) == 0){
    setup();
    return 0;
  }

  int party, port;
  char *verifier_ip = nullptr;

  if (strcmp(argv[1], PROVER_STR.c_str()) == 0)
    {
      party = PROVER;
      verifier_ip = argv[2];
      port = atoi(argv[3]);
    }
  else if (strcmp(argv[1], VERIFIER_STR.c_str()) == 0)
    {
      party = VERIFIER;
      port = atoi(argv[2]);  // No IP since the verifier acks as the server
  }
  else
    {
      error("Unknown party, please choose between prover/verifier\n");
    }

  // Parse the circuit's information

  CPCircuit zkr(CIRCUIT.c_str());

  printf("[+] num_wires: %d\n[+] num_gates: %d\n", zkr.num_wires, zkr.num_gates);
  printf("[+] public_inputs: %d\n[+] private_inputs: %d\n", zkr.num_public_inputs, zkr.num_private_inputs);
  printf("[+] outputs: %d\n", zkr.num_outputs);
  printf("Circuit parsed!\n");

  NetIO* io = new NetIO(verifier_ip, port);

  Commitment* c = new Commitment();

  // Start the protocol execution

  auto start = std::chrono::high_resolution_clock::now();

  ExtraInput extra = init_extra_input();

  bool* pub_input = new bool[zkr.num_public_inputs];
  ecdsa_read_pub_instance(pub_input, extra);

  if (party == PROVER)
    {
      bool* priv_input = new bool[zkr.num_private_inputs];
      bn_t secret;
      bn_init(secret);

      ecdsa_read_priv_instance(secret, priv_input, extra);
      prover<MOTExtension>(io, c, zkr, pub_input, secret, priv_input, extra);

      bn_free(secret);
    }

  if (party == VERIFIER)
    {
      verifier<MOTExtension>(io, c, zkr, pub_input, extra);
    }

  auto stop = std::chrono::high_resolution_clock::now();
  auto interval = std::chrono::duration_cast<microseconds>(stop - start);

  printf("Total time (in microseconds): ");

  cout <<  interval.count() <<  endl;
};
