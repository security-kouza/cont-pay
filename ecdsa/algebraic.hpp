/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#include "./ecdsa_util.h"

void ecdsa_prover_algebraic_PoK(NetIO* netio, bn_t s_inv, bn_t t, ec_t A, const ExtraInput& extra)
{

  // Parse the extra input

  ec_t PK;  ec_init(PK);
  ec_t K;   ec_init(K);
  bn_t r;   bn_init(r);
  bn_t sk;  bn_init(sk);
  uint8_t msg_hash[RLC_MD_LEN];

  ec_copy(PK, extra.ec_list[0]);
  ec_copy(K, extra.ec_list[1]);
  ec_get_x(r, K);
  bn_copy(sk, extra.bn_list[0]);

  for (int i = 0; i < RLC_MD_LEN; ++i){ msg_hash[i] = extra.bytes_list[i]; }

  // Variables for the algebraic proof

  ec_t A1, A2;     // Schnorr's first message
  bn_t as, at;     // Schnorr's first message's dlog
  bn_t q;          // dlog for Pedersen commitment of challenge
  ec_t Q;          // the public point corresponding to q
  ec_t recv_COM;   // commitment of the challenge from the verifier
  ec_t ckc;        // aux var to check COM
  bn_t recv_r_COM; // the randomness for commitment, received from V

  bn_t recv_c; // Schnorr's challenge
  bn_t z, zh ; // Schnorr's last message

  ec_t D;

  int len = RLC_MD_LEN;
  bn_t e;

  bn_t ord, aux;  // curve order and aux variable to compute the gcd (invert s)

  int transmitted;

  ec_init(A1);
  ec_init(A2);

  bn_init(as);
  bn_init(at);
  bn_init(q);

  ec_init(Q);
  ec_init(recv_COM);
  ec_init(ckc);
  bn_init(recv_r_COM);

  bn_init(recv_c);
  bn_init(z);
  bn_init(zh);

  ec_init(D);
  bn_init(e);

  bn_init(ord);
  bn_init(aux);

  ec_curve_get_ord(ord);

  /* Adjust the message (done by both parties) */

  adjustMsg(e, len, ord, msg_hash);

  ec_mul_sim_gen(D, e, PK, r);

  bn_rand_mod(q, ord);
  ec_mul_gen(Q, q);
  netio->send_data(Q, sizeof(ec_t));
  print_size_of_transmitted_dat("public point Q for comm", sizeof(ec_t));

  // receive the comitment from verifier

  netio->recv_data(recv_COM, sizeof(ec_t));

  /* We start the proof (this should be done by exchanging messages) */

  assert(ecdsa_prover1(A1, A2, as, at, A, D) == RLC_OK);

  netio->send_data(A1, sizeof(ec_t));
  print_size_of_transmitted_dat("public point A1", sizeof(ec_t));
  netio->send_data(A2, sizeof(ec_t));
  print_size_of_transmitted_dat("public point A2", sizeof(ec_t));

  // receive the challenge from verifier and check the commitment

  recv_bn(netio, recv_c);
  recv_bn(netio, recv_r_COM);
  printf("[+] Checking commitment ... \n");
  ec_mul_sim_gen(ckc, recv_r_COM, Q, recv_c);
  assert(ec_cmp(ckc, recv_COM) == RLC_EQ);

  // compute the response

  assert(ecdsa_prover2(z, zh, s_inv, t, as, at, recv_c) == RLC_OK);

  // send the response to the verifier

  transmitted = send_bn(netio, z);
  print_size_of_transmitted_dat("response z", transmitted);

  transmitted = send_bn(netio, zh);
  print_size_of_transmitted_dat("response zh", transmitted);

  // reveal the dlog Q to the verifier, to make it a PoK

  transmitted = send_bn(netio, q);
  print_size_of_transmitted_dat("dlog of Q", transmitted);

  ec_free(A1);
  ec_free(A2);
  bn_free(as);
  bn_free(at);
  bn_free(recv_c);
  bn_free(z);
  bn_free(zh);

  ec_free(D);
  bn_free(e);

  bn_free(ord);
  bn_free(aux);
};


void ecdsa_verifier_algebraic_PoK(NetIO* netio, bn_t a, ec_t A, ec_t B, const ExtraInput& extra)
{

  // Parse the extra input

  ec_t PK;  ec_init(PK);
  ec_t K;   ec_init(K);
  uint8_t msg_hash[RLC_MD_LEN];

  ec_copy(PK, extra.ec_list[0]);
  ec_copy(K, extra.ec_list[1]);

  for (int i = 0; i < RLC_MD_LEN; ++i){ msg_hash[i] = extra.bytes_list[i]; }

  // Variables for the algebraic proof

  ec_t D;
  ec_t recv_A1, recv_A2; // randomness receved from prover

  bn_t chal;       // Schnorr's challenge
  bn_t chal_r_com; // randomness to commit challenge
  ec_t recv_Q;     // public point from prover to commit to the challenge
  bn_t recv_q;     // the dlog of Q, receive from P
  ec_t ckc;        // aux to check recv_Q = recv_q P
  ec_t COM;        //the commitment to the challenge

  bn_t z, zh; // Schnorr's responses from prover
  bn_t ord;
  int accept = 1;

  int len = RLC_MD_LEN;
  bn_t e, r;

  int transmitted;

  ec_init(D);

  ec_init(recv_A1);
  ec_init(recv_A2);

  bn_init(chal);
  bn_init(chal_r_com);
  ec_init(recv_Q);
  bn_init(recv_q);
  ec_init(ckc);
  ec_init(COM);

  bn_init(z);
  bn_init(zh);
  bn_init(ord);
  bn_init(e);
  bn_init(r);

  ec_curve_get_ord(ord);

  /* Adjust the message (done by both parties) */

  adjustMsg(e, len, ord, msg_hash);

  ec_get_x(r, K);
  ec_mul_sim_gen(D, e, PK, r);

  // create and commit to the challenge

  assert(ecdsa_verifier1(chal) == RLC_OK);

  // receive the base Q from prover

  netio->recv_data(recv_Q, sizeof(ec_t));

  // commit by Pedersen

  bn_rand_mod(r, ord);
  ec_mul_sim_gen(COM, r, recv_Q, chal); // COM = chal Q + r P
  netio->send_data(COM, sizeof(ec_t));

  print_size_of_transmitted_dat("commitment of challenge", sizeof(ec_t));


  // recev 2 elements A1, A2 from prover

  (netio)->recv_data(recv_A1, sizeof(ec_t));
  (netio)->recv_data(recv_A2, sizeof(ec_t));

  // send the challenge

  transmitted = send_bn(netio, chal);
  print_size_of_transmitted_dat("challenge", transmitted);
  transmitted = send_bn(netio, r);
  print_size_of_transmitted_dat("randomness for commitment", transmitted);

  recv_bn(netio, z);
  recv_bn(netio, zh);
  recv_bn(netio, recv_q);

  ec_mul_gen(ckc, recv_q);
  accept = ecdsa_verifier2(A, B, D, K, recv_A1, recv_A2, chal, z, zh)
           && (ec_cmp(ckc, recv_Q) == RLC_EQ);
  printf("[+] accept:? %d\n", accept);

  if (accept) {
    printf ("[+] ECDSA test succeeded\n");
  } else {
    printf ("[-] ECDSA test failed\n");
  }

  ec_free(D);

  ec_free(recv_A1);
  ec_free(recv_A1);

  bn_free(chal);
  bn_free(chal_r_com)
  bn_free(recv_q);
  ec_free(recv_Q);
  ec_free(ckc);

  bn_free(z);
  bn_free(zh);
  bn_free(ord);
  bn_free(e);
  bn_free(r);
};
