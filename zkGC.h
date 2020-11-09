/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#ifndef ZKGC_H__
#define ZKGC_H__

extern "C"
{
#include "relic.h"
}

#include "external/emp-tool.h"
#include "external/emp-ot.h"
#include "external/emp-sh2pc.h"
#include "util/cp_circuit.h"
#include "util/util.h"
#include "extra_input.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <omp.h> // compile with flag -fopenmp, must go with -pthread

using namespace std;
using namespace std::chrono; // for timing
using namespace emp;

enum Parties {  VERIFIER = 1, PROVER = 2  };

template<typename IO, template<typename>class OTE>

class zkGC
{

public:
  // these pointers are for using the classes of EMP toolkit
  IO* io = nullptr;                  // IO channel
  OTE<IO>* ote = nullptr;            // ot-extension from class OTE
  HalfGateGen<IO>* gc_gen = nullptr; // Garbling scheme - generation
  HalfGateEva<IO>* gc_eva = nullptr; // Garbling scheme - evaluation
  Commitment* c = nullptr;

  // constructor of zkGC

  zkGC(Parties party, IO* io, Commitment* c, OTE<IO>* ote)
  {
    this->io = io;
    this->ote = ote; // both parties use this OTE
    this->c = c;

    if      (party == VERIFIER) { this->gc_gen = new HalfGateGen<IO>(this->io); }
    else if (party == PROVER)   { this->gc_eva = new HalfGateEva<IO>(this->io); }
  };

  ~zkGC()
  {
    delete ote;
    delete gc_eva;
    delete gc_gen;
  };

  // the following functions relate to GC scheme and OT scheme
  // their implementations are in util/gc_and_ot.hpp

  block zkGC_and_gate_eva(const block& a, const block& b, const block* table);

  void zkGC_and_gate_gen(block* ptr_out, const block& a, const block& b, block* ciph, int index);

  void zkGC_xor_gate_gen(block* tmp, const block& a, const block& b);

  void zkGC_not_gate_gen(block* tmp, const block& a);

  void zkGC_garble(CPCircuit zkr, block* lab0, block* lab1, block* ciph, bool* pub_input);

  void zkGC_compute_circ(CPCircuit zkr, block* inputs, block* output, block* recv_ciph, bool* pub_input);

  // When received ciphs from verifier, the prover can only decrypt one of them
  // and stores the remaining ciph in open_data[], which can be decrypted later
  // when the verifier calls open()
  // The function got_recv_post() doesn't work in the case of commited OT
  // the function below is its modified version
  void fixed_got_recv_post(block* data, const bool* r, int length);

  // the modifier version of recv_impl() in the library, calling fixed_got_recv_post()
  void fixed_recv_impl(block* data, const bool* b, int length);

  void zkGC_prover(CPCircuit zkr, bn_t secret, bool* pub_input, bool* priv_input, const ExtraInput& extra)
  {

    ec_t A;
    ec_init(A);

    io_clock_start();
    this->io->recv_data(A, sizeof(ec_t));
    io_clock_stop("[***] Received A");

    int secret_length = zkr.num_outputs/8; // In bytes
    bool* secret_bool = new bool[zkr.num_outputs];

    assert (bn_size_bin(secret) == secret_length);

    bool_of_bn(secret_bool, secret, secret_length);
    block* recv_ciph = new block[zkr.num_gates * 2]; // the recv data of prover

    io_clock_start();
    (this->io)->sync();
    (this->io)->recv_block(recv_ciph, zkr.num_gates * 2); // recv the ciphs from verifier
    (this->io)->flush();
    io_clock_stop("[***] received GC ciphs");

    // Perform OT to get the private input labels

    bool* all_input = new bool[zkr.num_inputs];
    block* recv_priv_inp_labs = new block[zkr.num_private_inputs];


    for (int i = 0; i < zkr.num_public_inputs; ++i) {
      all_input[i] = pub_input[i];
    }

    for (int i = 0; i < zkr.num_private_inputs; ++i) {
      all_input[zkr.num_public_inputs + i] = priv_input[i];
    }

    // do normal MOTExtension

    arithmetic_clock_start();

    fixed_recv_impl(recv_priv_inp_labs, priv_input, zkr.num_private_inputs);
    (this->io)->flush();
    arithmetic_clock_stop("fixex_recv_impl");

    /*  The prover evaluates the garbled circuit  */

    arithmetic_clock_start();

    block* res = new block[zkr.num_outputs]; // contain the result of evaluation

    if (this->gc_eva == nullptr) {
      printf("%s\n", "[-] Invalid gc_eva");
      return;
    }

    this->zkGC_compute_circ(zkr, recv_priv_inp_labs, res, recv_ciph, pub_input);

    arithmetic_clock_stop("[***] GC eval");

    cout << endl;

    /* The prover will not commit to the output label, they will produce \hat{B} instead  */

    io_clock_start();

    bn_t ord;
    bn_init(ord);
    ec_curve_get_ord(ord);

    bn_t* zs = new bn_t[zkr.num_outputs];
    bn_init_vector(zs, zkr.num_outputs);

    int len = bn_size_bin(ord);
    int n_blocks = len / 16;

    // The prover decrypts the structured output labels, which are field elements,
    // using the labels from the GC evaluation
    // IV = loop counter
    // key = blocks from res[]

    int out_ciph_len = len + 16;

    uint8_t* zs_cts = new uint8_t[2 * zkr.num_outputs * out_ciph_len];

    // receive the ciphertexts from the verifier
    (this->io)->recv_data(zs_cts, 2 * zkr.num_outputs * out_ciph_len);

    io_clock_stop("[***] received zs_cts");

    arithmetic_clock_start();

    #pragma omp parallel default(none) shared(zkr, secret_bool, out_ciph_len, zs, zs_cts, n_blocks, len, res) num_threads(4)
    {
      #pragma omp for schedule(guided, 2)

      for (int i = 0; i < zkr.num_outputs; ++i) {

        uint8_t* bytes = new uint8_t[len];
        block* plaintext = new block[n_blocks];

        int cts_idx;

        if (secret_bool[i])  cts_idx = out_ciph_len * (2 * i + 1);
        else                 cts_idx = out_ciph_len * (2 * i);

        simpleOT_blk_aes_cbc_dec(plaintext, res[i], &(zs_cts[cts_idx]), n_blocks, i);

        for (int j = 0; j < n_blocks; ++j) {
          blockToUint8(&(bytes[16 * j]), plaintext[j]);
        }

        bn_read_bin(zs[i], bytes, len);
      }
    };
    arithmetic_clock_stop("[***] decrypt zs_cts");

    // Compute \hat{B}

    algebraic_clock_start();
    bn_t hat_t;
    bn_init(hat_t);
    sample_Zp(hat_t);

    bn_t aux;
    bn_init(aux);
    bn_add_repeated_squaring_outLink(aux, zs, zkr.num_outputs);
    bn_mod(aux, aux, ord); // reduce modulo to avoid "insufficient buffer"

    ec_t hat_B;
    ec_init(hat_B);
    ec_mul_sim_gen(hat_B, hat_t, A, aux);
    ec_norm(hat_B, hat_B); // To avoid side channel leakage

    algebraic_clock_stop("[***] compute hat_B");

    io_clock_start();

    (this->io)->send_data(hat_B, sizeof(ec_t));
    print_size_of_transmitted_dat("sending hat_B", sizeof(ec_t));

    bn_t DELTA;
    bn_init(DELTA);
    recv_bn(this->io, DELTA);

    io_clock_stop("transmitted hatB and DELTA back");

    algebraic_clock_start();

    bn_t DELTA_inv;
    bn_init(DELTA_inv);
    bn_gcd_ext(aux, DELTA_inv, NULL, DELTA, ord);

    if (bn_sign(DELTA_inv) == RLC_NEG) {
      bn_add(DELTA_inv, DELTA_inv, ord);
    }

    bn_mul(aux, hat_t, DELTA_inv); // aux here represents t = hat_t / DELTA
    bn_mod(aux, aux, ord);

    algebraic_clock_stop("compute B");
    cout << endl;

    // The prover receives the secrets of the garbled circuit and verifies them

    io_clock_start();

    block* recv_delta = new block;
    block* recv_seed = new block;
    block* recv_start_pnt = new block;

    (this->io)->recv_block(recv_delta, 1);
    (this->io)->recv_block(recv_seed, 1);
    (this->io)->recv_block(recv_start_pnt, 1);

    block* verif_lab0 = new block[zkr.num_wires];
    block* verif_lab1 = new block[zkr.num_wires];
    block* verif_ciph = new block[zkr.num_gates * 2];

    io_clock_stop("receive secrets of GC");

    // Let the prover simulate a party similar to the verifier
    // overwrite the seed and delta of that party with recv_seed and recv_delta

    arithmetic_clock_start();

    zkGC<IO, OTE>* verif_zk = new zkGC<IO, OTE>(VERIFIER, this->io, this->c, this->ote);

    (verif_zk->gc_gen) -> seed = *recv_seed;
    (verif_zk->gc_gen) -> delta = *recv_delta;
    (verif_zk->gc_gen) -> start_point = *recv_start_pnt;
    ((verif_zk->gc_gen) -> mitccrh).setS((verif_zk->gc_gen) -> start_point);

    // Re-garble

    for (int i = 0; i < zkr.num_wires; ++i) {
      verif_lab1[i] = one_block();
      verif_lab0[i] = zero_block();
    }

    (verif_zk)->zkGC_garble(zkr, verif_lab0, verif_lab1, verif_ciph, pub_input);

    if (!(block_cmp(verif_ciph, recv_ciph, zkr.num_gates * 2))) {
      printf("%s\n", "[-] Verification of GC failed");
      return;

    } else {
      printf("[+] GC verified successfully\n");
    }

    arithmetic_clock_stop("[***] GC verify");

    //The prover receives the open info for the GC

    arithmetic_clock_start();
    block* open_labs_k = new block[zkr.num_private_inputs];
    block tmp;

    this->ote->open(open_labs_k, priv_input, zkr.num_private_inputs);

    for (int i = 0; i < zkr.num_private_inputs; ++i) {
      tmp = xorBlocks(open_labs_k[i], recv_priv_inp_labs[i]);

      if (block_cmp(&tmp, recv_delta, 1)) { // if temp != delta received from verifier
        printf("[-] Invalid pair of labels ...\n");
        return;
      }
    }

    printf("[+] The verifier computed ciphs correctly during OT:? OK\n");

    arithmetic_clock_stop("[***] OT verifiy");

    // If the GC is verified correctly, do the algebraic proof

    algebraic_clock_start();
    zkGC_prover_algebraic_PoK(secret, aux, A, extra);
    algebraic_clock_stop("[***] alg exec");
    cout << endl;

    cout << "[+] Prover finished" << endl << endl;

    print_total_size();
    cout << endl;

    printf("arithmetic time: %ld us\n", arithmetic_time);
    printf("algebraic time: %ld us\n", algebraic_time);
    printf("io time: %ld us\n", io_time);

    cout << endl;

  }

  void zkGC_verifier(CPCircuit zkr, bool* pub_input, const ExtraInput& extra)
  {

    int transmitted;

    bn_t a;
    ec_t A;
    bn_init(a);
    ec_init(A);

    sample_Zp(a);
    ec_mul_gen(A, a);

    // Send H, the common base for all OT transfers

    io_clock_start();

    this->io->send_data(A, sizeof(ec_t));
    print_size_of_transmitted_dat("public point A", sizeof(ec_t));

    io_clock_stop("[***] Sent A");
    cout << endl;

    // garble the circuit

    arithmetic_clock_start();

    block* lab0 = new block[zkr.num_wires];   // array of 0-labels (one for each wire)
    block* lab1 = new block[zkr.num_wires];   // array of 1-labels (one for each wire)
    block* ciph = new block[zkr.num_gates * 2]; // an array of gates' ciphertexts, 2 for each

    for (int i = 0; i < zkr.num_public_inputs; ++i) {
      lab1[i] = one_block();
      lab0[i] = zero_block();
    }

    // all labels are now generated, for all PRIVATE_wires in the circ

    this->zkGC_garble(zkr, lab0, lab1, ciph, pub_input);

    arithmetic_clock_stop("[***] zkGC_garble");

    io_clock_start();

    (this->io)->sync();
    (this->io)->send_block(ciph, zkr.num_gates * 2); // send the ciphs to prover
    (this->io)->flush();
    print_size_of_transmitted_dat("ciph for GC", zkr.num_gates * 2 * sizeof(block));

    io_clock_stop("sent GC");

    arithmetic_clock_start();

    // The verifier will send the priv_input labels through OT

    block* lab0_priv_inp = new block[zkr.num_private_inputs];
    block* lab1_priv_inp = new block[zkr.num_private_inputs];

    for (int i = 0; i < zkr.num_private_inputs; ++i) {
      lab0_priv_inp[i] = lab0[zkr.num_public_inputs + i]; // the 0-labels are generated during GC
      lab1_priv_inp[i] = lab1[zkr.num_public_inputs + i]; // the 1-labels are generated during GC
    }

    // send labels for private input to the prover

    (this->ote)->send(lab0_priv_inp, lab1_priv_inp, zkr.num_private_inputs);

    this->io->flush();

    // cf emp-ot/mextension.h

    unsigned long sz_dat_OT = 0;
    const int bsize = AES_BATCH_SIZE;

    for (int i = 0; i < zkr.num_private_inputs; i += bsize) {
      sz_dat_OT += sizeof(block) * min(bsize, zkr.num_private_inputs - i) * 2;
    }

    print_size_of_transmitted_dat("MOTE for priv_inp", sz_dat_OT);

    arithmetic_clock_stop("[***] MOTE_send");
    cout << endl;

    algebraic_clock_start();
    bn_t ord;
    bn_init(ord);
    ec_curve_get_ord(ord);

    bn_t* zs = new bn_t[2 * zkr.num_outputs];
    bn_init_vector(zs, 2 * zkr.num_outputs);

    bn_t DELTA;
    bn_init(DELTA);
    sample_Zp(DELTA);

    // sample a pair of field elements (z0, z1) for each output wire

    sample_Zp_out_labels(zkr, zs, DELTA, ord);

    algebraic_clock_stop("[***] sampling zs");

    arithmetic_clock_start();

    int len = bn_size_bin(ord);
    int n_blocks = len / 16;

    // The verifier encrypts the structured output labels, which are field elements,
    // using the output's labels from GC generation
    // IV = loop counter
    // key to encrypt z0 = the 0-label
    // key to encrypt z1 = the 1-label

    int out_ciph_len = len + 16;
    uint8_t* zs_cts = new uint8_t[2 * zkr.num_outputs * out_ciph_len];

    #pragma omp parallel default(none) shared(zs, zs_cts, len, n_blocks, out_ciph_len, zkr, lab0, lab1) num_threads(N_THREADS)
    {
      #pragma omp for schedule(guided, 2)

      for (int i = 0; i < 2 * zkr.num_outputs; ++i) {

        uint8_t* bytes = new uint8_t[len];
        block* plaintext = new block[n_blocks];
        int lbl_idx;

        bn_write_bin(bytes, len, zs[i]);

        for (int j = 0; j < n_blocks; ++j) {
          memcpy(&(plaintext[j]), bytes + 16 * j, 16);
        }

        // get the correct output label to encrypt zi

        lbl_idx = zkr.num_wires - zkr.num_outputs + i / 2;

        if (i % 2) {
          simpleOT_blk_aes_cbc_enc(&(zs_cts[out_ciph_len * i]), lab1[lbl_idx], plaintext, n_blocks, i / 2);
        } else {
          simpleOT_blk_aes_cbc_enc(&(zs_cts[out_ciph_len * i]), lab0[lbl_idx], plaintext, n_blocks, i / 2);
        }
      }
    };

    arithmetic_clock_stop("[***] encrypt zs");

    // send all pairs of ciphertexts of (z0, z1) to the prover

    io_clock_start();
    (this->io)->send_data(zs_cts, 2 * zkr.num_outputs * out_ciph_len);
    print_size_of_transmitted_dat("sent field elements zs encrypted", 2 * zkr.num_outputs * out_ciph_len);

    // Receive \hat{B}

    ec_t hat_B;
    ec_init(hat_B);

    (this->io)->recv_data(hat_B, sizeof(ec_t));

    transmitted = send_bn(this->io, DELTA);
    print_size_of_transmitted_dat("DELTA", transmitted);

    io_clock_stop("sent field elements and received DELTA");

    algebraic_clock_start();

    // Computing B

    bn_t* z0s = new bn_t[zkr.num_outputs];
    bn_init_vector(z0s, zkr.num_outputs);

    for (int i = 0; i < zkr.num_outputs; i++) {
      bn_copy(z0s[i], zs[2 * i]);
    }

    bn_t aux;
    bn_init(aux);
    bn_add_repeated_squaring_outLink(aux, z0s, zkr.num_outputs);
    bn_mod(aux, aux, ord);

    ec_t B;
    ec_init(B);
    ec_t ec_aux;
    ec_init(ec_aux);
    ec_mul(ec_aux, A, aux);

    bn_t DELTA_inv;
    bn_init(DELTA_inv);
    bn_gcd_ext(aux, DELTA_inv, NULL, DELTA, ord);

    if (bn_sign(DELTA_inv) == RLC_NEG) {
      bn_add(DELTA_inv, DELTA_inv, ord);
    }

    ec_sub(B, hat_B, ec_aux);
    ec_mul(B, B, DELTA_inv);

    algebraic_clock_stop("[***] compute B");

    // The verifier sends delta, so that the prover verifies the circuit
    // we send both the seed and the delta to the prover for verification
    // Also, the prover will need gc_gen -> start_point, so as to init the
    // sym. encr scheme

    io_clock_start();

    (this->io)->send_block(&(this->gc_gen)->delta, 1);
    print_size_of_transmitted_dat("delta in GC gen", sizeof(block));

    (this->io)->send_block(&(this->gc_gen)->seed, 1);
    print_size_of_transmitted_dat("seed in GC gen", sizeof(block));

    (this->io)->send_block(&(this->gc_gen)->start_point, 1);
    print_size_of_transmitted_dat("start_point in GC gen", sizeof(block));

    cout << endl;

    // If the prover is satisfied with the garbling, it will decommit to the result
    block* dumm = new block[1];

    // because the simulation of GC Gen by Prover uses the same io
    // channel, and it outputs some garbage during the generation
    // I don't know why flush seems not working properly here
    (this->io)->recv_block(dumm, 1);

    io_clock_stop("sent info to verify GC");

    /* The verifier opens the committed ciphertexts during OT */

    arithmetic_clock_start();

    (this->ote)->open();

    arithmetic_clock_stop("[***] last step of zk-fr-gc");
    cout << endl;

    algebraic_clock_start();

    zkGC_verifier_algebraic_PoK(a, A, B, extra);

    algebraic_clock_stop("[***] verifier's alg exec");

    cout << "[+] Verifier finished" << endl << endl;

    print_total_size();
    cout << endl;

    printf("arithmetic time: %ld us\n", arithmetic_time);
    printf("algebraic time: %ld us\n", algebraic_time);
    printf("io time: %ld us\n", io_time);

    cout << endl;

    ec_free(hat_B);
    bn_free(DELTA);

    for (int i = 0; i < zkr.num_outputs; i++) {
      bn_free(z0s[i]);
    }

    bn_free(aux);
    bn_free(ord);
    ec_free(B);
    ec_free(ec_aux);
    bn_free(DELTA_inv);
    bn_free(a);
    ec_free(A);
  }

private:
  // the following 2 functions are called by zkGC_prover and zkGC_verifier
  // to execute the algebraic PoK in the zkGC protocol
  // their implementations are in zkGC_algebraic.hpp

  void zkGC_prover_algebraic_PoK(bn_t secret, bn_t t, ec_t A, const ExtraInput& extra);
  void zkGC_verifier_algebraic_PoK(bn_t a, ec_t A, ec_t B, const ExtraInput& extra);
};

#endif // ZKGC_H__
