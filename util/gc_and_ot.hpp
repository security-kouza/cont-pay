/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#include "../zkGC.h"
#include <algorithm>

/*
  This file contains the implementations of functions necessary for:
  - the GC scheme
  - the OT scheme
  in the protocol
*/

// the and_gate_gen and and_gate_eva are modified versions of the ones in emp-tool
// because we do not use the io channel as in their original versions.
template<typename IO, template<typename>class OTE>
block zkGC<IO, OTE>::zkGC_and_gate_eva(const block& a, const block& b, const block* table)
{
  block out;
  MITCCRH mitccrh = (this->gc_eva)->mitccrh;

  if (isZero(&a) or isOne(&a) or isZero(&b) or isOne(&b)) {
    return _mm_and_si128(a, b);
  } else {
    if(mitccrh.key_used == KS_BATCH_N) {
      mitccrh.renew_ks((this->gc_eva)->gid);
    }

    garble_gate_eval_halfgates(a, b, &out, table, &mitccrh);
    ((this->gc_eva)->gid)++;
    return out;
  }
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_and_gate_gen(block* ptr_out, const block& a, const block& b, block* ciph, int index)
{
  block table[2];
  MITCCRH mitccrh = (this->gc_gen)->mitccrh;
  block delta = (this->gc_gen)->delta;

  if (isZero(&a) or isZero(&b)) {
    ptr_out[0] = zero_block();
    ptr_out[1] = one_block();
    return;
  } else if (isOne(&a)) {
    ptr_out[0] = (isOne(&b) ? one_block() : b);
    ptr_out[1] = (isOne(&ptr_out[0]) ? zero_block() : xorBlocks(b, delta));
    return;
  } else if (isOne(&b)) {
    ptr_out[0] = (isOne(&a) ? one_block() : a);
    ptr_out[1] = (isOne(&ptr_out[0]) ? zero_block() : xorBlocks(a, delta));
    return;
  } else {
    if(mitccrh.key_used == KS_BATCH_N) {
      mitccrh.renew_ks((this->gc_gen)->gid); // it's some helping class for sym. enc.
    }

    garble_gate_garble_halfgates(a, xorBlocks(a, delta), b, xorBlocks(b, delta),
                                 &ptr_out[0], &ptr_out[1], delta, table, &mitccrh);
    ((this->gc_gen)->gid)++;
    //io->send_block(table, 2);
    ciph[index] = table[0];
    ciph[index + 1] = table[1];
    return;
  }
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_xor_gate_gen(block* tmp, const block& a, const block& b)
{
  block delta = (this->gc_gen)->delta;

  if(isOne(&a)) {
    zkGC_not_gate_gen(tmp, b);
    return;
  } else if (isOne(&b)) {
    zkGC_not_gate_gen(tmp, a);
    return;
  } else if (isZero(&a)) {
    tmp[0] = b;
    tmp[1] = (isZero(&tmp[0]) ? one_block() : xorBlocks(b, delta));
    return;
  } else if (isZero(&b)) {
    tmp[0] = a;
    tmp[1] = xorBlocks(a, delta);
    return;
  } else {
    tmp[0] = xorBlocks(a, b);
    tmp[1] = xorBlocks(tmp[0], delta);
    return;
  }
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_not_gate_gen(block* tmp, const block& a)
{
  block delta = (this->gc_gen)->delta;

  if (isZero(&a)) {
    tmp[0] = one_block();
    tmp[1] = zero_block();
    return ;
  } else if (isOne(&a)) {
    tmp[0] = zero_block();
    tmp[1] = one_block();
    return;
  } else {
    tmp[0] = xorBlocks(a, delta);
    tmp[1] = a;
    return ;
  }
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_garble(CPCircuit zkr, block* lab0, block* lab1, block* ciph, bool* pub_input)
{

  PRG prg(&((this->gc_gen)->seed)); // we init the PRG with the seed from the GC scheme
  block* tmp = new block[2];
  block delta = (this->gc_gen)->delta;

  // we generate labels for priv_input wires
  prg.random_block(lab0, zkr.num_wires); // maybe fix a seed to send it for verification

  for (int i = 0; i < zkr.num_wires; ++i) {
    lab1[i] = xorBlocks(lab0[i], delta);
  }

  // later (seed, start_point) will be revealed for prover to do the verifcation.
  int fst_in, snd_in, out, gtype;

  for (int i = 0; i < zkr.num_gates; ++i) {
    fst_in = zkr.gates[4 * i];
    snd_in = zkr.gates[4 * i + 1];
    out = zkr.gates[4 * i + 2];
    gtype = zkr.gates[4 * i + 3];

    // If the input wires are public values
    // then the verifier must garble using zero_block()/one_block() accordingly
    block lab_fst_in, lab_snd_in;

    if (fst_in < zkr.num_public_inputs) {
      lab_fst_in = (pub_input[fst_in] == false ? zero_block() : one_block());
    } else lab_fst_in = lab0[fst_in];

    if (snd_in < zkr.num_public_inputs) {
      lab_snd_in = (pub_input[snd_in] == false ? zero_block() : one_block());
    } else lab_snd_in = lab0[snd_in];

    if (gtype == AND_GATE) {
      this->zkGC_and_gate_gen(tmp, lab_fst_in, lab_snd_in, ciph, 2 * i);
    } else if (gtype == XOR_GATE) {
      this->zkGC_xor_gate_gen(tmp, lab_fst_in, lab_snd_in);
    } else {
      assert (gtype == NOT_GATE);
      this->zkGC_not_gate_gen(tmp, lab_fst_in);
    }

    lab0[out] = tmp[0];
    lab1[out] = tmp[1];
  }

  delete[] tmp;
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_compute_circ(CPCircuit zkr, block* inputs, block* output, block* recv_ciph, bool* pub_input)
{
  block* all_wires = new block[zkr.num_wires];
  block* pub_inp_wires = new block[zkr.num_inputs];

  // set values for public input wires
  for (int i = 0; i < zkr.num_public_inputs; ++i) {
    if (pub_input[i] == true) {
      pub_inp_wires[i] = one_block();
    } else pub_inp_wires[i] = zero_block();
  }

  // combine the public inputs and the labels for private inputs
  // received from OT
  memcpy(all_wires, pub_inp_wires, zkr.num_public_inputs * sizeof(block));
  memcpy(all_wires + zkr.num_public_inputs, inputs, zkr.num_private_inputs * sizeof(block));

  block b_fst_in, b_snd_in;
  block* table = new block[2];

  for(int i = 0; i < zkr.num_gates; ++i) {
    // access to the labels using wire index
    b_fst_in = all_wires[zkr.gates[4 * i]];
    b_snd_in = all_wires[zkr.gates[4 * i + 1]];

    if(zkr.gates[4 * i + 3] == AND_GATE) {
      // set the 2 ciphertexts of the gate
      table[0] = recv_ciph[2 * i];
      table[1] = recv_ciph[2 * i + 1];

      all_wires[zkr.gates[4 * i + 2]] = this->zkGC_and_gate_eva(b_fst_in, b_snd_in, table);
    } else if (zkr.gates[4 * i + 3] == XOR_GATE) {
      all_wires[zkr.gates[4 * i + 2]] = (this->gc_eva)->xor_gate(b_fst_in, b_snd_in);
    } else {
      all_wires[zkr.gates[4 * i + 2]] = (this->gc_eva)->not_gate(b_fst_in);
    }
  }

  memcpy(output, all_wires + zkr.num_wires - zkr.num_outputs, zkr.num_outputs * sizeof(block));
  delete[] all_wires;
  delete[] table;
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::fixed_got_recv_post(block* data, const bool* r, int length)
{
  const int bsize = AES_BATCH_SIZE;
  block pad0[bsize];
  block pad1[bsize];
  TCCRH tccrh = this->ote->tccrh;

  if(this->ote->committing) { // verifier will open the rest of the ciphs later
    delete_array_null(this->ote->open_data);
    this->ote->open_data = new block[length];

    for(int i = 0; i < length; i += bsize) {
      this->io->recv_data(pad0, sizeof(block)*min(bsize, length - i));
      this->io->recv_data(pad1, sizeof(block)*min(bsize, length - i));

      if (bsize <= length - i)tccrh.H<bsize>(this->ote->tT + i, this->ote->tT + i, i);
      else tccrh.Hn(this->ote->tT + i, this->ote->tT + i, i, length - i);

      for(int j = i; j < i + bsize and j < length; ++j) {
        if (r[j]) { // originally, in mextension.h, it was ''if (r[i]) {'', which is incorr
          data[j] = xorBlocks(*(this->ote->tT + j), pad1[j - i]);
          this->ote->open_data[i] = pad0[j - i];
        } else {
          data[j] = xorBlocks(*(this->ote->tT + j), pad0[j - i]);
          this->ote->open_data[i] = pad1[j - i];;
        }
      }
    }
  } else { // there is no commitment and opening to the ciphs
    for(int i = 0; i < length; i += bsize) {
      this->io->recv_data(pad0, sizeof(block)*min(bsize, length - i));
      this->io->recv_data(pad1, sizeof(block)*min(bsize, length - i));

      if (bsize <= length - i)tccrh.H<bsize>(this->ote->tT + i, this->ote->tT + i, i);
      else tccrh.Hn(this->ote->tT + i, this->ote->tT + i, i, length - i);

      for(int j = i; j < i + bsize and j < length; ++j) {
        if (r[j])
          data[j] = xorBlocks(*(this->ote->tT + j), pad1[j - i]);
        else
          data[j] = xorBlocks(*(this->ote->tT + j), pad0[j - i]);
      }
    }

    delete[] this->ote->tT;
  }
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::fixed_recv_impl(block* data, const bool* b, int length)
{
  this->ote->recv_pre(b, length);
  this->ote->recv_check(b, length);
  fixed_got_recv_post(data, b, length);
}
