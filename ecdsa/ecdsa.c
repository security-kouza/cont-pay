/*

  Copyright (c) 2020 NTT corp. - All Rights Reserved

  This file is part of opcount which is released under Software License
  Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#include "ecdsa.h"

/* We implement the proof of knowledge:

   PoK { (s,t) : B = s^{-1} H + t P  /\  ECDSA.Verif(PK, msg, (r,s)) = 1 },

   where P is the EC generator and dlog_P(H) is unknown to both parties
   (at least unknown to the prover).
   Note that r (half of the signature) is known to the verifier.
   This can be translated into a full ZK PoK when combined with the CP relation.

   The proof consists of a Schnorr sigma-protocol for knowledge of:
   (s',t) : B = s' H + t P  /\  s' D = K
   where D := (Hash(msg) + r PK) and K := (x,y) in EC is such that x = r.
   (Note that s' corresponds to s^{-1}, in the following we just write s instead of s^{-1}.)


   This is done via a sigma-protocol as follows:

   Prover                                                  Verifier
   A1 := as H + at P;  A2 = as D
   as, at <-$ Zp     --------------------------------->

   c                       c <-$ Zp
   <---------------------------------

   zs := s * c + as                   zs, zt
   zt := t * c + at    --------------------------------->   check:
   zs H + zt P  ==  c B + A1  /\
   zs D  ==  c K + A2

   * Correctness: straightforward.

   * 2-special soundness:
   Assume two accepting transcripts with same first message and different challenge:
   (A1, A2; c; zs, zt) and (A1, A2; c'; zs', zt')

   Extract:  s = (zs - zs') / (c - c')             (over Zp)
   t = (zt - zt') / (c - c')

   Note that
   s H + t P = { (zs - zs') H + (zt - zt') P } / (c - c')
   = { (c B + A1) - (c' B + A1)  } / (c - c')
   = B

   and
   s D = { (zs - zs') D / (c - c') }
   = { (c K + A2) - (c' K + A2) } / (c - c')
   = K

   * Honest-Verifier ZK:
   On input c, sample zs, zt uniformlyl from Zp and compute:
   A1 := (zs H + zt P) - c B   and    A2 := zs D - c K.

   Output the transcript (A1, A2; c; zs, zt).

*/

int ecdsa_prover1(ec_t A1, ec_t A2, bn_t as, bn_t at, ec_t H, ec_t D)
{

  bn_t ord;
  int result = RLC_OK;

  bn_null(ord);

  bn_new(ord);
  ec_curve_get_ord(ord);

  bn_rand_mod(as, ord);  // as <-$ Zp
  bn_rand_mod(at, ord);  // at <-$ Zp

  ec_mul_sim_gen(A1, at, H, as);  // A1 := as H + at P
  ec_mul(A2, D, as);              // A2 = a D

  bn_free(ord);

  return result;
};


int ecdsa_verifier1(bn_t c)
{
  bn_t ord;
  int result = RLC_OK;

  bn_null(ord);

  bn_new(ord);
  ec_curve_get_ord(ord);
  bn_rand_mod(c, ord);

  bn_free(ord);

  return result;
}

int ecdsa_prover2(bn_t zs, bn_t zt, bn_t s, bn_t t, bn_t as, bn_t at, bn_t c)
{

  bn_t ord;
  int result = RLC_OK;

  bn_null(ord);

  bn_new(ord);
  ec_curve_get_ord(ord);

  bn_mul(zs, s, c);    // compute s * c
  bn_add(zs, zs, as);  // let zs := s * c + as
  bn_mod(zs, zs, ord);

  bn_mul(zt, t, c);    // compute t * c
  bn_add(zt, zt, at);  // let zt := t * c + at
  bn_mod(zt, zt, ord);

  bn_free(ord);

  return result;
};

int ecdsa_verifier2(ec_t H, ec_t B, ec_t D, ec_t K, ec_t A1, ec_t A2, bn_t c, bn_t zs, bn_t zt)
{

  ec_t lhs, rhs;
  bn_t x, ord; // variables to get coords - for debugging purpose

  ec_null(lhs);
  bn_null(x);
  ec_null(rhs);
  bn_null(ord);


  ec_new(lhs);
  bn_new(x);
  ec_new(rhs);
  bn_new(ord);
  ec_curve_get_ord(ord);

  // First equation
  ec_mul_sim_gen(lhs, zt, H, zs);  // let lhs := zs H + zt P
  ec_mul(rhs, B, c);               // compute c B
  ec_add(rhs, rhs, A1);            // let rhs := c B + A1

  if (ec_cmp(lhs, rhs) != RLC_EQ)
    {
      return 0;  // Reject the proof
    }

  // Second equation
  ec_mul(lhs, D, zs);    // let lhs := zs D
  ec_mul(rhs, K, c);     // compute c K
  ec_add(rhs, rhs, A2);  // let rhs := c K + A2

  if (ec_cmp(lhs, rhs) != RLC_EQ)
    {
      return 0;  // Reject the proof
    }

  ec_free(lhs);
  bn_free(x);
  ec_free(rhs);
  bn_free(ord);

  return 1;  // Accept the proof
};

int ecdsa_sig(bn_t r, bn_t s, ec_t K, uint8_t* msg, bn_t d)
{

  bn_t n, k, x, e;

  int result = RLC_OK;
  int len;

  bn_null(n);
  bn_null(k);
  bn_null(x);
  bn_null(e);

  bn_new(n);
  bn_new(k);
  bn_new(x);
  bn_new(e);

  ec_curve_get_ord(n);

  do
    {
      do {
        bn_rand_mod(k, n);
        ec_mul_gen(K, k);
        ec_get_x(x, K);
        bn_mod(r, x, n);
      } while (bn_is_zero(r));

      len = RLC_MD_LEN;

      if (8 * len > bn_bits(n)) {
        len = RLC_CEIL(bn_bits(n), 8);
        bn_read_bin(e, msg, len);
        bn_rsh(e, e, 8 * len - bn_bits(n));
      } else {
        bn_read_bin(e, msg, len);
      }

      bn_mul(s, d, r);
      bn_mod(s, s, n);
      bn_add(s, s, e);
      bn_mod(s, s, n);
      bn_gcd_ext(x, k, NULL, k, n);

      if (bn_sign(k) == RLC_NEG) {
        bn_add(k, k, n);
      }

      bn_mul(s, s, k);
      bn_mod(s, s, n);
    } while (bn_is_zero(s));

  bn_free(n);
  bn_free(k);
  bn_free(x);
  bn_free(e);

  return result;
}
