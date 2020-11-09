/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#ifndef ECDSA_H
#define ECDSA_H
#include <stdio.h>
#include <assert.h>
#include "relic.h"

int ecdsa_prover1(ec_t A1, ec_t A2, bn_t a, bn_t ah, ec_t H, ec_t D);

int ecdsa_verifier1(bn_t c);

int ecdsa_prover2(bn_t z, bn_t zh, bn_t s, bn_t t, bn_t a, bn_t ah, bn_t c);

int ecdsa_verifier2(ec_t H, ec_t B, ec_t D, ec_t K, ec_t A1, ec_t A2, bn_t c, bn_t z, bn_t zh);

int ecdsa_sig(bn_t r, bn_t s, ec_t K, uint8_t* msg, bn_t d);

#endif  // ECDSA_H
