/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

extern "C" {
#include "ecdsa/ecdsa.h"
}

#include "zkGC.h"
#include "ecdsa/algebraic.hpp"


template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_prover_algebraic_PoK(bn_t secret, bn_t t, ec_t A, const ExtraInput& extra)
{
  ecdsa_prover_algebraic_PoK(this->io, secret, t, A, extra);
}

template<typename IO, template<typename>class OTE>
void zkGC<IO, OTE>::zkGC_verifier_algebraic_PoK(bn_t a, ec_t A, ec_t B, const ExtraInput& extra)
{
  ecdsa_verifier_algebraic_PoK(this->io, a, A, B, extra);
}
