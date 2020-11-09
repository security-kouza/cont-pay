/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

struct ExtraInput {
  int bn_len;
  int ec_len;
  int bytes_len;
  bn_t *bn_list;        // 1 element for the secret (only for prover)
  ec_t *ec_list;        // 2 elements (PK, K)
  uint8_t *bytes_list;  // message
};
