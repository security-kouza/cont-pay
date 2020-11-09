/*

   Copyright (c) 2020 NTT corp. - All Rights Reserved

   This file is part of opcount which is released under Software License
   Agreement for Evaluation. See file LICENSE.pdf for full license details.

*/

#ifndef CP_CIRCUIT_H_
#define CP_CIRCUIT_H_

#include "emp-tool/execution/circuit_execution.h"
#include "emp-tool/execution/protocol_execution.h"
#include "emp-tool/utils/block.h"
#include "emp-tool/circuits/bit.h"
#include <stdio.h>

namespace emp
{
#define AND_GATE 0
#define XOR_GATE 1
#define NOT_GATE 2

class CPCircuit
{
public:
  int num_gates, num_wires;
  int num_public_inputs, num_private_inputs;
  int num_inputs, num_outputs;
  int* gates;
  block* wires;
  int tmp, tmp2;

  CPCircuit(const char* file)
  {
    FILE* f = fopen(file, "r");
    tmp2 = fscanf(f, "%d%d\n", &num_gates, &num_wires);
    tmp2 = fscanf(f, "%d%d%d\n", &num_public_inputs, &num_private_inputs, &num_outputs);
    tmp2 = fscanf(f, "\n");
    num_inputs = num_public_inputs + num_private_inputs;

    char str[10];
    gates = new int[num_gates * 4];
    wires = new block[num_wires];

    for(int i = 0; i < num_gates; ++i) {
      tmp2 = fscanf(f, "%d", &tmp);

      if (tmp == 2) {
        tmp2 = fscanf(f, "%d%d%d%d%s", &tmp, &gates[4 * i], &gates[4 * i + 1], &gates[4 * i + 2], str);

        if (str[0] == 'A')      gates[4 * i + 3] = AND_GATE;
        else if (str[0] == 'X') gates[4 * i + 3] = XOR_GATE;
      } else if (tmp == 1) { // the gate takes 1 input
        tmp2 = fscanf(f, "%d%d%d%s", &tmp, &gates[4 * i], &gates[4 * i + 2], str);
        gates[4 * i + 3] = NOT_GATE;
      }
    }

    fclose(f);
  }

  CPCircuit(const CPCircuit& zkr)
  {
    num_gates = zkr.num_gates;
    num_wires = zkr.num_wires;

    num_public_inputs  = zkr.num_public_inputs;
    num_private_inputs = zkr.num_private_inputs;
    num_inputs         = num_public_inputs + num_private_inputs;
    num_outputs        = zkr.num_outputs;

    gates = new int[num_gates * 4];
    wires = new block[num_wires];
    memcpy(gates, zkr.gates, num_gates * 4 * sizeof(int));
    memcpy(wires, zkr.wires, num_wires * sizeof(block));
  }
  ~CPCircuit()
  {
    delete[] gates;
    delete[] wires;
  }
  int table_size() const
  {
    return num_gates * 4;
  }

  void compute(block* out, block* public_in, block* private_in)
  {
    memcpy(wires, public_in, num_public_inputs * sizeof(block));
    memcpy(wires + num_public_inputs, private_in, num_private_inputs * sizeof(block));

    for(int i = 0; i < num_gates; ++i) {
      switch(gates[4 * i + 3]) {
      case AND_GATE:
        wires[gates[4 * i + 2]] = CircuitExecution::circ_exec->and_gate(wires[gates[4 * i]], wires[gates[4 * i + 1]]);

      case XOR_GATE:
        wires[gates[4 * i + 2]] = CircuitExecution::circ_exec->xor_gate(wires[gates[4 * i]], wires[gates[4 * i + 1]]);

      case NOT_GATE:
        wires[gates[4 * i + 2]] = CircuitExecution::circ_exec->not_gate(wires[gates[4 * i]]);
      }
    }

    memcpy(out, &wires[num_wires - num_outputs], num_outputs * sizeof(block));
  }
};
}
#endif // CP_CIRCUIT_H_
