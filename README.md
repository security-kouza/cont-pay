# zkCP prototype

Zero-Knowledge Contingent Payment (zkCP) is a propotype tool associated to the paper
[*"WI is Almost Enough: Contingent (Service) Payment All Over Again"*](https://dl.acm.org/doi/10.1145/3372297.3417888).


## Installation

*0*. Install required packages such as:
    cmake, git, build-essential, libssl-dev, libgmp-dev, libboost-all-dev

*1*. Install the [EMP Toolkit](https://github.com/emp-toolkit/emp-readme).
     You can install it by running `make get-emp-toolkit`.

*2*. Install the [Relic Toolkit](https://github.com/relic-toolkit).
     You can install it by running `make get-relic`.

*3*. After cloning our repository, run `make`.

Our code is compatible with the libraries at the date of May 1st 2020.
If you have installed them on your own and have any problems compiling our tool,
you can try to get a version of the libraries close to this date.

We have verified our tool using verion 9.3.0 of gcc and g++, running on Ubuntu 20.04.


## What is this tool for?

Our tool provides support for proving in ZK a statement like:

<!-- Equation computed with https://jsfiddle.net/8ndx694g -->
<!-- \text{PoK}\{(x,t):\mathit{com}=f(x)\,A+t\,P\} -->
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://render.githubusercontent.com/render/math?math=%5Ctext%7BPoK%7D%5C%7B(x%2Ct)%3A%5Ctext%7Bcom%7D%3Df(x)%5C%2CA%2Bt%5C%2CP%5C%7D">,

where
<img src="https://render.githubusercontent.com/render/math?math=P">
is the generator of a public elliptic curve,
<img src="https://render.githubusercontent.com/render/math?math=A">
is a uniformly chosen group element from the curve (with unknown dlog with respect to
<img src="https://render.githubusercontent.com/render/math?math=P">
) and
<img src="https://render.githubusercontent.com/render/math?math=%5Ctext%7Bcom%7D">
is a group element acting as a Pedersen commitment to the secret being sold.
Example of how this can be useful for Contingent Payment:

*1*. The seller will encrypt the secret,
<img src="https://render.githubusercontent.com/render/math?math=s">
(say of 256-bits) using One-Time Pad and will
hash the key used. More concretely, the seller will do:

<!-- k_1 \leftarrow \{0,1\}^{256},\: k_2 \leftarrow \{0,1\}^{128};\: c \coloneqq s \oplus k_1\;\:\: y \coloneqq \text{SHA2}(k_1 \parallel k_2) -->
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://render.githubusercontent.com/render/math?math=k_1%20%5Cleftarrow%20%5C%7B0%2C1%5C%7D%5E%7B256%7D%2C%5C%3A%20k_2%20%5Cleftarrow%20%5C%7B0%2C1%5C%7D%5E%7B128%7D%3B%5C%3A%20c%20%5Ccoloneqq%20s%20%5Coplus%20k_1%5C%3B%5C%3A%5C%3A%20y%20%5Ccoloneqq%20%5Ctext%7BSHA2%7D(k_1%20%5Cparallel%20k_2)">

and will then share the ciphertext and the SHA image with the buyer.

*2*. The seller will also commit to their secret by computing:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://render.githubusercontent.com/render/math?math=%5Ctext%7Bcom%7D%20%3D%20s%5C%2CA%20%2B%20t%5C%2CP%20%5C%3A%5Ctext%7Bfor%7D%5C%3A%20t%20%5Cleftarrow%20%5Cmathbb%7BZ%7D_p%20%5C%3A%5C%3A%5C%3A%5C%3A%5C%3A%5Ctext%7B(here%2C%20%7D%5C%3Ap%5C%3A%5Ctext%7Bis%20the%20order%20of%20the%20EC%20group).%7D">

*3*. Both parties will now run our zero-knowledge protocol for the above statement, where the function is
implemented as:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://render.githubusercontent.com/render/math?math=f_%7B(c%2C%5C!y)%7D(k_1%2Ck_2)%20%5Ccoloneqq%20c%20%5Coplus%20k_1%20%5C%3A%5Ctext%7Bif%7D%5C%3A%20y%20%3D%20%5Ctext%7BSHA2%7D(k_1%20%5Cparallel%20k_2)%20%5C%3A%5Ctext%7Bor%7D%5C%3A%20%5Cbot%20%5C%3A%5Ctext%7Botherwise%7D.">

*4*. Now that the buyer (the verifier) is convinced about the fact that the SHA preimage known
by the prover decrypts
<img src="https://render.githubusercontent.com/render/math?math=c">
to the opening that the prover knows for
<img src="https://render.githubusercontent.com/render/math?math=%5Ctext%7Bcom%7D">
(the secret), they can start an independent (algebraic) zero-knowledge proof to ensure that
the secret is valid.

(In our next example of selling ECDSA signatures, this last step can be done with simply
a Schnorr proof of knowledge of a dlog, we refer to our
[paper](https://dl.acm.org/doi/10.1145/3372297.3417888) for more details.)

> With this tool, we provide a Boolean circuit describing the above decryption function based on OTP
(*data/XOR_SHA.txt*). If the secret is longer than 256-bits, you may need to define your
own circuit. In our paper, for the experiments about RSA signatures (where secrets are 2048
or even 4096 bits long), we used a circuit
based on AES instead of OTP. Contact us for more information about how we generated it.

## Usage (Example for selling ECDSA signatures)

*1*. The seller (prover) will generate a key pair by running:

```
./protocol_bin keygen
```

This will create a pair of files *data/public.key* and *data/private.key* corresponding
to a public/secret ECDSA signature key pair.

*2*. The seller (prover) will encrypt the secret to be sold and
hash the encryption key. To do so, run:

```
./protocol_bin setup
```

This will first compute a signature on the agreed message (*data/msg.txt*). This signature
is considered to be the secret to be sold.
The above execution will also create a file (*data/pub_input.txt*) containing the ciphertext (ct)
of the encrypted secret and a hash (y) of the key used for encryption as well as a second
file (*data/prv_input.txt*) containing extra information to complete the ZK proof.

*3*. Now the seller should share their public key (*data/public.key*) and
the public information from the above setup (*data/pub_input.txt*) with the
buyer (the verifier). This can be sent through an insecure channel.

*4*. Run the ZK proof protocol. The verifier (buyer) will act as the server, running:

```
./protocol_bin verifier PORT
```

(Choosing your favorite PORT number.)
To start the client process, run:

```
./protocol_bin prover IP PORT
```

Replacing IP by the IP address of the server host (usually 127.0.0.1 if you are running
both parties on the same machine) and PORT by the same port number selected before.


## How to use our tool for other purposes (other than ECDSA signatures)

The main modification you will have to perform is with respect step *4* from the above
[explanation](#what-is-this-tool-for) corresponding to the algebraic proof of the validity of
the secret.

*1*. Modify *extra_input.h* for the auxiliary inputs needed for the algebraic proof
apart from the default required inputs (the secret,
<img src="https://render.githubusercontent.com/render/math?math=t">,
<img src="https://render.githubusercontent.com/render/math?math=a">,
<img src="https://render.githubusercontent.com/render/math?math=A">,
<img src="https://render.githubusercontent.com/render/math?math=B^*">
(see our [paper](https://dl.acm.org/doi/10.1145/3372297.3417888) to recall their roles).

*2*. Modify *init_extra_input()* in *ecdsa_util.h* according to your new *ExtraInput*
defined in step *1*.

*3*. Modify *algebraic.hpp* to implement *ecdsa_prover_algebraic_PoK(...)* and
*ecdsa_verifier_algebraic_PoK(...)*.

*4*. The wrapper functions in *zkGC_algebraic.hpp* will integrate your functions in step *3*
into our  zkGC protocol. No further actions need to be done.


## License

See the LICENSE.pdf file.