# Ligero Zero-Knowledge Proofs

The circuit crate produces a WASM binary that can be used with the [Ligero Prover](https://github.com/ligeroinc/ligero-prover). This subdirectory contains sample inputs for the prover and verifier.

## Installation

Follow the build instructions from the Ligero repo in order to build and install Ligero `webgpu_prover` and `webgpu_verifier`.

## Usage

### Prover

Prover inputs can be constructed with the TXE library:

```typescript
import { argify, encrypt, extract } from "@safe-research/safe-txe";

const transaction = buildYourTransaction();
const recipients = fetchRecipientsOnchain();

const { blob, private } = encrypt({ transaction, recipients });
const { public } = extract({
  blob,
  structHash: hashStruct(transaction),
  nonce: transaction.nonce,
});
console.log("prover inputs", argify({ public, private }));
```

In order to generate a proof:

```sh
webgpu_prover "$(cat prover.json)"
```

<details><summary>Output:</summary>

```
=== Start ===
Start Stage 1
Exit with code 0
Num Linear constraints:             7026666
Num quadratic constraints:          214252727
Num Batch Equal Gates:              0
Num Batch Multiply Gates:           0
Root of Merkle Tree: 96a881a66fecd5329d95d0d77d9295cd22ae9457f87f824de34407e72c257c46
----------------------------------------
Start Stage 2
Exit with code 0
Num Linear constraints:             7026666
Num quadratic constraints:          214252727
----------------------------------------
Start Stage 3
Exit with code 0
Num Linear constraints:             7026666
Num quadratic constraints:          214252727

Prover root: 96a881a66fecd5329d95d0d77d9295cd22ae9457f87f824de34407e72c257c46
Validation of encoding:              true
Validation of linear constraints:    true
Validation of quadratic constraints: true
------------------------------------------
Final prove result:                  true

========== Timing Info ==========
Instantiate: 62ms    (min: 13, max: 34, count: 3)
stage1: 235018ms    (min: 235018, max: 235018, count: 1)
stage2: 646571ms    (min: 646571, max: 646571, count: 1)
stage3: 203908ms    (min: 203908, max: 203908, count: 1)
```

</details>

### Verifier

Verifier inputs can be constructed with the on-chain public data:

```typescript
import { argify, extract } from "@safe-research/safe-txe";

const [structHash, nonce, blob] = fetchRegisteredTransactionOnchain();

const inputs = extract({ blob, structHash, nonce });
console.log("verifier inputs", argify(inputs));
```

In order to verify the proof:

```sh
webgpu_verifier "$(cat verifier.json)"
```

<details><summary>Output:</summary>

```
=============== Start Verify ===============
Exit with code 0
Num Linear constraints:             7026666
Num quadratic constraints:          214252727

Prover root  : 96a881a66fecd5329d95d0d77d9295cd22ae9457f87f824de34407e72c257c46
Verifier root: 96a881a66fecd5329d95d0d77d9295cd22ae9457f87f824de34407e72c257c46
Validating Merkle Tree Root:         true
Validating Encoding Correctness:     true
Validating Linear Constraints:       true
Validating Quadratic Constraints:    true
Validating Encoding Equality:        true
Validating Linear Equality:          true
Validating Quadratic Equality:       true
-----------------------------------------
Final Verify Result:                 true

========== Timing Info ==========
Instantiate: 12ms    (min: 12, max: 12, count: 1)
Verify time: 420410ms    (min: 420410, max: 420410, count: 1)

```

</details>

## Results

**On my machine** (AMD 7840U with 32GB of RAM), the proving took around 18m05s to generated a 480MB proof, and took 7m00s to verify the proof. In its current state, this is not really feasible. Note, however, that the circuit we (very naively) created has hundreds of millions of constraints, and given more work and time, we can probably optimize the circuit in order to improve performance.
