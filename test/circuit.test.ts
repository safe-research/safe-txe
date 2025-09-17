import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { describe, it } from "node:test";
import { ethers } from "ethers";
import { type Bytes, encrypt, extract, type Input } from "../src/index.ts";

const circuit = await fs
	.readFile("./target/wasm32-unknown-unknown/debug/safe_txe_circuit.wasm")
	.catch(() => null)
	.then(async (wasm) => {
		if (!wasm) {
			return null;
		}

		const bytes = wasm as BufferSource;
		const decoder = new TextDecoder();
		const { instance } = await WebAssembly.instantiate(bytes, {
			env: {
				log: (ptr: number, len: number) => {
					const { memory } = instance.exports as { memory: WebAssembly.Memory };
					const buffer = new Uint8Array(memory.buffer.slice(ptr, ptr + len));
					const message = decoder.decode(buffer);
					console.log(message);
				},
			},
		});
		const { memory, txe_input_new, txe_input_free, txe_circuit } =
			instance.exports as {
				memory: WebAssembly.Memory;
				txe_input_new: (
					transactionLength: number,
					recipientsLength: number,
				) => number;
				txe_input_free: (input: number) => void;
				txe_circuit: (input: number) => number;
			};
		return (input: Input) => {
			const ptr = txe_input_new(
				input.public.ciphertext.length,
				input.public.recipients.length,
			);
			try {
				const buffer = new Uint8Array(memory.buffer.slice(ptr));
				buffer[0] = 1;
				txe_circuit(ptr);
				return true;
			} catch {
				return false;
			} finally {
				txe_input_free(ptr);
			}
		};
	});

async function txe() {
	const transaction = {
		to: `0x${"a1".repeat(20)}`,
		value: 2n,
		data: "0x03040506",
		operation: 1,
		safeTxGas: 7n,
		baseGas: 8n,
		gasPrice: 9n,
		gasToken: `0x${"a2".repeat(20)}`,
		refundReceiver: `0x${"a3".repeat(20)}`,
		nonce: 1337n,
	} as const;

	const proposer = (await crypto.subtle.generateKey("X25519", true, [
		"deriveBits",
	])) as CryptoKeyPair;
	const recipients = [
		proposer,
		...(await Promise.all(
			[...Array(2)].map(() =>
				crypto.subtle.generateKey("X25519", false, ["deriveBits"]),
			),
		)),
	] as CryptoKeyPair[];

	const structHash = ethers.TypedDataEncoder.hashStruct(
		"SafeTx",
		{
			SafeTx: [
				{ type: "address", name: "to" },
				{ type: "uint256", name: "value" },
				{ type: "bytes", name: "data" },
				{ type: "uint8", name: "operation" },
				{ type: "uint256", name: "safeTxGas" },
				{ type: "uint256", name: "baseGas" },
				{ type: "uint256", name: "gasPrice" },
				{ type: "address", name: "gasToken" },
				{ type: "address", name: "refundReceiver" },
				{ type: "uint256", name: "nonce" },
			],
		},
		transaction,
	);
	const { blob, ...input } = await encrypt({
		transaction,
		recipients: recipients.map((r) => r.publicKey),
	});

	return {
		...extract({
			structHash: structHash as Bytes,
			nonce: transaction.nonce,
			blob,
		}),
		...input,
	};
}

describe("circuit", { skip: !circuit }, () => {
	describe("verify", () => {
		it("should verify a valid TXE", async () => {
			const input = await txe();
			const htoa = (x: string) => Buffer.from(x.replace(/^0x/, ""), "hex");
			const bstr = (x: Uint8Array) =>
				`b"${[...x].map((b) => `\\x${b.toString(16).padStart(2, "0")}`)}"`;
			console.log(`
        Input {
          public: PublicInput {
            structHash: ${bstr(htoa(input.public.structHash))},
            nonce: ${bstr(htoa(input.public.nonce.toString(16).padStart(64, "0")))},
            ciphertext: ${bstr(input.public.ciphertext)},
            iv: ${bstr(input.public.iv)},
            tag: ${bstr(input.public.tag)},
            recipients: &[${input.public.recipients.map(
							(r) => `Recipient {
              encryptedKey: ${bstr(r.encryptedKey)},
              ephemeralPublicKey: ${bstr(r.ephemeralPublicKey)},
            }`,
						)}],
          },
          private: PrivateInput {
            transaction: ${bstr(input.private.transaction)},
            contentEncryptionKey: ${bstr(input.private.contentEncryptionKey)},
            recipients: &[${input.private.recipients.map(
							(r) => `Recipient {
              publicKey: ${bstr(r.publicKey)},
              ephemeralPrivateKey: ${bstr(r.ephemeralPrivateKey)},
            }`,
						)}],
          },
        }
      `);
			assert.equal(circuit?.(input), true);
		});

		it("should fail if TXE was tamperred with", async () => {
			const input = await txe();
			assert.equal(circuit?.(input), false);
		});
	});
});
