import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import { describe, it } from "node:test";
import { promisify } from "node:util";
import { ethers } from "ethers";
import {
	argify,
	type Bytes,
	encrypt,
	extract,
	type Input,
} from "../src/index.ts";

const { TXE_LOG } = process.env;
const wasm = await fs
	.readFile("./target/wasm32-unknown-unknown/debug/safe-txe-circuit.wasm")
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
					if (!TXE_LOG) {
						return;
					}
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
		const getMemoryCursor = (ptr: number, len?: number) => {
			const buffer = new Uint8Array(memory.buffer, ptr, len);
			const view = new DataView(memory.buffer, ptr, len);

			let pos = 0;
			return {
				write: (data: Uint8Array) => {
					buffer.set(data, pos);
					pos += data.length;
				},
				skip: (size: number) => {
					pos += size;
				},
				slice: (itemSize: number = 1) => {
					const ptr = view.getUint32(pos, true);
					const len = view.getUint32(pos + 4, true) * itemSize;
					pos += 8;
					return getMemoryCursor(ptr, len);
				},
			};
		};
		return async (input: Input) => {
			const ptr = txe_input_new(
				input.public.ciphertext.length,
				input.public.recipients.length,
			);
			try {
				const cursor = getMemoryCursor(ptr);
				cursor.write(ethers.getBytes(input.public.structHash));
				cursor.write(ethers.getBytes(ethers.toBeHex(input.public.nonce, 32)));
				cursor.slice().write(input.public.ciphertext);
				cursor.write(input.public.iv);
				cursor.write(input.public.tag);
				let recipients = cursor.slice(56);
				for (const recipient of input.public.recipients) {
					recipients.write(recipient.encryptedKey);
					recipients.write(recipient.ephemeralPublicKey);
				}
				cursor.slice().write(input.private.transaction);
				cursor.write(input.private.contentEncryptionKey);
				recipients = cursor.slice(64);
				for (const recipient of input.private.recipients) {
					recipients.write(recipient.publicKey);
					recipients.write(recipient.ephemeralPrivateKey);
				}
				txe_circuit(ptr);
				return true;
			} catch {
				return false;
			} finally {
				txe_input_free(ptr);
			}
		};
	});

const BIN = "./target/debug/safe-txe-circuit";
const bin = await fs
	.access(BIN, fs.constants.R_OK | fs.constants.W_OK)
	.catch(() => true)
	.then((err) => {
		if (err) {
			return null;
		}

		const exec = promisify(execFile);
		return async (input: Input) => {
			const args = argify(input);
			const { error, stdout, stderr } = await exec(BIN, [
				args.public,
				args.private,
			]).catch((error) => ({ error, ...error }));
			if (TXE_LOG) {
				console.log(
					`--- BEGIN STDOUT ---\n${stdout}--- END STDOUT ---`,
				);
				console.log(
					`--- BEGIN STDERR ---\n${stderr}--- END STDERR ---`,
				);
			}
			return !error;
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

describe("circuit", () => {
	for (const { name, circuit } of [
		{ name: "wasm", circuit: wasm },
		{ name: "bin", circuit: bin },
	]) {
		describe(name, { skip: !circuit }, () => {
			describe("verify", () => {
				it("should verify a valid TXE", async () => {
					const input = await txe();
					assert.equal(await circuit?.(input), true);
				});

				it("should fail if TXE was tamperred with", async () => {
					for (const modify of [
						// biome-ignore-start lint/style/noNonNullAssertion: test code
						// biome-ignore-start lint/suspicious/noAssignInExpressions: test code
						(input: Input) =>
							(input.public.structHash = `0x${(BigInt(input.public.structHash) + 1n).toString(16).padStart(64, "0")}`),
						(input: Input) => input.public.nonce++,
						(input: Input) => (input.public.ciphertext[0]! ^= 0xff),
						(input: Input) => (input.public.iv[0]! ^= 0xff),
						(input: Input) => (input.public.tag[0]! ^= 0xff),
						(input: Input) =>
							(input.public.recipients[0]!.encryptedKey[0]! ^= 0xff),
						(input: Input) =>
							(input.public.recipients[0]!.ephemeralPublicKey[0]! ^= 0xff),
						(input: Input) => (input.private.transaction[0]! ^= 0xff),
						(input: Input) => (input.private.contentEncryptionKey[0]! ^= 0xff),
						(input: Input) =>
							(input.private.recipients[0]!.publicKey[0]! ^= 0xff),
						(input: Input) =>
							(input.private.recipients[0]!.ephemeralPrivateKey[0]! ^= 0xff),
						// biome-ignore-end lint/style/noNonNullAssertion: test code
						// biome-ignore-end lint/suspicious/noAssignInExpressions: test code
					]) {
						const input = await txe();
						modify(input);
						assert.equal(await circuit?.(input), false);
					}
				});
			});
		});
	}
});
