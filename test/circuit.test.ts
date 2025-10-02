import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { describe, it } from "node:test";
import { WASI } from "node:wasi";
import { ethers } from "ethers";
import {
	argify,
	type Bytes,
	encrypt,
	extract,
	type Input,
} from "../src/index.ts";

const { TXE_LOG } = process.env;
const circuit = await fs
	.readFile("./target/wasm32-unknown-unknown/release/safe_txe_circuit.wasm")
	.catch(() => null)
	.then(async (wasm) => {
		if (!wasm) {
			return null;
		}

		const module = await WebAssembly.compile(wasm as BufferSource);
		const decoder = new TextDecoder();

		return async (input: Input) => {
			const args = argify(input);
			const wasi = new WASI({
				version: "preview1",
				args: ["safe_txe_circuit", args.public, args.private],
			});
			const instance = await WebAssembly.instantiate(module, {
				env: {
					log: (ptr: number, len: number) => {
						if (!TXE_LOG) {
							return;
						}
						const { memory } = instance.exports as {
							memory: WebAssembly.Memory;
						};
						const buffer = new Uint8Array(memory.buffer.slice(ptr, ptr + len));
						const message = decoder.decode(buffer);
						console.log(message);
					},
				},
				wasi_snapshot_preview1: {
					// biome-ignore-start lint/complexity/useLiteralKeys: index signature type
					args_get: wasi.wasiImport["args_get"],
					args_sizes_get: wasi.wasiImport["args_sizes_get"],
					proc_exit: wasi.wasiImport["proc_exit"],
					// biome-ignore-end lint/complexity/useLiteralKeys: index signature type
				},
			});
			const code = wasi.start(instance);
			return code === 0;
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
				(input: Input) => (input.private.recipients[0]!.publicKey[0]! ^= 0xff),
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
