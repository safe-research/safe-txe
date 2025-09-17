import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";
import { generalDecrypt } from "jose";
import { decrypt, encrypt, toJWE } from "../src/index.ts";

describe("txe", () => {
	describe("encryption", () => {
		it("encrypts and decrypts", async () => {
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
			} as const;

			const recipients = (await Promise.all(
				[...Array(5)].map(() =>
					crypto.subtle.generateKey("X25519", false, ["deriveBits"]),
				),
			)) as CryptoKeyPair[];

			const { blob } = await encrypt({
				transaction,
				recipients: recipients.map((r) => r.publicKey),
			});

			for (const { privateKey } of recipients) {
				const decrypted = await decrypt({ blob, privateKey });
				assert.deepEqual(decrypted, transaction);
			}
		});

		it("can be converted to a JWE", async () => {
			const zero = `0x${"00".repeat(20)}` as const;
			const transaction = {
				to: zero,
				value: 0n,
				data: "0x",
				operation: 0,
				safeTxGas: 0n,
				baseGas: 0n,
				gasPrice: 0n,
				gasToken: zero,
				refundReceiver: zero,
			} as const;
			const recipient = (await crypto.subtle.generateKey("X25519", false, [
				"deriveBits",
			])) as CryptoKeyPair;

			const { blob } = await encrypt({
				transaction,
				recipients: [recipient.publicKey],
			});

			const jwe = toJWE(blob);
			const { plaintext } = await generalDecrypt(jwe, recipient.privateKey);
			assert.deepEqual(
				plaintext,
				ethers.getBytes(
					ethers.encodeRlp([
						transaction.to,
						ethers.toBeArray(transaction.value),
						transaction.data,
						ethers.toBeArray(transaction.operation),
						ethers.toBeArray(transaction.safeTxGas),
						ethers.toBeArray(transaction.baseGas),
						ethers.toBeArray(transaction.gasPrice),
						transaction.gasToken,
						transaction.refundReceiver,
					]),
				),
			);
		});
	});
});
