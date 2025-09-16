import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decrypt, encrypt } from "../src/index.ts";

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

			const proposer = (await crypto.subtle.generateKey("X25519", false, [
				"deriveBits",
			])) as CryptoKeyPair;
			const recipients = (await Promise.all(
				[...Array(5)].map(() =>
					crypto.subtle.generateKey("X25519", false, ["deriveBits"]),
				),
			)) as CryptoKeyPair[];

      const blob = await encrypt({
        transaction,
        proposer,
        recipients: recipients.map((r) => r.publicKey),
      });

			for (const { privateKey } of recipients) {
				const decrypted = await decrypt({ blob, privateKey });
				assert.deepEqual(decrypted, transaction);
			}
		});
	});
});
