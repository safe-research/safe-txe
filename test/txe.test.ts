import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { rlpDecode, rlpEncode } from "../src/safe.ts";

describe("tests", () => {
	it("passes", () => {
		assert.ok(true);
	});
});

describe("safe", () => {
	describe("rlp", () => {
		it("encodes and decodes", () => {
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
			const roundtrip = rlpDecode(rlpEncode(transaction));
			assert.deepEqual(roundtrip, transaction);
		});
	});
});
