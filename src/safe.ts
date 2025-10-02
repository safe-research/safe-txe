import { type Address, type Bytes, isAddress, isBytes } from "./bytes.ts";
import * as rlp from "./rlp.ts";

enum Operation {
	CALL = 0,
	DELEGATECALL = 1,
}

type SafeTransaction = {
	to: Address;
	value: bigint;
	data: Bytes;
	operation: Operation;
	safeTxGas: bigint;
	baseGas: bigint;
	gasPrice: bigint;
	gasToken: Address;
	refundReceiver: Address;
	nonce: bigint;
};

type SafeTransactionParameters = Omit<SafeTransaction, "nonce">;

function encode(transaction: SafeTransactionParameters): Uint8Array {
	return rlp.encode([
		transaction.to,
		transaction.value,
		transaction.data,
		transaction.operation,
		transaction.safeTxGas,
		transaction.baseGas,
		transaction.gasPrice,
		transaction.gasToken,
		transaction.refundReceiver,
	]);
}

function decode(encoded: Uint8Array): SafeTransactionParameters {
	const fields = rlp.decode(encoded);
	if (!Array.isArray(fields) || fields.length !== 9) {
		throw new Error("invalid RLP-encoded Safe transaction");
	}

	const asAddress = (v: unknown): Address => {
		if (!isAddress(v)) {
			throw new Error(`invalid address field: ${v}`);
		}
		return v;
	};
	const asBytes = (v: unknown): Bytes => {
		if (!isBytes(v)) {
			throw new Error(`invalid bytes field: ${v}`);
		}
		return v;
	};
	const asBigInt = (v: unknown): bigint => {
		if (!isBytes(v)) {
			throw new Error(`invalid bigint field: ${v}`);
		}
		return v === "0x" ? 0n : BigInt(v);
	};
	const asOperation = (v: unknown): Operation => {
		if (v === "0x") {
			return Operation.CALL;
		} else if (v === "0x01") {
			return Operation.DELEGATECALL;
		} else {
			throw new Error(`invalid operation field: ${v}`);
		}
	};

	return {
		to: asAddress(fields[0]),
		value: asBigInt(fields[1]),
		data: asBytes(fields[2]),
		operation: asOperation(fields[3]),
		safeTxGas: asBigInt(fields[4]),
		baseGas: asBigInt(fields[5]),
		gasPrice: asBigInt(fields[6]),
		gasToken: asAddress(fields[7]),
		refundReceiver: asAddress(fields[8]),
	};
}

export type { Operation, SafeTransaction, SafeTransactionParameters };
export { encode, decode };
