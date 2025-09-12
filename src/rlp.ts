import { type Bytes, byteLength, isBytes } from "./bytes.ts";

type Encode = number | bigint | Bytes | Encode[];
type Decode = Bytes | Decode[];

function encode(data: Encode): Uint8Array {
	if (Array.isArray(data)) {
		return lengthPrefix(0xc0, ...data.map(encode));
	} else if (isBytes(data)) {
		if (byteLength(data) === 1 && Number(data) < 0x80) {
			return Uint8Array.from([Number(data)]);
		} else {
			return lengthPrefix(0x80, fromBytes(data));
		}
	} else if (typeof data === "bigint" || typeof data === "number") {
		return encode(`0x${hex(data)}`);
	} else {
		throw new Error(`invalid RLP field ${data}`);
	}
}

function lengthPrefix(offset: number, ...chunks: Uint8Array[]): Uint8Array {
	const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
	let start: number;
	let result: Uint8Array;
	if (length < 56) {
		start = 1;
		result = new Uint8Array(start + length);
		result[0] = offset + length;
	} else {
		const lbytes = hex(length);
		const lsize = lbytes.length / 2;
		start = 1 + lsize;
		result = new Uint8Array(start + length);
		result[0] = offset + 55 + lsize;
		setHex(result.subarray(1), lbytes);
	}
	for (const chunk of chunks) {
		result.set(chunk, start);
		start += chunk.length;
	}
	return result;
}

function decode(data: Uint8Array): Decode {
	const [result, rest] = next(data);
	if (rest.length > 0) {
		throw new Error("invalid RLP data: trailing bytes");
	}
	return result;
}

function next(data: Uint8Array): [Decode, Uint8Array] {
	const tag = data[0];
	if (tag === undefined) {
		throw new Error("invalid RLP data: empty input");
	}
	if (tag <= 0x7f) {
		return [`0x${toHexByte(tag)}`, data.slice(1)];
	} else if (tag <= 0xbf) {
		const [payload, rest] = prefixedLength(tag, 0x80, data);
		return [toBytes(payload), rest];
	} else {
		const [payload, rest] = prefixedLength(tag, 0xc0, data);
		const items: Decode[] = [];
		let remaining = payload;
		while (remaining.length > 0) {
			const [item, rest] = next(remaining);
			items.push(item);
			remaining = rest;
		}
		return [items, rest];
	}
}

function prefixedLength(
	tag: number,
	offset: number,
	data: Uint8Array,
): [Uint8Array, Uint8Array] {
	const long = offset + 55;
	try {
		if (tag <= long) {
			const length = tag - offset;
			const end = 1 + length;
			return [data.slice(1, end), data.slice(end)];
		} else {
			const lsize = tag - long;
			const start = 1 + lsize;
			const length = Number(toBytes(data.slice(1, start)));
			const end = start + length;
			return [data.slice(start, end), data.slice(end)];
		}
	} catch {
		throw new Error("invalid RLP data: invalid length prefix");
	}
}

function hex(value: number | bigint): string {
	if (value === 0 || value === 0n) {
		return "";
	}
	const hex = value.toString(16);
	return hex.length % 2 === 0 ? hex : `0${hex}`;
}

function setHex(array: Uint8Array, hex: string) {
	for (let i = 0; i < hex.length / 2; i++) {
		const j = i * 2;
		array[i] = parseInt(hex.slice(j, j + 2), 16);
	}
}

function fromHex(data: string): Uint8Array {
	const result = new Uint8Array(data.length / 2);
	setHex(result, data);
	return result;
}

function fromBytes(data: Bytes): Uint8Array {
	return fromHex(data.slice(2));
}

function toHexByte(byte: number): string {
	return byte.toString(16).padStart(2, "0");
}

function toBytes(data: Uint8Array): Bytes {
	return `0x${[...data].map(toHexByte).join("")}` as Bytes;
}

export { encode, decode };
