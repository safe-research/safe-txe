type Address = `0x${string}`;
type Bytes = `0x${string}`;

function isAddress(s: unknown): s is Address {
	return typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
}

function isBytes(s: unknown): s is Bytes {
	return typeof s === "string" && /^0x([0-9a-fA-F]{2})*$/.test(s);
}

function byteLength(b: Bytes): number {
	return (b.length - 2) / 2;
}

function toBytes(array: Uint8Array): Bytes {
	return `0x${[...array].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export type { Address, Bytes };
export { isAddress, isBytes, byteLength, toBytes };
