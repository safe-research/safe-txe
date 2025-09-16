type Address = `0x${string}`;
type Hex = string;
type Bytes = `0x${Hex}`;

function isAddress(s: unknown): s is Address {
	return typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
}

function isBytes(s: unknown): s is Bytes {
	return typeof s === "string" && /^0x([0-9a-fA-F]{2})*$/.test(s);
}

function isHex(s: unknown): s is Hex {
	return typeof s === "string" && /^([0-9a-fA-F]{2})*$/.test(s);
}

function byteLength(b: Bytes): number {
	return (b.length - 2) / 2;
}

function setHex(array: Uint8Array, hex: Hex) {
	for (let i = 0; i < hex.length / 2; i++) {
		const j = i * 2;
		array[i] = parseInt(hex.slice(j, j + 2), 16);
	}
}

export type { Address, Bytes, Hex };
export { isAddress, isBytes, isHex, byteLength, setHex };
