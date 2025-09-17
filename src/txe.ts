type TXE = {
	ciphertext: Uint8Array;
	iv: Uint8Array;
	tag: Uint8Array;
	recipients: [TXERecipient, ...TXERecipient[]];
};

type TXERecipient = {
	encryptedKey: Uint8Array;
	ephemeralPublicKey: Uint8Array;
};

function isTXE(value: unknown): value is TXE {
	if (value === null || typeof value !== "object") {
		return false;
	}
	const txe = value as Record<keyof TXE, unknown>;
	const isUint8Array = (v: unknown, len?: number): boolean => {
		return v instanceof Uint8Array && (len === undefined || v.length === len);
	};

	return (
		isUint8Array(txe.ciphertext) &&
		isUint8Array(txe.iv, 12) &&
		isUint8Array(txe.tag, 16) &&
		Array.isArray(txe.recipients) &&
		txe.recipients.length > 0 &&
		txe.recipients.every(
			(recipient) =>
				isUint8Array(recipient.encryptedKey, 24) &&
				isUint8Array(recipient.ephemeralPublicKey, 32),
		)
	);
}

function cursor() {
	let current = 0;
	return (size: number): number => {
		const old = current;
		current += size;
		return old;
	};
}

function encode(txe: TXE): Uint8Array {
	if (!isTXE(txe)) {
		throw new Error("invalid TXE");
	}

	const buffer = new ArrayBuffer(
		2 +
			txe.ciphertext.length + // ciphertext length (2 bytes) + ciphertext
			12 + // iv (12 bytes) +
			16 + // tag (16 bytes) +
			1 + // number of encryptedKeys minus 1 (1 byte) +
			txe.recipients.length * (24 + 32), // recipients (24 bytes encryptedKey + 32 bytes ephemeralPublicKey)
	);

	const view = new DataView(buffer);
	const data = new Uint8Array(buffer);
	const pos = cursor();

	view.setUint16(pos(2), txe.ciphertext.length);
	data.subarray(pos(txe.ciphertext.length)).set(txe.ciphertext);
	data.subarray(pos(12)).set(txe.iv);
	data.subarray(pos(16)).set(txe.tag);
	view.setUint8(pos(1), txe.recipients.length - 1);
	for (const { encryptedKey, ephemeralPublicKey } of txe.recipients) {
		data.subarray(pos(24)).set(encryptedKey);
		data.subarray(pos(32)).set(ephemeralPublicKey);
	}

	return data;
}

function decode(data: Uint8Array): TXE {
	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	const pos = cursor();
	const take = (len: number) => {
		const start = pos(len);
		return data.slice(start, start + len);
	};

	const ciphertextLength = view.getUint16(pos(2));
	const ciphertext = take(ciphertextLength);
	const iv = take(12);
	const tag = take(16);
	const encryptedKeysCountMinusOne = view.getUint8(pos(1));
	const recipients = [...Array(encryptedKeysCountMinusOne + 1)].map(() => ({
		encryptedKey: take(24),
		ephemeralPublicKey: take(32),
	})) as TXE["recipients"];

	return { ciphertext, iv, tag, recipients };
}

type JWE = {
	ciphertext: string;
	iv: string;
	tag: string;
	recipients: {
		encrypted_key: string;
		header: {
			alg: "ECDH-ES+A128KW";
			epk: {
				x: string;
				crv: "X25519";
				kty: "OKP";
			};
		};
	}[];
	protected: "eyJlbmMiOiJBMTI4R0NNIn0"; // { enc: "A128GCM" }
};

function toJWE(input: TXE | Uint8Array): JWE {
	const txe = input instanceof Uint8Array ? decode(input) : input;
	const ciphertext = base64Encode(txe.ciphertext);
	const iv = base64Encode(txe.iv);
	const tag = base64Encode(txe.tag);
	const recipients = txe.recipients.map(
		(recipient) =>
			({
				encrypted_key: base64Encode(recipient.encryptedKey),
				header: {
					alg: "ECDH-ES+A128KW",
					epk: {
						x: base64Encode(recipient.ephemeralPublicKey),
						crv: "X25519",
						kty: "OKP",
					},
				},
			}) as const,
	);
	return {
		ciphertext,
		iv,
		tag,
		recipients,
		protected: "eyJlbmMiOiJBMTI4R0NNIn0",
	};
}

function base64Encode(data: Uint8Array): string {
	type ToBase64 = {
		toBase64(options?: {
			alphabet?: "base64" | "base64url";
			omitPadding?: boolean;
		}): string;
	};
	if ((Uint8Array.prototype as Partial<ToBase64>).toBase64) {
		return (data as unknown as ToBase64).toBase64({
			alphabet: "base64url",
			omitPadding: true,
		});
	}

	const bitstr = [...data].map((byte) => String.fromCodePoint(byte)).join("");
	return btoa(bitstr)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export type { TXE };
export { isTXE, encode, decode, toJWE };
