import * as base64 from "jose/base64url";
import { type Bytes, byteLength } from "./bytes.ts";
import { decodeBlob, decryptJwe } from "./encryption.ts";

type Input = {
	public: PublicInput;
	private: PrivateInput;
};

type PublicInput = {
	structHash: Bytes;
	nonce: bigint;
	ciphertext: Uint8Array;
	iv: Uint8Array;
	tag: Uint8Array;
	recipients: {
		encryptedKey: Uint8Array;
		ephemeralKey: Uint8Array;
	}[];
};

type PrivateInput = {
	transaction: Uint8Array;
	contentKey: Uint8Array;
	privateKey: Uint8Array;
	recipients: {
		publicKey: Uint8Array;
	}[];
};

type Extract = {
	nonce: bigint;
	structHash: Bytes;
	blob: Uint8Array;
	privateKey?: CryptoKey;
	recipients?: CryptoKey[];
};

const MAX_UINT = (1n << 256n) - 1n;
async function extract({
	nonce,
	structHash,
	blob,
	privateKey,
	recipients,
}: Extract): Promise<Input> {
	if (byteLength(structHash) !== 32) {
		throw new Error("invalid struct hash");
	}
	if (nonce < 0n || nonce > MAX_UINT) {
		throw new Error("invalid nonce");
	}

	const jwe = decodeBlob(blob);
	const ciphertext = base64.decode(jwe.ciphertext);
	const input: Input = {
		public: {
			structHash,
			nonce,
			ciphertext,
			iv: base64.decode(jwe.iv),
			tag: base64.decode(jwe.tag),
			recipients: jwe.recipients.map((recipient) => ({
				encryptedKey: base64.decode(recipient.encrypted_key),
				ephemeralKey: base64.decode(recipient.header.epk.x),
			})),
		},
		private: {
			transaction: new Uint8Array(ciphertext.length),
			contentKey: new Uint8Array(16),
			privateKey: new Uint8Array(32),
			recipients: jwe.recipients.map(() => ({
				publicKey: new Uint8Array(32),
			})),
		},
	};

	if (privateKey) {
		const { plaintext } = await decryptJwe(jwe, privateKey);
		const { d } = await crypto.subtle.exportKey("jwk", privateKey);
		input.private.transaction = plaintext;
		// TODO: input.private.contentKey
		input.private.privateKey = base64.decode(d as string);
	}

	if (recipients) {
		if (recipients.length !== input.public.recipients.length) {
			throw new Error("recipient length mismatch");
		}

		input.private.recipients = await Promise.all(
			recipients.map(async (recipient) => {
				const { crv, x } = await crypto.subtle.exportKey("jwk", recipient);
				if (crv !== "X25519" || !x) {
					throw new Error("invalid recipient public key");
				}
				return { publicKey: base64.decode(x) };
			}),
		);
	}

	return input;
}

export type { Input, PublicInput, PrivateInput };
export { extract };
