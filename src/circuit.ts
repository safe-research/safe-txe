import { type Bytes, byteLength } from "./bytes.ts";
import { decode } from "./txe.ts";

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
		ephemeralPublicKey: Uint8Array;
	}[];
};

type PrivateInput = {
	transaction: Uint8Array;
	contentEncryptionKey: Uint8Array;
	recipients: {
		publicKey: Uint8Array;
		ephemeralPrivateKey: Uint8Array;
	}[];
};

type Extract = {
	nonce: bigint;
	structHash: Bytes;
	blob: Uint8Array;
};

const MAX_UINT = (1n << 256n) - 1n;
function extract({ nonce, structHash, blob }: Extract): Input {
	if (byteLength(structHash) !== 32) {
		throw new Error("invalid struct hash");
	}
	if (nonce < 0n || nonce > MAX_UINT) {
		throw new Error("invalid nonce");
	}

	const txe = decode(blob);
	const input: Input = {
		public: {
			structHash,
			nonce,
			...txe,
		},
		// Verifying a proof with Ligero requires the private input sizes to match
		// the inputs used when proving, while their values do not actually matter.
		// Use empty (but correctly sized) private input values. The actual private
		// inputs will be generated when encrypting.
		private: {
			transaction: new Uint8Array(txe.ciphertext.length),
			contentEncryptionKey: new Uint8Array(16),
			recipients: txe.recipients.map(() => ({
				publicKey: new Uint8Array(32),
				ephemeralPrivateKey: new Uint8Array(32),
			})),
		},
	};

	return input;
}

export type { Input, PublicInput, PrivateInput };
export { extract };
