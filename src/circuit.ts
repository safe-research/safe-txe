import { type Bytes, byteLength, toBytes } from "./bytes.ts";
import * as rlp from "./rlp.ts";
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

type InputArguments = {
	public: Bytes;
	private: Bytes;
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
	return conceal({
		public: {
			structHash,
			nonce,
			...txe,
		},
	});
}

function conceal(input: Pick<Input, "public">): Input {
	return {
		...input,
		// Verifying a proof with Ligero requires the private input sizes to match
		// the inputs used when proving, while their values do not actually matter.
		// Use empty (but correctly sized) private input values. The actual private
		// inputs will be generated when encrypting.
		private: {
			transaction: new Uint8Array(input.public.ciphertext.length),
			contentEncryptionKey: new Uint8Array(16),
			recipients: input.public.recipients.map(() => ({
				publicKey: new Uint8Array(32),
				ephemeralPrivateKey: new Uint8Array(32),
			})),
		},
	};
}

function argify(input: Input): InputArguments {
	return {
		public: toBytes(
			rlp.encode([
				input.public.structHash,
				input.public.nonce,
				input.public.ciphertext,
				input.public.iv,
				input.public.tag,
				input.public.recipients.map((r) => [
					r.encryptedKey,
					r.ephemeralPublicKey,
				]),
			]),
		),
		private: toBytes(
			rlp.encode([
				input.private.transaction,
				input.private.contentEncryptionKey,
				input.private.recipients.map((r) => [
					r.publicKey,
					r.ephemeralPrivateKey,
				]),
			]),
		),
	};
}

export type { Input, PublicInput, PrivateInput, InputArguments };
export { extract, conceal, argify };
