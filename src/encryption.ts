import {
	base64url,
	FlattenedEncrypt,
	type GeneralJWE,
	generalDecrypt,
} from "jose";
import type { PrivateInput } from "./circuit.ts";
import { unprotectedOptions } from "./internal/jose-private.js";
import {
	rlpDecode,
	rlpEncode,
	type SafeTransactionParameters,
} from "./safe.ts";
import { decode, encode, type TXE } from "./txe.ts";

type Encrypt = {
	transaction: SafeTransactionParameters;
	recipients: CryptoKey[];
};

async function contentEncryptionKey(): Promise<Uint8Array> {
	const cek = new Uint8Array(16);
	crypto.getRandomValues(cek);
	return cek;
}

async function ephemeralPrivateKey(): Promise<CryptoKey> {
	const { privateKey } = (await crypto.subtle.generateKey("X25519", true, [
		"deriveBits",
	])) as CryptoKeyPair;
	return privateKey;
}

async function exportPrivateKey(epk: CryptoKey): Promise<Uint8Array> {
	const { d } = (await crypto.subtle.exportKey("jwk", epk)) as { d: string };
	return base64url.decode(d);
}

async function exportPublicKey(recipient: CryptoKey): Promise<Uint8Array> {
	const raw = await crypto.subtle.exportKey("raw", recipient);
	return new Uint8Array(raw);
}

async function encrypt({
	transaction,
	recipients,
}: Encrypt): Promise<{ blob: Uint8Array; private: PrivateInput }> {
	if (recipients.length === 0) {
		throw new Error("must encrypt to at least one recipient");
	}
	const encoded = rlpEncode(transaction);
	const cek = await contentEncryptionKey();

	const epks = await Promise.all(recipients.map(() => ephemeralPrivateKey()));
	const jwes = await Promise.all(
		recipients.map(async (recipient, i) =>
			new FlattenedEncrypt(encoded)
				.setProtectedHeader({ enc: "A128GCM" })
				.setUnprotectedHeader({ alg: "ECDH-ES+A128KW" })
				.setContentEncryptionKey(cek)
				.setKeyManagementParameters({ epk: epks[i] as CryptoKey })
				.encrypt(recipient, unprotectedOptions),
		),
	);
	const txe = toTXE(jwes as [InternalJWE, ...InternalJWE[]]);
	return {
		blob: encode(txe),
		private: {
			transaction: encoded,
			contentEncryptionKey: cek,
			recipients: await Promise.all(
				recipients.map(async (recipient, i) => ({
					publicKey: await exportPublicKey(recipient),
					ephemeralPrivateKey: await exportPrivateKey(epks[i] as CryptoKey),
				})),
			),
		},
	};
}

type Decrypt = {
	blob: Uint8Array;
	privateKey: CryptoKey;
};

async function decrypt({
	blob,
	privateKey,
}: Decrypt): Promise<SafeTransactionParameters> {
	const txe = decode(blob);
	const jwe = fromTXE(txe);
	const { plaintext } = await generalDecrypt(jwe, privateKey);
	return rlpDecode(plaintext);
}

type InternalJWE = {
	ciphertext: string;
	iv: string;
	tag: string;
	encrypted_key: string;
	header: {
		alg: "ECDH-ES+A128KW";
		epk: {
			x: string;
			crv: "X25519";
			kty: "OKP";
		};
	};
	protected: "eyJlbmMiOiJBMTI4R0NNIn0";
};

function toTXE([jwe, ...jwes]: InternalJWE[]): TXE {
	if (jwe === undefined) {
		throw new Error("at least one JWE required");
	}
	const ciphertext = base64url.decode(jwe.ciphertext);
	const iv = base64url.decode(jwe.iv);
	const tag = base64url.decode(jwe.tag);
	const recipient = (jwe: InternalJWE) => ({
		encryptedKey: base64url.decode(jwe.encrypted_key),
		ephemeralPublicKey: base64url.decode(jwe.header.epk.x),
	});
	return {
		ciphertext,
		iv,
		tag,
		recipients: [recipient(jwe), ...jwes.map(recipient)],
	};
}

const encoder = new TextEncoder();
function fromTXE(txe: TXE): GeneralJWE {
	const ciphertext = base64url.encode(txe.ciphertext);
	const iv = base64url.encode(txe.iv);
	const tag = base64url.encode(txe.tag);
	const recipients = txe.recipients.map((recipient) => ({
		encrypted_key: base64url.encode(recipient.encryptedKey),
		header: {
			alg: "ECDH-ES+A128KW",
			epk: {
				x: base64url.encode(recipient.ephemeralPublicKey),
				crv: "X25519",
				kty: "OKP",
			},
		},
	}));
	const prot = base64url.encode(
		encoder.encode(JSON.stringify({ enc: "A128GCM" })),
	);
	return {
		ciphertext,
		iv,
		tag,
		recipients,
		protected: prot,
	};
}

export { encrypt, decrypt };
