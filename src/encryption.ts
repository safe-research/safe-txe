import { GeneralEncrypt, generalDecrypt } from "jose";
import {
	rlpDecode,
	rlpEncode,
	type SafeTransactionParameters,
} from "./safe.ts";

type Encrypt = {
	transaction: SafeTransactionParameters;
	proposer: Pick<CryptoKeyPair, "privateKey">;
	recipients: CryptoKey[];
};

async function encrypt({
	transaction,
	recipients,
}: Encrypt): Promise<Uint8Array> {
	if (recipients[0] === undefined) {
		throw new Error("must encrypt to at least one recipient");
	}
	const encoded = rlpEncode(transaction);
	let builder = new GeneralEncrypt(encoded)
		.setProtectedHeader({ enc: "A128GCM" })
		.addRecipient(recipients[0])
		.setUnprotectedHeader({ alg: "ECDH-ES+A128KW" });
	for (const recipient of recipients.slice(1)) {
		builder = builder
			.addRecipient(recipient)
			.setUnprotectedHeader({ alg: "ECDH-ES+A128KW" });
	}
	const jwe = await builder.encrypt();
	return encodeBlob(jwe as JWE);
}

type Decrypt = {
	blob: Uint8Array;
	privateKey: CryptoKey;
};

async function decrypt({
	blob,
	privateKey,
}: Decrypt): Promise<SafeTransactionParameters> {
	const jwe = decodeBlob(blob);
	const { plaintext } = await decryptJwe(jwe, privateKey);
	return rlpDecode(plaintext);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type JWE = {
	ciphertext: string;
	iv: string;
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
	tag: string;
	protected: "eyJlbmMiOiJBMTI4R0NNIn0"; // {"enc":"A128GCM"}
};

function encodeBlob(jwe: JWE): Uint8Array {
	return encoder.encode(JSON.stringify(jwe));
}

function decodeBlob(blob: Uint8Array): JWE {
	const jwe = JSON.parse(decoder.decode(blob));
	return jwe;
}

function decryptJwe(
	jwe: JWE,
	privateKey: CryptoKey,
): Promise<{ plaintext: Uint8Array }> {
	return generalDecrypt(jwe, privateKey);
}

export { encrypt, decrypt, encodeBlob, decodeBlob, decryptJwe };
