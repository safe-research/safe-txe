// TODO: Jose does not expose the API to create multi-recipient JWEs with a
// chosen content encryption key and ephemeral ECDH key. Import some internals
// to work around this for testing, but  we need to implement this ourselves.
import { unprotected } from "../../node_modules/jose/dist/webapi/lib/private_symbols.js";
export const unprotectedOptions = { [unprotected]: true };
