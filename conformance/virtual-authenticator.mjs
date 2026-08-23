import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";

const toBytes = (value) =>
  value instanceof Uint8Array ? value : new Uint8Array(value);
const toBuffer = (value) => {
  const bytes = toBytes(value);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
};
const base64url = (value) => Buffer.from(value).toString("base64url");
const fromBase64url = (value) => new Uint8Array(Buffer.from(value, "base64url"));
const sha256 = (value) => createHash("sha256").update(value).digest();

export function installVirtualAuthenticator(origin) {
  let credential;
  class PublicKeyCredential {}
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  PublicKeyCredential.isConditionalMediationAvailable = async () => true;
  globalThis.PublicKeyCredential = PublicKeyCredential;
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL(origin),
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        async create({ publicKey }) {
          credential = register(origin, publicKey);
          return credential.browserCredential;
        },
        async get({ publicKey }) {
          if (!credential) throw new Error("virtual authenticator has no credential");
          return authenticate(origin, publicKey, credential);
        },
      },
    },
  });
}

function register(origin, options) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  const credentialId = randomBytes(32);
  const coseKey = encodeCbor(
    new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, fromBase64url(jwk.x)],
      [-3, fromBase64url(jwk.y)],
    ]),
  );
  const rpIdHash = sha256(options.rp.id);
  const counter = Buffer.alloc(4);
  const credentialLength = Buffer.alloc(2);
  credentialLength.writeUInt16BE(credentialId.length);
  const authData = Buffer.concat([
    rpIdHash,
    Buffer.from([0x45]),
    counter,
    Buffer.alloc(16),
    credentialLength,
    credentialId,
    coseKey,
  ]);
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.create",
      challenge: base64url(options.challenge),
      origin,
      crossOrigin: false,
    }),
  );
  const attestationObject = encodeCbor(
    new Map([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", new Uint8Array(authData)],
    ]),
  );
  return {
    credentialId,
    privateKey,
    counter: 0,
    browserCredential: browserCredential(credentialId, {
      attestationObject,
      clientDataJSON,
      getTransports: () => ["internal"],
      getPublicKeyAlgorithm: () => -7,
      getPublicKey: () => null,
      getAuthenticatorData: () => toBuffer(authData),
    }),
  };
}

function authenticate(origin, options, credential) {
  credential.counter += 1;
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(credential.counter);
  const authData = Buffer.concat([
    sha256(options.rpId),
    Buffer.from([0x05]),
    counter,
  ]);
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: base64url(options.challenge),
      origin,
      crossOrigin: false,
    }),
  );
  const signature = sign(
    "sha256",
    Buffer.concat([authData, sha256(clientDataJSON)]),
    credential.privateKey,
  );
  return browserCredential(credential.credentialId, {
    authenticatorData: toBuffer(authData),
    clientDataJSON: toBuffer(clientDataJSON),
    signature: toBuffer(signature),
    userHandle: null,
  });
}

function browserCredential(credentialId, response) {
  return {
    id: base64url(credentialId),
    rawId: toBuffer(credentialId),
    response: Object.fromEntries(
      Object.entries(response).map(([key, value]) => [
        key,
        typeof value === "function" ? value : toBuffer(value),
      ]),
    ),
    type: "public-key",
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({}),
  };
}

function encodeCbor(value) {
  if (value instanceof Uint8Array) return encodeBytes(2, value);
  if (typeof value === "string") return encodeBytes(3, Buffer.from(value));
  if (typeof value === "number") {
    return value >= 0 ? encodeLength(0, value) : encodeLength(1, -1 - value);
  }
  if (value instanceof Map) {
    const entries = [...value].flatMap(([key, item]) => [encodeCbor(key), encodeCbor(item)]);
    return Buffer.concat([encodeLength(5, value.size), ...entries]);
  }
  throw new TypeError(`unsupported virtual-authenticator CBOR value: ${typeof value}`);
}

function encodeBytes(major, value) {
  return Buffer.concat([encodeLength(major, value.length), Buffer.from(value)]);
}

function encodeLength(major, value) {
  const prefix = major << 5;
  if (value < 24) return Buffer.from([prefix | value]);
  if (value < 256) return Buffer.from([prefix | 24, value]);
  if (value < 65536) {
    const encoded = Buffer.alloc(3);
    encoded[0] = prefix | 25;
    encoded.writeUInt16BE(value, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(5);
  encoded[0] = prefix | 26;
  encoded.writeUInt32BE(value, 1);
  return encoded;
}
