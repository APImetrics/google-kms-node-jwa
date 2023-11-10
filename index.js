const bufferEqual = require('buffer-equal-constant-time');
const { Buffer } = require('safe-buffer');
const crypto = require('crypto');
const formatEcdsa = require('ecdsa-sig-formatter');
const util = require('util');
const { KeyManagementServiceClient } = require('@google-cloud/kms');

const KMS_CLIENT = new KeyManagementServiceClient();

const MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';
let MSG_INVALID_SECRET = 'secret must be a string or buffer';
let MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer';
const MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object';

const supportsKeyObjects = typeof crypto.createPublicKey === 'function';
if (supportsKeyObjects) {
  MSG_INVALID_VERIFIER_KEY += ' or a KeyObject';
  MSG_INVALID_SECRET += 'or a KeyObject';
}

function typeError(template, ...args) {
  const errMsg = util.format.bind(util, template)(...args);
  return new TypeError(errMsg);
}

async function convertToPublicKey(key) {
  if (Buffer.isBuffer(key)) {
    return key;
  }

  if (typeof key === 'string') {
    return key;
  }

  if (!key || !key.projectId) {
    return key;
  }

  // Get Public Key from Google KMS private key
  const {
    projectId,
    locationId,
    keyRingId,
    keyId,
    versionId,
  } = key;

  // Build the version name
  const versionName = KMS_CLIENT.cryptoKeyVersionPath(
    projectId,
    locationId,
    keyRingId,
    keyId,
    versionId,
  );

  const [publicKey] = await KMS_CLIENT.getPublicKey({
    name: versionName,
  });

  return publicKey.pem;
}

function checkIsPublicKey(key) {
  if (Buffer.isBuffer(key)) {
    return;
  }

  if (typeof key === 'string') {
    return;
  }

  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }

  if (typeof key.type !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }

  if (typeof key.asymmetricKeyType !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }

  if (typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
}

function checkIsPrivateKey(key) {
  if (Buffer.isBuffer(key)) {
    return;
  }

  if (typeof key === 'string') {
    return;
  }

  if (typeof key === 'object') {
    return;
  }

  throw typeError(MSG_INVALID_SIGNER_KEY);
}

function checkIsSecretKey(key) {
  if (Buffer.isBuffer(key)) {
    return;
  }

  if (typeof key === 'string') {
    return;
  }

  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_SECRET);
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_SECRET);
  }

  if (key.type !== 'secret') {
    throw typeError(MSG_INVALID_SECRET);
  }

  if (typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_SECRET);
  }
}

function fromBase64(base64) {
  return base64
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function toBase64(base64url) {
  let base64urlStr = base64url.toString();

  const padding = 4 - (base64urlStr.length % 4);
  if (padding !== 4) {
    for (let i = 0; i < padding; i += 1) {
      base64urlStr += '=';
    }
  }

  return base64urlStr
    .replace(/-/g, '+')
    .replace(/_/g, '/');
}

function bufferOrString(obj) {
  return Buffer.isBuffer(obj) || typeof obj === 'string';
}

function normalizeInput(thing) {
  if (!bufferOrString(thing)) { return JSON.stringify(thing); }
  return thing;
}

function isGoogleKmsKey(key) {
  return key && key.projectId && key.locationId && key.keyRingId;
}

async function signWithGoogleKms(bits, privateKey, message) {
  const {
    projectId, locationId, keyRingId, keyId, versionId,
  } = privateKey;

  const hashScheme = `sha${bits}`;
  const digest = crypto.createHash(hashScheme);
  digest.update(message);

  // Build the version name
  const versionName = KMS_CLIENT.cryptoKeyVersionPath(
    projectId,
    locationId,
    keyRingId,
    keyId,
    versionId,
  );

  // Sign the message with Cloud KMS
  const [signResponse] = await KMS_CLIENT.asymmetricSign({
    name: versionName,
    digest: {
      [hashScheme]: digest.digest(),
    },
  });
  const encoded = signResponse.signature.toString('base64');
  return fromBase64(encoded);
}

function createHmacSigner(bits) {
  return async function sign(thingIn, secret) {
    checkIsSecretKey(secret);
    const thing = normalizeInput(thingIn);
    const hmac = crypto.createHmac(`sha${bits}`, secret);
    const sig = (hmac.update(thing), hmac.digest('base64'));
    return fromBase64(sig);
  };
}

function createHmacVerifier(bits) {
  return async function verify(thing, signature, secret) {
    const computedSig = await createHmacSigner(bits)(thing, secret);
    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig));
  };
}

function createKeySigner(bits) {
  return async function sign(thingIn, privateKey) {
    const thing = normalizeInput(thingIn);

    if (isGoogleKmsKey(privateKey)) {
      return signWithGoogleKms(bits, privateKey, thing);
    }
    checkIsPrivateKey(privateKey);
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = crypto.createSign(`RSA-SHA${bits}`);
    const sig = (signer.update(thing), signer.sign(privateKey, 'base64'));
    return fromBase64(sig);
  };
}

function createKeyVerifier(bits) {
  return async function verify(thingIn, signatureIn, publicKeyIn) {
    const publicKey = await convertToPublicKey(publicKeyIn);
    checkIsPublicKey(publicKey);
    const thing = normalizeInput(thingIn);
    const signature = toBase64(signatureIn);
    const verifier = crypto.createVerify(`RSA-SHA${bits}`);
    verifier.update(thing);
    return verifier.verify(publicKey, signature, 'base64');
  };
}

function createPSSKeySigner(bits) {
  return async function sign(thingIn, privateKey) {
    const thing = normalizeInput(thingIn);

    if (isGoogleKmsKey(privateKey)) {
      return signWithGoogleKms(bits, privateKey, thing);
    }
    checkIsPrivateKey(privateKey);
    const signer = crypto.createSign(`RSA-SHA${bits}`);
    const sig = (signer.update(thing), signer.sign({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, 'base64'));
    return fromBase64(sig);
  };
}

function createPSSKeyVerifier(bits) {
  return async function verify(thingIn, signatureIn, publicKeyIn) {
    const publicKey = await convertToPublicKey(publicKeyIn);
    checkIsPublicKey(publicKey);
    const thing = normalizeInput(thingIn);
    const signature = toBase64(signatureIn);
    const verifier = crypto.createVerify(`RSA-SHA${bits}`);
    verifier.update(thing);
    return verifier.verify({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature, 'base64');
  };
}

function createECDSASigner(bits) {
  const inner = createKeySigner(bits);
  return async function sign(...args) {
    const signed = await inner(...args);
    const signature = formatEcdsa.derToJose(signed, `ES${bits}`);
    return signature;
  };
}

function createECDSAVerifer(bits) {
  const inner = createKeyVerifier(bits);
  return async function verify(thing, signatureIn, publicKey) {
    const signature = formatEcdsa.joseToDer(signatureIn, `ES${bits}`).toString('base64');
    const result = await inner(thing, signature, publicKey);
    return result;
  };
}

function createNoneSigner() {
  return async function sign() {
    return '';
  };
}

function createNoneVerifier() {
  return async function verify(thing, signature) {
    return signature === '';
  };
}

module.exports = function jwa(algorithm) {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner,
  };
  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier,
  };
  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/);
  if (!match) { throw typeError(MSG_INVALID_ALGORITHM, algorithm); }
  const algo = (match[1] || match[3]).toLowerCase();
  const bits = match[2];

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  };
};
