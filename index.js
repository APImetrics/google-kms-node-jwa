var bufferEqual = require('buffer-equal-constant-time');
var Buffer = require('safe-buffer').Buffer;
var crypto = require('crypto');
var formatEcdsa = require('ecdsa-sig-formatter');
var util = require('util');
// Imports the Cloud KMS library
const {KeyManagementServiceClient} = require('@google-cloud/kms');

const KMS_CLIENT = new KeyManagementServiceClient();

var MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "RS256", "RS384", "PS256", "PS384",  "ES256", "ES384", and "none".'
var MSG_INVALID_SECRET = 'secret must be a string or buffer';
var MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer';
var MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object';

var supportsKeyObjects = typeof crypto.createPublicKey === 'function';
if (supportsKeyObjects) {
  MSG_INVALID_VERIFIER_KEY += ' or a KeyObject';
  MSG_INVALID_SECRET += 'or a KeyObject';
}

async function convertToPublicKey (key)
{
  if (Buffer.isBuffer(key)) {
    return key;
  }

  if (typeof key === 'string') {
    return key;
  }
  
  if (key.projectId) {
    const {
      projectId,
      locationId,
      keyRingId,
      keyId,
      versionId
    } = key;

    // Build the version name
    const versionName = KMS_CLIENT.cryptoKeyVersionPath(
      projectId,
      locationId,
      keyRingId,
      keyId,
      versionId
    );

    const [publicKey] = await KMS_CLIENT.getPublicKey({
      name: versionName,
    });

    return publicKey.pem;
  }
  return key;
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
};

function checkIsPrivateKey(key) {
  if (typeof key === 'object') {
    const {
      projectId,
      locationId,
      keyRingId,
      keyId,
      versionId
    } = key;
    if (projectId && locationId && keyRingId && keyId && versionId) {
      return;
    }
  }
  throw typeError(MSG_INVALID_SIGNER_KEY);
};

function checkIsSecretKey(key) {
  if (Buffer.isBuffer(key)) {
    return;
  }

  if (typeof key === 'string') {
    return key;
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
  base64url = base64url.toString();

  var padding = 4 - base64url.length % 4;
  if (padding !== 4) {
    for (var i = 0; i < padding; ++i) {
      base64url += '=';
    }
  }

  return base64url
    .replace(/\-/g, '+')
    .replace(/_/g, '/');
}

function typeError(template) {
  var args = [].slice.call(arguments, 1);
  var errMsg = util.format.bind(util, template).apply(null, args);
  return new TypeError(errMsg);
}

function bufferOrString(obj) {
  return Buffer.isBuffer(obj) || typeof obj === 'string';
}

function normalizeInput(thing) {
  if (!bufferOrString(thing))
    thing = JSON.stringify(thing);
  return thing;
}

// function createHmacSigner(bits) {
//   return function sign(thing, secret) {
//     checkIsSecretKey(secret);
//     thing = normalizeInput(thing);
//     var hmac = crypto.createHmac('sha' + bits, secret);
//     var sig = (hmac.update(thing), hmac.digest('base64'))
//     return fromBase64(sig);
//   }
// }

// function createHmacVerifier(bits) {
//   return function verify(thing, signature, secret) {
//     var computedSig = createHmacSigner(bits)(thing, secret);
//     return bufferEqual(Buffer.from(signature), Buffer.from(computedSig));
//   }
// }

function createKeySigner(bits) {
 return async function sign(thing, {projectId, locationId, keyRingId, keyId, versionId}) {
    checkIsPrivateKey({projectId, locationId, keyRingId, keyId, versionId});
    thing = normalizeInput(thing);

    const hashScheme = 'sha' + bits;
    const digest = crypto.createHash(hashScheme);
    digest.update(thing);
    const digestBase64 = digest.digest();

    // Build the version name
    const versionName = KMS_CLIENT.cryptoKeyVersionPath(
      projectId,
      locationId,
      keyRingId,
      keyId,
      versionId
    );

    // Sign the message with Cloud KMS
    const [signResponse] = await KMS_CLIENT.asymmetricSign({
      name: versionName,
      digest: {
        [hashScheme]: digestBase64,
      },
    });
    const encoded = signResponse.signature.toString('base64');
    return fromBase64(encoded);
  }
}

function createKeyVerifier(bits) {
  return async function verify(thing, signature, publicKey) {
    publicKey = await convertToPublicKey(publicKey);
    checkIsPublicKey(publicKey);
    thing = normalizeInput(thing);
    signature = toBase64(signature);
    var verifier = crypto.createVerify('RSA-SHA' + bits);
    verifier.update(thing);
    console.log('verifier.verify', publicKey, signature, 'base64');
    return verifier.verify(publicKey, signature, 'base64');
  }
}

// function createPSSKeySigner(bits) {
//   return function sign(thing, privateKey) {
//     checkIsPrivateKey(privateKey);
//     thing = normalizeInput(thing);
//     var signer = crypto.createSign('RSA-SHA' + bits);
//     var sig = (signer.update(thing), signer.sign({
//       key: privateKey,
//       padding: crypto.constants.RSA_PKCS1_PSS_PADDING,      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
//     }, 'base64'));
//     return fromBase64(sig);
//   }
// }

function createPSSKeyVerifier(bits) {
  return async function verify(thing, signature, publicKey) {
    publicKey = await convertToPublicKey(publicKey);
    checkIsPublicKey(publicKey);
    thing = normalizeInput(thing);
    signature = toBase64(signature);
    var verifier = crypto.createVerify('RSA-SHA' + bits);
    verifier.update(thing);
    return verifier.verify({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }, signature, 'base64');
  }
}

function createECDSASigner(bits) {
  var inner = createKeySigner(bits);
  return function sign() {
    var signature = inner.apply(null, arguments);
    signature = formatEcdsa.derToJose(signature, 'ES' + bits);
    return signature;
  };
}

function createECDSAVerifer(bits) {
  var inner = createKeyVerifier(bits);
  return function verify(thing, signature, publicKey) {
    signature = formatEcdsa.joseToDer(signature, 'ES' + bits).toString('base64');
    var result = inner(thing, signature, publicKey);
    return result;
  };
}

function createNoneSigner() {
  return function sign() {
    return '';
  }
}

function createNoneVerifier() {
  return function verify(thing, signature) {
    return signature === '';
  }
}

module.exports = function jwa(algorithm) {
  var signerFactories = {
    // hs: createHmacSigner,
    rs: createKeySigner,
    ps: createKeySigner,
    es: createECDSASigner,
    none: createNoneSigner,
  }
  var verifierFactories = {
    // hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier,
  }
  var match = algorithm.match(/^(RS|PS|ES)(256|384)$|^(none)$/);
  if (!match)
    throw typeError(MSG_INVALID_ALGORITHM, algorithm);
  var algo = (match[1] || match[3]).toLowerCase();
  var bits = match[2];

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  }
};
