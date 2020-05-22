
const crypto = require('crypto');
const { KeyManagementServiceClient } = require('@google-cloud/kms');


const projectId = 'apimetrics-qc';
const locationId = 'us-central1';
const keyRingId = 'google-kms-node-jwa';
const keyId = 'rsa-private';
const versionId = '4';

async function main(
  message = Buffer.from('...')
) {
  // Instantiates a client
  const client = new KeyManagementServiceClient();

  // Build the version name
  const versionName = client.cryptoKeyVersionPath(
    projectId,
    locationId,
    keyRingId,
    keyId,
    versionId
  );
  console.log(versionName);


  const [publicKey] = await client.getPublicKey({
    name: versionName,
  });

  console.log(`Public key pem: ${publicKey.pem}`);

  // Create a digest of the message. The digest needs to match the digest
  // configured for the Cloud KMS key.
  const hashType = 'sha256';
  const digest = crypto.createHash(hashType);
  digest.update(message);
  const hash = digest.digest().toString('base64');
  console.log(hash);

  // Sign the message with Cloud KMS
  const [signResponse] = await client.asymmetricSign({
    name: versionName,
    digest: {
      [hashType]: hash,
    },
  });

  // Example of how to display signature. Because the signature is in a binary
  // format, you need to encode the output before printing it to a console or
  // displaying it on a screen.
  const encoded = signResponse.signature.toString('base64');
  console.log(`Signature: ${encoded}`);

  return signResponse.signature;
}

main(Buffer.from('Hello world')).catch(ex => console.error(ex));