const crypto = require('crypto');
const path = require('path');
const base64url = require('base64url');
const formatEcdsa = require('ecdsa-sig-formatter');
const spawn = require('child_process').spawn;
const Buffer = require('safe-buffer').Buffer;
const semver = require('semver');
const fs = require('fs');
const test = require('tap').test;
const jwa = require('..');

const nodeVersion = semver.clean(process.version);
const SUPPORTS_KEY_OBJECTS = typeof crypto.createPublicKey === 'function';

// these key files will be generated as part of `make test`
const rsaPrivateKey = fs.readFileSync(__dirname + '/rsa-private.pem').toString();
const rsaPublicKey = fs.readFileSync(__dirname + '/rsa-public.pem').toString();
const rsaPrivateKeyWithPassphrase = fs.readFileSync(__dirname + '/rsa-passphrase-private.pem').toString();
const rsaPublicKeyWithPassphrase = fs.readFileSync(__dirname + '/rsa-passphrase-public.pem').toString();
const rsaWrongPublicKey = fs.readFileSync(__dirname + '/rsa-wrong-public.pem').toString();
const ecdsaPrivateKey = {
  '256': fs.readFileSync(__dirname + '/ec256-private.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-private.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-private.pem').toString(),
};
const ecdsaPublicKey = {
  '256': fs.readFileSync(__dirname + '/ec256-public.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-public.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-public.pem').toString(),
};
const ecdsaWrongPublicKey = {
  '256': fs.readFileSync(__dirname + '/ec256-wrong-public.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-wrong-public.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-wrong-public.pem').toString(),
};
const googleKmsPrivateKey = { 
  projectId: 'apimetrics-qc', 
  locationId: 'us-central1', 
  keyRingId: 'google-kms-node-jwa', 
  keyId: 'rsa-private', 
  versionId: '4'
};

const BIT_DEPTHS = ['256', '384', '512'];

test('HMAC signing, verifying', async function (t) {
  const input = 'eugene mirman';
  const secret = 'shhhhhhhhhh';
  const promises = BIT_DEPTHS.map(async function (bits) {
    const algo = jwa('HS'+bits);
    const sig = await algo.sign(input, secret);
    t.ok(await algo.verify(input, sig, secret), 'should verify');
    t.notOk(await algo.verify(input, 'other sig', secret), 'should verify');
    t.notOk(await algo.verify(input, sig, 'incrorect'), 'shoud not verify');
  });
  await Promise.all(promises);
  t.end();
});

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    const input = 'foo bar baz';
    const secret = 'this-is-a-bad-secret';
    const secretBuf = Buffer.from(secret, 'utf8');
    const secretObj = crypto.createSecretKey(secretBuf);

    test('HS' + bits + 'signing, verifying (w/ KeyObject)', async function (t) {
      const algo = jwa('HS' + bits);

      const sigs = [
        await algo.sign(input, secret),
        await algo.sign(input, secretBuf),
        await algo.sign(input, secretObj)
      ];

      for (var i = 0; i < sigs.length; ++i) {
        t.ok(await algo.verify(input, sigs[i], secret));
        t.ok(await algo.verify(input, sigs[i], secretBuf));
        t.ok(await algo.verify(input, sigs[i], secretObj));
      }

      t.end();
    });
  });
}

test('RSA signing, verifying', async function (t) {
  const input = 'h. jon benjamin';
  const promises = BIT_DEPTHS.map(async function (bits) {
    const algo = jwa('RS'+bits);
    const sig = await algo.sign(input, rsaPrivateKey);
    t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
    t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
  });
  await Promise.all(promises);
  t.end();
});

// run only on nodejs version >= 0.11.8
if (semver.gte(nodeVersion, '0.11.8')) {
  test('RSA with passphrase signing, verifying', async function (t) {
  const input = 'test input';
  const promises = BIT_DEPTHS.map(async function (bits) {
    const algo = jwa('RS'+bits);
    const secret = 'test_pass';
    const sig = await algo.sign(input, {key: rsaPrivateKeyWithPassphrase, passphrase: secret});
    t.ok(await algo.verify(input, sig, rsaPublicKeyWithPassphrase), 'should verify');
  });
  await Promise.all(promises);
  t.end();
  });
}

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    test('RS'+bits+': signing, verifying (KeyObject)', async function (t) {
      const input = 'h. jon benjamin';
      const algo = jwa('RS'+bits);
      const sig = await algo.sign(input, crypto.createPrivateKey(rsaPrivateKey));
      t.ok(await algo.verify(input, sig, crypto.createPublicKey(rsaPublicKey)), 'should verify');
      t.notOk(await algo.verify(input, sig, crypto.createPublicKey(rsaWrongPublicKey)), 'shoud not verify');
      t.end();
    });
  });
}


if (semver.satisfies(nodeVersion, '^6.12.0 || >=8.0.0')) {
  test('RSA-PSS signing, verifying', async function (t) {
    const input = 'h. jon benjamin';
    const promises = BIT_DEPTHS.map(async function (bits) {
      const algo = jwa('PS'+bits);
      const sig = await algo.sign(input, rsaPrivateKey);
      t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
      t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
    });
    await Promise.all(promises);
    t.end();
  });

  if (SUPPORTS_KEY_OBJECTS) {
    BIT_DEPTHS.forEach(function (bits) {
      test('PS'+bits+': signing, verifying (KeyObject)', async function (t) {
        const input = 'h. jon benjamin';
        const algo = jwa('PS'+bits);
        const sig = await algo.sign(input, crypto.createPrivateKey(rsaPrivateKey));
        t.ok(await algo.verify(input, sig, crypto.createPublicKey(rsaPublicKey)), 'should verify');
        t.notOk(await algo.verify(input, sig, crypto.createPublicKey(rsaWrongPublicKey)), 'should not verify');
        t.end();
      });
    });
  }
}


// BIT_DEPTHS.forEach(function (bits) {
//   test('RS'+bits+': openssl sign -> js verify', function (t) {
//     const input = 'iodine';
//     const algo = jwa('RS'+bits);
//     const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sign', __dirname + '/rsa-private.pem']);
//     var buffer = Buffer.alloc(0);

//     dgst.stdout.on('data', function (buf) {
//       buffer = Buffer.concat([buffer, buf]);
//     });

//     dgst.stdin.write(input, function() {
//       dgst.stdin.end();
//     });

//     dgst.on('exit', async function (code) {
//       if (code !== 0)
//         return t.fail('could not test interop: openssl failure');
//       const sig = base64url(buffer);

//       t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
//       t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'should not verify');
//       t.end();
//     });
//   });
// });

// if (semver.satisfies(nodeVersion, '^6.12.0 || >=8.0.0')) {
//   BIT_DEPTHS.forEach(function (bits) {
//     test('PS'+bits+': openssl sign -> js verify', function (t) {
//       const input = 'iodine';
//       const algo = jwa('PS'+bits);
//       const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-1', '-sign', __dirname + '/rsa-private.pem']);
//       var buffer = Buffer.alloc(0);

//       dgst.stdout.on('data', function (buf) {
//         buffer = Buffer.concat([buffer, buf]);
//       });

//       dgst.stdin.write(input, function() {
//         dgst.stdin.end();
//       });

//       dgst.on('exit', async function (code) {
//         if (code !== 0)
//           return t.fail('could not test interop: openssl failure');
//         const sig = base64url(buffer);

//         t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
//         t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'should not verify');
//         t.end();
//       });
//     });
//   });
// }

BIT_DEPTHS.forEach(function (bits) {
  test('ES'+bits+': signing, verifying', async function (t) {
    const input = 'kristen schaal';
    const algo = jwa('ES'+bits);
    const sig = await algo.sign(input, ecdsaPrivateKey[bits]);
    t.ok(await algo.verify(input, sig, ecdsaPublicKey[bits]), 'should verify');
    t.notOk(await algo.verify(input, sig, ecdsaWrongPublicKey[bits]), 'should not verify');
    t.end();
  });
});

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    test('ES'+bits+': signing, verifying (KeyObject)', async function (t) {
      const input = 'kristen schaal';
      const algo = jwa('ES'+bits);
      const sig = await algo.sign(input, crypto.createPrivateKey(ecdsaPrivateKey[bits]));
      t.ok(await algo.verify(input, sig, crypto.createPublicKey(ecdsaPublicKey[bits])), 'should verify');
      t.notOk(await algo.verify(input, sig, crypto.createPublicKey(ecdsaWrongPublicKey[bits])), 'should not verify');
      t.end();
    });
  });
}

// BIT_DEPTHS.forEach(function (bits) {
//   test('ES'+bits+': openssl sign -> js verify', function (t) {
//     const input = 'strawberry';
//     const algo = jwa('ES'+bits);
//     const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sign', __dirname + '/ec'+bits+'-private.pem']);
//     var buffer = Buffer.alloc(0);
//     dgst.stdin.end(input);
//     dgst.stdout.on('data', function (buf) {
//       buffer = Buffer.concat([buffer, buf]);
//     });
//     dgst.on('exit', async function (code) {
//       if (code !== 0)
//         return t.fail('could not test interop: openssl failure');
//       const sig = formatEcdsa.derToJose(buffer, 'ES' + bits);
//       t.ok(await algo.verify(input, sig, ecdsaPublicKey[bits]), 'should verify');
//       t.notOk(await algo.verify(input, sig, ecdsaWrongPublicKey[bits]), 'should not verify');
//       t.end();
//     });
//   });
// });

// BIT_DEPTHS.forEach(function (bits) {
//   const input = 'bob\'s';
//   const inputFile = path.join(__dirname, 'interop.input.txt');
//   const signatureFile = path.join(__dirname, 'interop.sig.txt');

//   function opensslVerify(keyfile) {
//     return spawn('openssl', [
//       'dgst',
//       '-sha'+bits,
//       '-verify', keyfile,
//       '-signature', signatureFile,
//       inputFile
//     ]);
//   }

//   test('ES'+bits+': js sign -> openssl verify', async function (t) {
//     const publicKeyFile = path.join(__dirname, 'ec'+bits+'-public.pem');
//     const wrongPublicKeyFile = path.join(__dirname, 'ec'+bits+'-wrong-public.pem');
//     const privateKey = ecdsaPrivateKey[bits];
//     const signature =
//       formatEcdsa.joseToDer(
//         await jwa('ES'+bits).sign(input, privateKey),
//         'ES' + bits
//       );
//     fs.writeFileSync(inputFile, input);
//     fs.writeFileSync(signatureFile, signature);

//     t.plan(2);
//     opensslVerify(publicKeyFile).on('exit', function (code) {
//       t.same(code, 0, 'should be a successful exit');
//     });
//     opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
//       t.same(code, 1, 'should be invalid');
//     });
//   });
// });

// BIT_DEPTHS.forEach(function (bits) {
//   const input = 'burgers';
//   const inputFile = path.join(__dirname, 'interop.input.txt');
//   const signatureFile = path.join(__dirname, 'interop.sig.txt');

//   function opensslVerify(keyfile) {
//     return spawn('openssl', [
//       'dgst',
//       '-sha'+bits,
//       '-verify', keyfile,
//       '-signature', signatureFile,
//       inputFile
//     ]);
//   }

//   test('RS'+bits+': js sign -> openssl verify', async function (t) {
//     const publicKeyFile = path.join(__dirname, 'rsa-public.pem');
//     const wrongPublicKeyFile = path.join(__dirname, 'rsa-wrong-public.pem');
//     const privateKey = rsaPrivateKey;
//     const signature =
//       base64url.toBuffer(
//         await jwa('RS'+bits).sign(input, privateKey)
//       );
//     fs.writeFileSync(signatureFile, signature);
//     fs.writeFileSync(inputFile, input);

//     t.plan(2);
//     opensslVerify(publicKeyFile).on('exit', function (code) {
//       t.same(code, 0, 'should be a successful exit');
//     });
//     opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
//       t.same(code, 1, 'should be invalid');
//     });
//   });
// });

// if (semver.satisfies(nodeVersion, '^6.12.0 || >=8.0.0')) {
//   BIT_DEPTHS.forEach(function (bits) {
//     const input = 'burgers';
//     const inputFile = path.join(__dirname, 'interop.input.txt');
//     const signatureFile = path.join(__dirname, 'interop.sig.txt');

//     function opensslVerify(keyfile) {
//       return spawn('openssl', [
//         'dgst',
//         '-sha'+bits,
//         '-sigopt', 'rsa_padding_mode:pss',
//         '-verify', keyfile,
//         '-signature', signatureFile,
//         inputFile
//       ]);
//     }

//     test('PS'+bits+': js sign -> openssl verify', async function (t) {
//       const publicKeyFile = path.join(__dirname, 'rsa-public.pem');
//       const wrongPublicKeyFile = path.join(__dirname, 'rsa-wrong-public.pem');
//       const privateKey = rsaPrivateKey;
//       const signature =
//         base64url.toBuffer(
//           await jwa('PS'+bits).sign(input, privateKey)
//         );
//       fs.writeFileSync(signatureFile, signature);
//       fs.writeFileSync(inputFile, input);

//       t.plan(2);
//       opensslVerify(publicKeyFile).on('exit', function (code) {
//         t.same(code, 0, 'should be a successful exit');
//       });
//       opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
//         t.same(code, 1, 'should be invalid');
//       });
//     });
//   });
// }


test('jwa: none', async function (t) {
  const input = 'whatever';
  const algo = jwa('none');
  const sig = await algo.sign(input);
  t.ok(await algo.verify(input, sig), 'should verify');
  t.notOk(await algo.verify(input, 'something'), 'shoud not verify');
  t.end();
});

test('jwa: some garbage algorithm', function (t) {
  try {
    jwa('something bogus');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms');
  }
  t.end();
});

['hs256', 'nonE', 'ps256', 'es256', 'rs256'].forEach(function (alg) {
  test('jwa: non-IANA names', function (t) {
    try {
      jwa(alg);
      t.fail('should throw');
    } catch(ex) {
      t.same(ex.name, 'TypeError');
      t.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms');
    }
    t.end();
  });
});

['ahs256b', 'anoneb', 'none256', 'rsnone'].forEach(function (superstringAlg) {
  test('jwa: superstrings of other algorithms', function (t) {
    try {
      jwa(superstringAlg);
      t.fail('should throw');
    } catch(ex) {
      t.same(ex.name, 'TypeError');
      t.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms');
    }
    t.end();
  });
});

['rs', 'ps', 'es', 'hs'].forEach(function (partialAlg) {
  test('jwa: partial strings of other algorithms', function (t) {
    try {
      jwa(partialAlg);
      t.fail('should throw');
    } catch(ex) {
      t.same(ex.name, 'TypeError');
      t.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms');
    }
    t.end();
  });
});

test('jwa: hs512, missing secret', async function (t) {
  const algo = jwa('HS512');
  try {
    await algo.sign('some stuff');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/secret/), 'should say something about secrets');
  }
  t.end();
});

test('jwa: hs512, weird input type', async function (t) {
  const algo = jwa('HS512');
  const input = {a: ['whatever', 'this', 'is']};
  const secret = 'bones';
  const sig = await algo.sign(input, secret);
  t.ok(await algo.verify(input, sig, secret), 'should verify');
  t.notOk(await algo.verify(input, sig, 'other thing'), 'should not verify');
  t.end();
});

test('jwa: rs512, weird input type', async function (t) {
  const algo = jwa('RS512');
  const input = {a: ['whatever', 'this', 'is']};
  const sig = await algo.sign(input, rsaPrivateKey);
  t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
  t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'should not verify');
  t.end();
});

test('jwa: rs512, missing signing key', async function (t) {
  const algo = jwa('RS512');
  try {
    await algo.sign('some stuff');
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/key/), 'should say something about keys');
  }
  t.end();
});

test('jwa: rs512, missing verifying key', async function (t) {
  const algo = jwa('RS512');
  const input = {a: ['whatever', 'this', 'is']};
  const sig = await algo.sign(input, rsaPrivateKey);
  try {
    await algo.verify(input, sig)
    t.fail('should throw');
  } catch(ex) {
    t.same(ex.name, 'TypeError');
    t.ok(ex.message.match(/key/), 'should say something about keys');
  }
  t.end();
});

if (semver.satisfies(nodeVersion, '^6.12.0 || >=8.0.0')) {
  test('jwa: ps512, weird input type', async function (t) {
    const algo = jwa('PS512');
    const input = {a: ['whatever', 'this', 'is']};
    const sig = await algo.sign(input, rsaPrivateKey);
    t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
    t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'should not verify');
    t.end();
  });

  test('jwa: ps512, missing signing key', async function (t) {
    const algo = jwa('PS512');
    try {
      await algo.sign('some stuff');
      t.fail('should throw');
    } catch(ex) {
      t.same(ex.name, 'TypeError');
      t.ok(ex.message.match(/key/), 'should say something about keys');
    }
    t.end();
  });

  test('jwa: ps512, missing verifying key', async function (t) {
    const algo = jwa('PS512');
    const input = {a: ['whatever', 'this', 'is']};
    const sig = await algo.sign(input, rsaPrivateKey);
    try {
      await algo.verify(input, sig);
      t.fail('should throw');
    } catch(ex) {
      t.same(ex.name, 'TypeError');
      t.ok(ex.message.match(/key/), 'should say something about keys');
    }
    t.end();
  });
}

if (semver.satisfies(nodeVersion, '^6.12.0 || >=8.0.0')) {
  test('RSA-PSS signing, Google KMS key, verifying', async function (t) {
    const input = 'h. jon benjamin';
    const promises = [256].map(async function (bits) {
      const algo = jwa('PS'+bits);
      const sig = await algo.sign(input, googleKmsPrivateKey);
      t.ok(await algo.verify(input, sig, googleKmsPrivateKey), 'should verify');
      t.ok(await algo.verify(input, sig, rsaPublicKey), 'should verify');
      t.notOk(await algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify');
    });
    await Promise.all(promises);
    t.end();
  });
}