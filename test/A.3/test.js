/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.3
 */

const fs = require('fs');
const path = require('path');

const Buffer = require('safe-buffer').Buffer;
const jwkToPem = require('jwk-to-pem');
const test = require('tap').test;

const jwa = require('../../');

const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));

const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'));
const pubKey = jwkToPem(jwk);

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');

const algo = jwa('ES256');

test('A.3', async function (t) {
	t.plan(3);

	t.equivalent(input, inputFromBytes);

	t.ok(await algo.verify(input, signature, pubKey));
	t.ok(await algo.verify(input.toString('ascii'), signature, pubKey));
})
