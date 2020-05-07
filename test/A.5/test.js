/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.5
 */

const fs = require('fs');
const path = require('path');

const test = require('tap').test;

const jwa = require('../../');

const input = fs.readFileSync(path.join(__dirname, 'input.txt'));

const algo = jwa('none');

test('A.5', async function (t) {
	t.plan(2);

	t.equal(await algo.sign(input), '');
	t.ok(await algo.verify(input, ''));
})
