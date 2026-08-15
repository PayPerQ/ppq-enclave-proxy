import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signRequest, deriveSigningKey, amzTimestamps } from '../src/sigv4.mjs';

// The example credentials AWS uses across its SigV4 documentation.
const DOC_CREDS = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
};
const DOC_NOW = new Date('2015-08-30T12:36:00Z');

test('amzTimestamps formats the SigV4 date pair', () => {
  assert.deepEqual(amzTimestamps(DOC_NOW), {
    amzDate: '20150830T123600Z',
    dateStamp: '20150830',
  });
});

test('deriveSigningKey matches the AWS documentation example', () => {
  // "Deriving the signing key" example from the AWS General Reference.
  const key = deriveSigningKey(DOC_CREDS.secretAccessKey, '20150830', 'us-east-1', 'iam');
  assert.equal(
    key.toString('hex'),
    'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
  );
});

test('signRequest reproduces the AWS docs IAM ListUsers example signature', () => {
  // The complete worked GET example from "Signature Version 4 signing process".
  const out = signRequest({
    method: 'GET',
    host: 'iam.amazonaws.com',
    path: '/',
    query: 'Action=ListUsers&Version=2010-05-08',
    body: '',
    signHeaders: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    region: 'us-east-1',
    service: 'iam',
    creds: DOC_CREDS,
    now: DOC_NOW,
  });
  assert.equal(
    out.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, ' +
      'SignedHeaders=content-type;host;x-amz-date, ' +
      'Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
  );
  assert.equal(out['x-amz-date'], '20150830T123600Z');
  assert.equal(out['x-amz-security-token'], undefined);
});

test('a session token is sent AND signed (STS creds are the Bedrock case)', () => {
  const out = signRequest({
    method: 'POST',
    host: 'bedrock-runtime.us-east-2.amazonaws.com',
    path: '/model/us.openai.gpt-5.5-v1%3A0/converse-stream',
    body: '{"messages":[]}',
    signHeaders: { 'content-type': 'application/json' },
    region: 'us-east-2',
    creds: { ...DOC_CREDS, sessionToken: 'FwoGZXIvYXdzEXAMPLETOKEN' },
    now: DOC_NOW,
  });
  assert.equal(out['x-amz-security-token'], 'FwoGZXIvYXdzEXAMPLETOKEN');
  assert.match(
    out.authorization,
    /SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, /,
  );
  assert.match(out.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-2\/bedrock\/aws4_request, /);
});

test('signature is a pure function of (request, creds, clock)', () => {
  const args = {
    method: 'POST',
    host: 'bedrock-runtime.us-east-2.amazonaws.com',
    path: '/model/us.openai.gpt-5.5-v1%3A0/converse-stream',
    body: '{"messages":[{"role":"user","content":[{"text":"hi"}]}]}',
    signHeaders: { 'content-type': 'application/json' },
    region: 'us-east-2',
    creds: DOC_CREDS,
    now: DOC_NOW,
  };
  assert.deepEqual(signRequest(args), signRequest(args));
});

test('golden: the full mantle-shaped signature is pinned exactly', () => {
  // Pins the ENTIRE construction (canonical URI form included) for the real
  // request shape this signer exists for, not just inequality between two
  // encodings (CodeRabbit, PR #17). The base construction is proven against
  // AWS's published doc vectors above; this golden freezes it against
  // regressions — any change to header set, encoding, or scope moves it.
  const out = signRequest({
    method: 'POST',
    host: 'bedrock-mantle.us-east-2.api.aws',
    path: '/openai/v1/responses',
    body: '{"model":"openai.gpt-5.5","input":[],"stream":true,"store":false}',
    signHeaders: { 'content-type': 'application/json' },
    region: 'us-east-2',
    service: 'bedrock-mantle',
    creds: { ...DOC_CREDS, sessionToken: 'FwoEXAMPLETOKEN' },
    now: new Date('2026-08-14T12:00:00Z'),
  });
  assert.equal(
    out.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260814/us-east-2/bedrock-mantle/aws4_request, ' +
      'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, ' +
      'Signature=b36f6f62c8399979e6896ad6d0b46a376bb80260321ac7bf6144a45c63894c93',
  );
});

test('the canonical URI is double-encoded (the %3A → %253A Bedrock gotcha)', () => {
  // The wire path is single-encoded; SigV4 signs the DOUBLE-encoded form for
  // non-S3 services. If the implementation ever signed the wire path verbatim,
  // these two would collide: a path whose literal bytes are the double-encoded
  // form must produce a DIFFERENT signature than the single-encoded path,
  // proving the signer re-encodes rather than passing through.
  const base = {
    method: 'POST',
    host: 'bedrock-runtime.us-east-2.amazonaws.com',
    body: '{}',
    region: 'us-east-2',
    creds: DOC_CREDS,
    now: DOC_NOW,
  };
  const single = signRequest({ ...base, path: '/model/us.openai.gpt-5.5-v1%3A0/converse-stream' });
  const double = signRequest({ ...base, path: '/model/us.openai.gpt-5.5-v1%253A0/converse-stream' });
  assert.notEqual(single.authorization, double.authorization);
});
