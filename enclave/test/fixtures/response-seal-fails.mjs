// Preloaded (`node --import`) into a server under test: every EHBP response
// encryptor fails, so a sealed request is opened normally and its answer then
// cannot be sealed back. Requests without EHBP are untouched.
import { EhbpRecipient } from '../../src/ehbp-server.mjs';

EhbpRecipient.prototype.responseEncryptor = async function responseEncryptor() {
  throw new Error('injected: response sealing fails');
};
