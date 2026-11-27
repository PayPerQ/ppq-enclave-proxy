// A relayed stream as the upstream sent it: the routing receipt's two comment
// events set aside, so a test can compare the frames and read the receipt.
import { RECEIPT_PREFIX, RECEIPT_SIG_PREFIX } from '../src/receipt.mjs';

/** `{ body, receiptJson, sig }`: `body` is `text` without the receipt events. */
export function splitReceipt(text) {
  let receiptJson = null;
  let sig = null;
  const events = String(text).split('\n\n');
  const kept = events.filter((event) => {
    if (event.startsWith(RECEIPT_PREFIX)) {
      receiptJson = event.slice(RECEIPT_PREFIX.length);
      return false;
    }
    if (event.startsWith(RECEIPT_SIG_PREFIX)) {
      sig = JSON.parse(event.slice(RECEIPT_SIG_PREFIX.length));
      return false;
    }
    return true;
  });
  return { body: kept.join('\n\n'), receiptJson, sig };
}
