/**
 * Posts the enclave fleet's autoscaling events to Slack.
 *
 * Runs as a Lambda behind an EventBridge rule on `aws.autoscaling` events for
 * one group (configure-scaling-alerts.sh). Before this, scaling left a trace
 * only in the group's activity history: the 2026-09-18 health-replacement loop
 * and the 2026-09-23 ratchet to five boxes were both found after the fact.
 *
 * What is posted, and what is not:
 *   - scale out / scale in by a policy        -> one line each, with the size change
 *   - a box replaced after failing its health check -> a warning (a loop shows as
 *     one warning every few minutes, which is the thing worth noticing)
 *   - any launch or termination that FAILED   -> a loud line with AWS's reason
 *   - instance-refresh launches and terminations that succeed -> nothing: every
 *     cutover, certificate renewal and fleet refresh rolls the fleet on purpose,
 *     and its own workflow already reports the outcome
 *   - the replacement LAUNCH after a health failure -> nothing; the termination
 *     warning already says a replacement is coming, and a failed replacement
 *     launch is posted as a failure
 *
 * The webhook is read from SSM at runtime (WEBHOOK_PARAM), outside the
 * `/ppq-enclave/` path on purpose: the enclave host role may read everything
 * under that prefix, and the hosts are untrusted by design. An unset or
 * malformed webhook turns posting off with a log line; it never fails the
 * invocation, so the pipeline can be deployed before the secret exists.
 *
 * Tests: `node --test scripts/fleet/scaling-alerts/index.test.mjs` (no dependencies).
 */
// Slack's two incoming-webhook shapes, as horse-power's enclaveAlerts.ts accepts them.
export const SLACK_WEBHOOK = /^https:\/\/hooks\.slack\.com\/(?:services\/)?[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$/;
const MAX_REASON = 300;

const clip = (s, n = MAX_REASON) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

/** "…changing the desired capacity from 2 to 3…" -> { from: 2, to: 3 } */
export function capacityChange(cause) {
  const m = /desired capacity from (\d+) to (\d+)/.exec(String(cause ?? ''));
  return m ? { from: Number(m[1]), to: Number(m[2]) } : null;
}

/**
 * Sort one event into what happened. Pure; the handler only decides whether
 * and where to post the result of `format`.
 */
export function classify(event) {
  const type = String(event?.['detail-type'] ?? '');
  const d = event?.detail ?? {};
  const cause = String(d.Cause ?? '');
  const launch = type.startsWith('EC2 Instance Launch');
  const terminate = type.startsWith('EC2 Instance Terminate');
  const failed = type.endsWith('Unsuccessful');
  if (!launch && !terminate) return { kind: 'ignored' };
  if (failed) return { kind: launch ? 'launch_failed' : 'terminate_failed' };
  if (/instance refresh/i.test(cause)) return { kind: 'refresh' };
  if (/health check|unhealthy/i.test(cause)) return { kind: terminate ? 'health_replaced' : 'health_relaunch' };
  const change = capacityChange(cause);
  if (/triggered policy/i.test(cause) && change) {
    if (change.to > change.from) return { kind: 'scale_out', ...change };
    if (change.to < change.from) return { kind: 'scale_in', ...change };
  }
  return { kind: 'other' };
}

/** The Slack text for one event, or null when the event is not worth a post. */
export function format(event) {
  const d = event?.detail ?? {};
  const id = d.EC2InstanceId || 'an instance';
  const zone = d.Details?.['Availability Zone'];
  const where = zone ? ` in ${zone}` : '';
  const c = classify(event);
  switch (c.kind) {
    case 'scale_out':
      return `:arrow_up_small: *Enclave fleet scaled out*: ${c.from} → ${c.to} boxes, load per box above target. Launched ${id}${where}.`;
    case 'scale_in':
      return `:arrow_down_small: *Enclave fleet scaled in*: ${c.from} → ${c.to} boxes. Removed ${id} after draining.`;
    case 'health_replaced':
      return `:warning: *Enclave box replaced*: ${id}${where} failed its load balancer health check; a replacement is launching.`;
    case 'launch_failed': {
      const change = capacityChange(d.Cause);
      const why = change ? ` (desired ${change.from} → ${change.to})` : '';
      return `:rotating_light: *Enclave fleet could not launch a box*${why}: ${clip(d.StatusMessage || d.Description)}`;
    }
    case 'terminate_failed':
      return `:rotating_light: *Enclave fleet could not remove ${id}*: ${clip(d.StatusMessage || d.Description)}`;
    case 'other':
      return `:information_source: *Enclave fleet*: ${clip(d.Description)}. ${clip(d.Cause, 200)}`;
    default:
      return null; // refresh, health_relaunch, ignored
  }
}

/** A manual `{"ppqTest": true}` invocation posts a connectivity check. */
export const TEST_TEXT = ':white_check_mark: *Enclave fleet scaling alerts are connected* (test message; no scaling happened).';

export function createHandler({ getWebhook, post, group, log = console }) {
  return async function handler(event) {
    const isTest = event?.ppqTest === true;
    if (!isTest && group && event?.detail?.AutoScalingGroupName !== group) {
      return { posted: false, reason: 'other group' };
    }
    const text = isTest ? TEST_TEXT : format(event);
    if (!text) return { posted: false, reason: classify(event).kind };
    const url = await getWebhook();
    if (!url) {
      log.warn('scaling alert not posted: webhook unset or not a Slack incoming-webhook URL');
      return { posted: false, reason: 'no webhook' };
    }
    const status = await post(url, text);
    if (status >= 500) throw new Error(`Slack returned ${status}`); // let Lambda retry
    if (status >= 400) log.warn(`Slack rejected the alert with ${status}; not retrying`);
    return { posted: status < 400, status };
  };
}

let cached; // per warm container: the webhook rarely changes, and a redeploy clears it
async function webhookFromSsm() {
  if (cached !== undefined) return cached;
  // Imported here, not at the top: the SDK ships in the Lambda runtime but not
  // in this repo, and a top-level import would make the module untestable.
  const { SSMClient, GetParameterCommand } = await import('@aws-sdk/client-ssm');
  try {
    const out = await new SSMClient({}).send(new GetParameterCommand({ Name: process.env.WEBHOOK_PARAM, WithDecryption: true }));
    const url = out.Parameter?.Value?.trim() ?? '';
    cached = SLACK_WEBHOOK.test(url) ? url : null;
  } catch (err) {
    if (err?.name !== 'ParameterNotFound') throw err;
    cached = null;
  }
  return cached;
}

async function postToSlack(url, text) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(5_000),
  });
  return res.status;
}

export const handler = createHandler({
  getWebhook: webhookFromSsm,
  post: postToSlack,
  group: process.env.ASG_NAME,
});
