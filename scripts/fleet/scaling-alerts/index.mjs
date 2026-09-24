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
 * Which check failed. The group uses load-balancer health checks, but Auto
 * Scaling also replaces a box whose EC2 status checks fail, and naming the wrong
 * one sends whoever reads the alert to the wrong place.
 */
export function healthCheckName(cause) {
  const c = String(cause ?? '');
  if (/\bELB\b|load balancer/i.test(c)) return 'its load balancer health check';
  if (/\bEC2\b/.test(c)) return 'its EC2 health check';
  return 'a health check';
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
  // Load-balancer failures say "health check"; EC2 ones say "status checks";
  // the replacement launch says "unhealthy instance".
  if (/health check|status check|unhealthy/i.test(cause)) return { kind: terminate ? 'health_replaced' : 'health_relaunch' };
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
      return `:warning: *Enclave box replaced*: ${id}${where} failed ${healthCheckName(d.Cause)}; a replacement is launching.`;
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
    // 429 (rate limited) and 5xx are transient: throw, and Lambda's async retry
    // redelivers after a minute or more, longer than Slack's Retry-After. Other
    // 4xx mean the webhook is wrong, so retrying would only repeat the failure.
    if (status === 429 || status >= 500) throw new Error(`Slack returned ${status}`);
    if (status >= 400) log.warn(`Slack rejected the alert with ${status}; not retrying`);
    return { posted: status < 400, status };
  };
}

/**
 * A webhook getter that caches ONLY a valid URL. A missing or malformed value
 * is re-read on the next event: Lambda keeps module state across warm
 * invocations, so caching the absence would keep alerts off in that container
 * after the secret is stored, the exact order in which this gets set up.
 * Scaling events are rare, so re-reading SSM while it is unset costs nothing.
 */
export function createWebhookGetter(readParam) {
  let url = null;
  return async () => {
    if (url) return url;
    const value = String((await readParam()) ?? '').trim();
    if (SLACK_WEBHOOK.test(value)) url = value;
    return url;
  };
}

async function readWebhookParam() {
  // Imported here, not at the top: the SDK ships in the Lambda runtime but not
  // in this repo, and a top-level import would make the module untestable.
  const { SSMClient, GetParameterCommand } = await import('@aws-sdk/client-ssm');
  try {
    const out = await new SSMClient({}).send(new GetParameterCommand({ Name: process.env.WEBHOOK_PARAM, WithDecryption: true }));
    return out.Parameter?.Value;
  } catch (err) {
    if (err?.name === 'ParameterNotFound') return null;
    throw err;
  }
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
  getWebhook: createWebhookGetter(readWebhookParam),
  post: postToSlack,
  group: process.env.ASG_NAME,
});
