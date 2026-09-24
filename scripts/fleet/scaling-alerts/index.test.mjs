import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, format, capacityChange, createHandler, SLACK_WEBHOOK, TEST_TEXT } from './index.mjs';

// Cause strings are verbatim from ppq-enclave-fleet's activity history.
const ev = (type, detail) => ({
  'detail-type': type,
  source: 'aws.autoscaling',
  detail: { AutoScalingGroupName: 'ppq-enclave-fleet', EC2InstanceId: 'i-0abc', Details: { 'Availability Zone': 'us-east-1b' }, ...detail },
});
const SCALE_OUT = ev('EC2 Instance Launch Successful', { Cause: 'At 2026-09-23T17:10:20Z a monitor alarm TargetTracking-ppq-enclave-fleet-AlarmHigh in state ALARM triggered policy flows-per-box-target changing the desired capacity from 2 to 3.  At 2026-09-23T17:10:32Z an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 2 to 3.', Description: 'Launching a new EC2 instance: i-0abc' });
const SCALE_IN = ev('EC2 Instance Terminate Successful', { Cause: 'At 2026-09-23T17:47:05Z a monitor alarm TargetTracking-ppq-enclave-fleet-AlarmLow in state ALARM triggered policy flows-per-box-target changing the desired capacity from 3 to 2.  At 2026-09-23T17:47:17Z an instance was taken out of service in response to a difference between desired and actual capacity, shrinking the capacity from 3 to 2.', Description: 'Terminating EC2 instance: i-0abc' });
const HEALTH_TERM = ev('EC2 Instance Terminate Successful', { Cause: 'At 2026-09-18T18:26:54Z an instance was taken out of service in response to an ELB system health check failure.', Description: 'Terminating EC2 instance: i-0abc' });
const HEALTH_LAUNCH = ev('EC2 Instance Launch Successful', { Cause: 'At 2026-09-18T18:26:55Z an instance was launched in response to an unhealthy instance needing to be replaced.', Description: 'Launching a new EC2 instance: i-0def' });
const REFRESH_LAUNCH = ev('EC2 Instance Launch Successful', { Cause: 'At 2026-09-23T18:46:00Z an instance was launched in response to an instance refresh.', Description: 'Launching a new EC2 instance: i-0abc' });
const REFRESH_TERM = ev('EC2 Instance Terminate Successful', { Cause: 'At 2026-09-23T18:50:00Z an instance was taken out of service in response to an instance refresh.', Description: 'Terminating EC2 instance: i-0abc' });
const LAUNCH_FAILED = ev('EC2 Instance Launch Unsuccessful', { EC2InstanceId: '', StatusCode: 'Failed', Cause: 'At 2026-09-13T02:34:12Z a monitor alarm ppq-enclave-fleet-flows-high in state ALARM triggered policy flows-scale-out changing the desired capacity from 1 to 2.', StatusMessage: 'Your requested instance type (c6i.2xlarge) is not supported in your requested Availability Zone (us-east-1e). Please retry your request by not specifying an Availability Zone or choosing us-east-1a, us-east-1b, us-east-1c, us-east-1d, us-east-1f. Launching EC2 instance failed.', Description: 'Launching a new EC2 instance.  Status Reason: Your requested instance type (c6i.2xlarge) is not supported' });

test('capacityChange reads the from/to sizes out of a cause', () => {
  assert.deepEqual(capacityChange(SCALE_OUT.detail.Cause), { from: 2, to: 3 });
  assert.equal(capacityChange('no numbers here'), null);
  assert.equal(capacityChange(undefined), null);
});

test('policy-driven scaling posts one line each way, with the size change', () => {
  assert.deepEqual(classify(SCALE_OUT), { kind: 'scale_out', from: 2, to: 3 });
  assert.equal(format(SCALE_OUT), ':arrow_up_small: *Enclave fleet scaled out*: 2 → 3 boxes, load per box above target. Launched i-0abc in us-east-1b.');
  assert.deepEqual(classify(SCALE_IN), { kind: 'scale_in', from: 3, to: 2 });
  assert.equal(format(SCALE_IN), ':arrow_down_small: *Enclave fleet scaled in*: 3 → 2 boxes. Removed i-0abc after draining.');
});

test('a health-check replacement warns once, on the termination', () => {
  assert.equal(classify(HEALTH_TERM).kind, 'health_replaced');
  assert.match(format(HEALTH_TERM), /^:warning: \*Enclave box replaced\*: i-0abc in us-east-1b failed its load balancer health check/);
  assert.equal(classify(HEALTH_LAUNCH).kind, 'health_relaunch');
  assert.equal(format(HEALTH_LAUNCH), null);
});

test('instance refreshes are silent when they succeed: every release rolls the fleet on purpose', () => {
  assert.equal(format(REFRESH_LAUNCH), null);
  assert.equal(format(REFRESH_TERM), null);
});

test('any failed launch or termination is loud, even inside a refresh, and carries AWS\'s reason', () => {
  const text = format(LAUNCH_FAILED);
  assert.match(text, /^:rotating_light: \*Enclave fleet could not launch a box\* \(desired 1 → 2\): Your requested instance type \(c6i\.2xlarge\) is not supported/);
  assert.ok(text.length < 400, 'reason is clipped');
  const refreshFail = ev('EC2 Instance Launch Unsuccessful', { Cause: 'an instance was launched in response to an instance refresh.', StatusMessage: 'InsufficientInstanceCapacity' });
  assert.match(format(refreshFail), /could not launch a box\*: InsufficientInstanceCapacity$/);
  const termFail = ev('EC2 Instance Terminate Unsuccessful', { StatusMessage: 'Timed out waiting for draining' });
  assert.equal(format(termFail), ':rotating_light: *Enclave fleet could not remove i-0abc*: Timed out waiting for draining');
});

test('anything else is posted as information rather than dropped', () => {
  const manual = ev('EC2 Instance Launch Successful', { Cause: 'At 2026-09-24T10:00:00Z a user request update of AutoScalingGroup constraints to min: 3 changing the desired capacity from 2 to 3.', Description: 'Launching a new EC2 instance: i-0abc' });
  assert.equal(classify(manual).kind, 'other');
  assert.match(format(manual), /^:information_source: \*Enclave fleet\*: Launching a new EC2 instance: i-0abc\. At 2026/);
  assert.equal(classify({ 'detail-type': 'EC2 Instance-launch Lifecycle Action', detail: {} }).kind, 'ignored');
  assert.equal(format({ 'detail-type': 'Something else', detail: {} }), null);
});

test('the webhook check accepts both Slack shapes and nothing else', () => {
  assert.ok(SLACK_WEBHOOK.test('https://hooks.slack.com/services/T0001/B0002/abcDEF123'));
  assert.ok(SLACK_WEBHOOK.test('https://hooks.slack.com/T0001/B0002/abcDEF123'));
  assert.ok(!SLACK_WEBHOOK.test('https://hooks.slack.com.evil.example/services/T0001/B0002/abc'));
  assert.ok(!SLACK_WEBHOOK.test('http://hooks.slack.com/services/T0001/B0002/abc'));
  assert.ok(!SLACK_WEBHOOK.test('https://hooks.slack.com/services/T0001/B0002/abc?x=1'));
});

// ── handler wiring ───────────────────────────────────────────────────────────

const spy = (status = 200) => {
  const calls = [];
  return { calls, post: async (url, text) => { calls.push({ url, text }); return status; } };
};
const quiet = { warn() {} };
const URL_OK = 'https://hooks.slack.com/services/T0001/B0002/abc';

test('handler posts what format produces, and nothing for suppressed events', async () => {
  const s = spy();
  const h = createHandler({ getWebhook: async () => URL_OK, post: s.post, group: 'ppq-enclave-fleet', log: quiet });
  assert.deepEqual(await h(SCALE_OUT), { posted: true, status: 200 });
  assert.equal(s.calls[0].text, format(SCALE_OUT));
  assert.deepEqual(await h(REFRESH_LAUNCH), { posted: false, reason: 'refresh' });
  assert.equal(s.calls.length, 1);
});

test('handler ignores another group\'s events even if the rule ever matched them', async () => {
  const s = spy();
  const h = createHandler({ getWebhook: async () => URL_OK, post: s.post, group: 'ppq-enclave-fleet', log: quiet });
  const foreign = { ...SCALE_OUT, detail: { ...SCALE_OUT.detail, AutoScalingGroupName: 'someone-else' } };
  assert.deepEqual(await h(foreign), { posted: false, reason: 'other group' });
  assert.equal(s.calls.length, 0);
});

test('no webhook yet: nothing is posted and the invocation still succeeds', async () => {
  const s = spy();
  const h = createHandler({ getWebhook: async () => null, post: s.post, group: 'ppq-enclave-fleet', log: quiet });
  assert.deepEqual(await h(SCALE_OUT), { posted: false, reason: 'no webhook' });
  assert.equal(s.calls.length, 0);
});

test('a Slack 5xx is retried by throwing; a 4xx is logged and dropped', async () => {
  const h5 = createHandler({ getWebhook: async () => URL_OK, post: spy(503).post, group: 'ppq-enclave-fleet', log: quiet });
  await assert.rejects(h5(SCALE_OUT), /Slack returned 503/);
  const h4 = createHandler({ getWebhook: async () => URL_OK, post: spy(404).post, group: 'ppq-enclave-fleet', log: quiet });
  assert.deepEqual(await h4(SCALE_OUT), { posted: false, status: 404 });
});

test('a manual {"ppqTest": true} invocation posts the connectivity check', async () => {
  const s = spy();
  const h = createHandler({ getWebhook: async () => URL_OK, post: s.post, group: 'ppq-enclave-fleet', log: quiet });
  assert.deepEqual(await h({ ppqTest: true }), { posted: true, status: 200 });
  assert.equal(s.calls[0].text, TEST_TEXT);
});
