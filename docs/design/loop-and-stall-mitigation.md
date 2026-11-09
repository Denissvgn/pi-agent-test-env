# Loop and provider-stall mitigation

Two native qualification attempts for the 4.9.1 release were blocked by failures
outside the code under test:

- **Model loop.** A read-only reviewer stage read the right files, then repeated
  an identical `ls` call nine times until it reached its 12-turn limit.
- **Provider stall.** On an indexed run, the model server accepted a request,
  streamed nothing for about 150 seconds, then closed the stream ("Stream ended
  without finish_reason"). The gateway could not prove the abandoned request had
  stopped, quarantined its slot and failed the run closed.

Both behaved as designed: bounded and fail-closed. This change makes the first
fail sooner and more clearly, and makes the second survivable for direct
endpoints that opt in, without hiding either.

## Repeated tool calls

A completed tool call repeats the previous one when the tool name, canonical
arguments, result text and error flag all match. The agent is then receiving no
new information. `skill/runtime/tool_repetition.py` holds the signature and run
tracking, shared by the in-container worker and the parent's trace analysis.

- The worker stops Pi once a run exceeds 5, the same way it enforces turn and
  token limits.
- The parent classifies the stop as `repeated_tool_call` only after recounting
  the retained trace, so the worker's own report is never trusted. Turn and
  token limits keep precedence.
- It is a fixed runner policy, not a budget field. Budgets carry revisions,
  steering, frozen experiment matrices and application contracts. A new budget
  key would have touched all of them for a value nobody needs to tune yet.
- Including the result in the signature avoids stopping legitimate polling whose
  output changes. Five identical calls in a row with identical results is
  stuck.

The guard never turns a failure into a pass: the looping reviewer would still
fail, at its sixth `ls` instead of its twelfth turn.

## Transient provider retries (direct endpoints)

The runner disables every Pi retry layer (`retry.enabled: false`,
`provider.maxRetries: 0`), and evidence analysis treats a retry as a policy
error. The opt-in keeps that default.

- **Field.** An endpoint `transient_retries` of 0 to 3. It is part of the
  endpoint configuration, so changing it needs a new confirmation.
- **Pi settings.** For Pi 1.2.0 only, Pi's agent-level retry is enabled with that
  `maxRetries` and a 2-second base delay. SDK-level provider retries stay off, so
  every attempt appears as `auto_retry_start`/`auto_retry_end` in the trace. Pi's
  own rule decides which errors are transient. It includes 5xx statuses,
  overload and dropped streams, and Pi omits the failed attempt from the model's
  context.
- **Evidence.** A retry is accepted only when Pi reports the endpoint budget as
  `maxAttempts` and the attempt is within it. Each traced retry accounts for one
  failed attempt. Exhausted retries and any other failed message still fail.
  Evidence records `provider_retries` (allowed, attempts and error text); stage
  evidence sums attempts across segments, and the run summary shows the count
  per agent.
- **Status.** A retried stage can still be `verified`, because the model never
  saw the failed attempt. Comparisons should filter on `provider_retries`. This
  differs from authorized recovery, which continues a stopped session and is
  marked `recovered`.

## Indexed gateway (deferred)

Indexed bindings reject `transient_retries` (`transient-retries-unsupported`).
After an upstream failure the gateway sets `uncertain`, refuses new requests, and
the broker refuses admission and quarantines the gateway at teardown. That is
what keeps its one-request-in-flight promise when the server may still be
working on an abandoned request.

A possible later design:

- After an uncertain release, the gateway holds its slot for a fixed drain period
  (at least the request timeout), then frees it.
- Requests arriving meanwhile wait in the gateway queue, so `queue_wait_seconds`
  must exceed the drain period.
- The gateway receipt records each recovery and its drain time, within a budget.

This needs its own changes and campaign evidence:

- **Request limits.** `request_limits` code iterates over and sums its values, so
  the policy belongs in a separate binding field.
- **Broker.** Admission, activation and teardown would all have to accept a
  draining gateway.
- **Assumption.** The capacity promise would rest on an explicit assumption that
  the server ends an abandoned request within the drain period.

## Qualification

These changes alter the campaign source identity: runtime, scripts and
evidence. A release that ships them needs its own native campaign. That campaign
should add scripted oracles alongside the existing abort, timeout, crash and
provider-fatal cells:

1. A scripted agent that repeats one tool call: expect `repeated_tool_call`,
   the observed run in `observed_budget_counts`, confirmed cleanup, and no
   scoring.
2. A negative control whose repeated calls return changing results: expect no
   early stop.
3. A direct endpoint with `transient_retries: 1` whose first stream drops: expect
   a `verified` stage with `provider_retries` of 1.
4. The same endpoint failing twice: expect `Provider retries exhausted` and an
   invalid stage.
5. An indexed profile carrying the field: expect rejection before any launch.

Campaign profiles themselves should keep the default (no retries) unless that
release deliberately qualifies the retry path.
