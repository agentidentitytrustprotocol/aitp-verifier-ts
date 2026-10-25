// The conformance adapter's protocol behaviour: replies, skips, and the
// per-fixture state the runner resets with begin_fixture. Fixture outcomes
// themselves are checked by aitp-conformance against the adapter binary.

import { Adapter, type AdapterReply } from "../src/adapter.js";
import { assert, eq, test } from "./harness.js";

const adapter = () =>
  new Adapter({
    info: { implementation: "aitp-verifier-ts", version: "0.0.0", repository: "https://example.com/repo", commit: "0".repeat(40) },
    oidcIssuers: new Map(),
  });

let n = 0;
const call = (a: Adapter, op: string, params: Record<string, unknown> = {}) => a.handle({ id: `req-${++n}`, op, params: params as never });

function errorCode(r: AdapterReply): string | undefined {
  return r.ok ? undefined : r.error_code;
}

test("adapter: init advertises every op it dispatches", async () => {
  const a = adapter();
  const r = await call(a, "init", { version: "1" });
  assert(r.ok, "init succeeds");
  const ops = r.result.supported_ops as string[];
  for (const op of ["set_clock", "begin_fixture", "verify_tct", "verify_delegation_token"]) assert(ops.includes(op), op);
  // A v0.3 delegation input names delegation_token; the v0.1 object shape is a skip.
  for (const op of ops) assert(errorCode(await call(a, op, { delegation_token: "x" })) !== "OP_NOT_SUPPORTED", `${op} is dispatched`);
  eq(errorCode(await call(a, "verify_delegation_token", { delegation: {} })), "OP_NOT_SUPPORTED");
});

test("adapter: an unknown op is a skip, not a failure", async () => {
  eq(errorCode(await call(adapter(), "verify_session_bundle")), "OP_NOT_SUPPORTED");
});

test("adapter: replies echo the request id", async () => {
  const r = await adapter().handle({ id: "abc", op: "begin_fixture", params: {} });
  eq(r.id, "abc");
});

test("adapter: replay state lasts for one fixture", async () => {
  const a = adapter();
  const id = { message_id: "550e8400-e29b-41d4-a716-446655440099" };
  eq(errorCode(await call(a, "process_handshake_message", id)), undefined);
  eq(errorCode(await call(a, "process_handshake_message", id)), "REPLAY_DETECTED");
  await call(a, "begin_fixture");
  eq(errorCode(await call(a, "process_handshake_message", id)), undefined, "reset by begin_fixture");
});

test("adapter: protocol errors carry the registry code; adapter faults do not", async () => {
  const a = adapter();
  await call(a, "set_clock", { now_unix_secs: 1711900000 });
  eq(errorCode(await call(a, "verify_tct", { tct_token: "not.a.jws" })), "TCT_SIGNATURE_INVALID");
  eq(errorCode(await call(a, "set_clock", {})), "INTERNAL_ERROR");
});
