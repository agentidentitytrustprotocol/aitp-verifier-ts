// Test entry point. Verification never touches the network: fetch is
// replaced by a function that throws before any test module loads.

globalThis.fetch = (() => {
  throw new Error("network access is forbidden in tests");
}) as typeof fetch;

const { run } = await import("./harness.js");
await import("./primitives.test.js");
await import("./kat.test.js");
await import("./verify.test.js");
await import("./adapter.test.js");
const failed = await run();
if (failed > 0) {
  // Deno and Node both expose process via node:process.
  const { exit } = await import("node:process");
  exit(1);
}
