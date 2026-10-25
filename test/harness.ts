// A tiny test harness. The suite compiles to plain ESM and runs unchanged
// under Node and Deno, so it depends on neither runtime's test runner.

type TestFn = () => void | Promise<void>;

const tests: { name: string; fn: TestFn }[] = [];

export function test(name: string, fn: TestFn): void {
  tests.push({ name, fn });
}

export class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssertionError";
  }
}

export function assert(cond: unknown, message = "assertion failed"): asserts cond {
  if (!cond) throw new AssertionError(message);
}

export function eq<T>(actual: T, expected: T, message = ""): void {
  if (!Object.is(actual, expected)) {
    throw new AssertionError(`${message ? `${message}: ` : ""}expected ${show(expected)}, got ${show(actual)}`);
  }
}

export function throws(fn: () => unknown, message = "expected a throw"): void {
  try {
    fn();
  } catch {
    return;
  }
  throw new AssertionError(message);
}

function show(v: unknown): string {
  return typeof v === "string" ? JSON.stringify(v) : String(v);
}

export async function run(): Promise<number> {
  let failed = 0;
  for (const t of tests) {
    try {
      await t.fn();
      console.log(`ok   ${t.name}`);
    } catch (e) {
      failed++;
      console.log(`FAIL ${t.name}\n     ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    }
  }
  console.log(`\n${tests.length - failed} passed, ${failed} failed, ${tests.length} total`);
  return failed;
}
