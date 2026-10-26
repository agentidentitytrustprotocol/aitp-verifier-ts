// Edge cases of the strict primitives, independent of the spec vectors.

import * as b64 from "../src/b64.js";
import { fromHex, toHex, utf8 } from "../src/bytes.js";
import { canonicalize, serializeNumber } from "../src/jcs.js";
import { parseJson } from "../src/json.js";
import { parseAid } from "../src/aid.js";
import { parseSignatureField } from "../src/sigfield.js";
import { JwsFormatError, parseCompactJws } from "../src/jws.js";
import { isUuidV4 } from "../src/fields.js";
import { checkNow, isExpired, withinWindow } from "../src/timeutil.js";
import { verifyRaw } from "../src/keys.js";
import { parseAid as aidOf } from "../src/aid.js";
import { assert, eq, test, throws } from "./harness.js";

test("json: duplicate keys are rejected at every depth", () => {
  throws(() => parseJson('{"a":1,"a":2}'));
  throws(() => parseJson('{"x":{"y":{"z":{"k":1,"k":1}}}}'));
  throws(() => parseJson('[{"a":[{"b":{"c":true,"c":false}}]}]'));
  // Escaped spelling of the same name is the same name.
  throws(() => parseJson('{"aud":"A","\\u0061ud":"B"}'));
  eq(JSON.stringify(parseJson('{"x":{"y":{"z":{"k":1,"l":1}}}}')), '{"x":{"y":{"z":{"k":1,"l":1}}}}');
});

test("json: __proto__ is an ordinary member", () => {
  const v = parseJson('{"__proto__":{"polluted":true}}') as Record<string, unknown>;
  eq(Object.getPrototypeOf(v), Object.prototype);
  eq(Object.keys(v).join(), "__proto__");
  eq(({} as Record<string, unknown>).polluted, undefined);
});

test("json: grammar and I-JSON limits", () => {
  for (const bad of [
    "",
    "{",
    "{}x",
    "[1,]",
    '{"a":1,}',
    "01",
    "1.",
    ".5",
    "+1",
    "NaN",
    "1e999",
    '"\\ud800"',
    '"\\udc00x"',
    '"a\tb"',
    '"\\x41"',
    "'a'",
    "tru",
    '{"a" 1}',
  ]) {
    throws(() => parseJson(bad), `accepted ${JSON.stringify(bad)}`);
  }
  eq(parseJson(' {"a" : [ 1 , -0.5e+2 , "\\ud83d\\ude00" ] } ') !== null, true);
  eq((parseJson('"\\ud83d\\ude00"') as string).codePointAt(0), 0x1f600);
});

test("b64: strict unpadded base64url", () => {
  eq(b64.encode(utf8("")), "");
  eq(b64.encode(utf8("f")), "Zg");
  eq(b64.encode(utf8("fo")), "Zm8");
  eq(b64.encode(utf8("foo")), "Zm9v");
  eq(b64.encode(new Uint8Array([0xfb, 0xff])), "-_8");
  eq(toHex(b64.decode("-_8")), "fbff");
  for (const bad of ["Zg==", "Zg=", "Z", "Zm9v\n", "Zm 9v", "+/8", "Zh", "Zm9", "Zm8=", "Zm-"]) {
    eq(b64.tryDecode(bad), undefined, `accepted ${JSON.stringify(bad)}`);
  }
  // "Zh" carries non-zero trailing bits: it would decode to "f" like "Zg".
  eq(toHex(b64.decode("Zg")), "66");
  eq(b64.decodeExact("Zm9v", 2), undefined);
});

test("jcs: RFC 8785 number serialization", () => {
  const cases: [number, string][] = [
    [0, "0"],
    [-0, "0"],
    [1, "1"],
    [-1.5, "-1.5"],
    [1e21, "1e+21"],
    [1e20, "100000000000000000000"],
    [1e-7, "1e-7"],
    [0.000001, "0.000001"],
    [5e-324, "5e-324"],
    [1.7976931348623157e308, "1.7976931348623157e+308"],
    [9007199254740992, "9007199254740992"],
    // biome-ignore lint/correctness/noPrecisionLoss: the RFC 8785 vector is this literal, rounded at parse time.
    [333333333.33333329, "333333333.3333333"],
    [4.5, "4.5"],
    [0.002, "0.002"],
    [295147905179352830000, "295147905179352830000"],
  ];
  for (const [n, s] of cases) eq(serializeNumber(n), s, String(n));
  throws(() => serializeNumber(NaN));
  throws(() => serializeNumber(Infinity));
});

test("jcs: UTF-16 key order and string escaping (RFC 8785 §3.2.3)", () => {
  const obj = parseJson(
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
  );
  // Read the order off the output itself: Object.keys would list "1" first.
  const out = canonicalize(obj);
  const at = (k: string) => out.indexOf(`${JSON.stringify(k)}:`);
  const order = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"].map(at);
  assert(
    order.every((i, n) => i >= 0 && (n === 0 || i > (order[n - 1] as number))),
    `order ${order.join()}`,
  );
  eq(canonicalize({ s: '\u0000\u001f\b\f\n\r\t"\\/\u007f é' }), '{"s":"\\u0000\\u001f\\b\\f\\n\\r\\t\\"\\\\/\u007f é"}');
  eq(canonicalize({ b: [true, false, null, { z: 1, a: [] }], a: {} }), '{"a":{},"b":[true,false,null,{"a":[],"z":1}]}');
  throws(() => canonicalize({ s: "\ud800" }));
  throws(() => canonicalize({ n: Infinity }));
  throws(() => canonicalize({ d: new Date(0) }));
});

test("aid: grammar", () => {
  const ed = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
  const p = "AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR";
  eq(parseAid(`aid:pubkey:${ed}`)?.key.alg, "ed25519");
  eq(parseAid(`aid:pubkey:ed25519:${ed}`)?.tagged, true);
  eq(parseAid(`aid:pubkey:p256:${p}`)?.key.alg, "p256");
  for (const bad of [
    `aid:pubkey:${ed}A`,
    `aid:pubkey:${ed.slice(1)}`,
    `aid:pubkey:p256:${ed}`,
    `aid:pubkey:ed25519:${p}`,
    `aid:pubkey:${p}`,
    `aid:pubkey:secp256k1:${ed}`,
    `aid:pubkey:ED25519:${ed}`,
    `aid:key:${ed}`,
    `aid:pubkey:${ed.slice(0, 42)}=`,
    // 0x04 prefix: not a compressed point.
    `aid:pubkey:p256:B${p.slice(1)}`,
  ]) {
    eq(parseAid(bad), undefined, bad);
  }
});

test("sigfield: the three wire forms", () => {
  const raw = "A".repeat(86);
  eq(parseSignatureField(raw)?.alg, "ed25519");
  eq(parseSignatureField(`ed25519.${raw}`)?.tagged, true);
  eq(parseSignatureField(`p256.${raw}`)?.alg, "p256");
  for (const bad of [`ES256.${raw}`, `p256.${raw}A`, raw.slice(1), `${raw}==`, `p256.${raw.slice(0, 85)}B`, `.${raw}`]) {
    eq(parseSignatureField(bad), undefined, bad);
  }
});

test("jws: strict compact parsing", () => {
  const h = b64.encode(utf8('{"alg":"EdDSA","typ":"aitp-tct+jwt"}'));
  const p = b64.encode(utf8('{"ver":"aitp/0.3"}'));
  const s = b64.encode(new Uint8Array(64));
  eq(parseCompactJws(`${h}.${p}.${s}`).claims.ver, "aitp/0.3");
  const dup = b64.encode(utf8('{"aud":"a","aud":"b"}'));
  const arr = b64.encode(utf8("[1]"));
  for (const bad of [
    `${h}.${p}`,
    `${h}.${p}.${s}.${s}`,
    `${h}..${s}`,
    `${h}.${p}.`,
    `${h}=.${p}.${s}`,
    `${h}.${dup}.${s}`,
    `${h}.${arr}.${s}`,
    `${h}.${p}.${s}=`,
  ]) {
    let threw = false;
    try {
      parseCompactJws(bad);
    } catch (e) {
      threw = e instanceof JwsFormatError;
    }
    assert(threw, `accepted ${bad}`);
  }
});

test("fields: uuid v4 layout", () => {
  assert(isUuidV4("550e8400-e29b-41d4-a716-446655440000"));
  assert(!isUuidV4("550E8400-E29B-41D4-A716-446655440000"));
  assert(!isUuidV4("550e8400-e29b-11d4-a716-446655440000"));
  assert(!isUuidV4("550e8400-e29b-41d4-c716-446655440000"));
  assert(!isUuidV4("550e8400e29b41d4a716446655440000"));
});

test("bytes: hex round trip", () => {
  eq(toHex(fromHex("00ff10")), "00ff10");
  throws(() => fromHex("0"));
  throws(() => fromHex("zz"));
});

test("timeutil: explicit now", () => {
  eq(isExpired(100, 99), false);
  eq(isExpired(100, 100), true);
  eq(withinWindow(1000, 1300), true);
  eq(withinWindow(1000, 1301), false);
  eq(withinWindow(1301, 1000), false);
  throws(() => checkNow(1.5));
  throws(() => checkNow(-1));
});

test("keys: only raw 64-byte R || S signatures are considered", async () => {
  const p256 = aidOf("aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR")!.key;
  const ed = aidOf("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik")!.key;
  const msg = utf8("m");
  for (const len of [0, 63, 65, 70, 72]) {
    eq(await verifyRaw(p256, msg, new Uint8Array(len).fill(1)), false, `p256 ${len}`);
    eq(await verifyRaw(ed, msg, new Uint8Array(len).fill(1)), false, `ed25519 ${len}`);
  }
});
