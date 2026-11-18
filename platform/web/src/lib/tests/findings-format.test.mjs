import assert from "node:assert/strict";
import test from "node:test";

import {
  fieldValuesText,
  findingMeta,
  reconciliationItems,
  scalarText,
  unwrapNotePayload,
} from "../findings-format.ts";

test("scalarText never renders objects or crashes", () => {
  assert.equal(scalarText(undefined), "-");
  assert.equal(scalarText(""), "-");
  assert.equal(scalarText(3), "3");
  assert.equal(scalarText(false), "false");
  assert.equal(scalarText({ nested: true }), "-");
});

test("fieldValuesText accepts arrays, pipe strings and scalar values", () => {
  assert.equal(fieldValuesText({ values: ["a", "b"], off: 0, size: 1 }), "a/b");
  assert.equal(fieldValuesText({ values: "_INSE | +INSE", off: 0, size: 1 }), "_INSE | +INSE");
  assert.equal(fieldValuesText({ value: 0x58, off: 0, size: 1 }), "88");
  assert.equal(fieldValuesText({ off: 0, size: 1 }), "-");
});

test("findingMeta reads projection payload/detail", () => {
  assert.deepEqual(findingMeta({ payload: { verdict: "matched", source: "traffic+static" } }), {
    verdict: "matched",
    source: "traffic+static",
  });
  assert.deepEqual(findingMeta({ detail: { verdict: "traffic-only" }, source: "traffic" }), {
    verdict: "traffic-only",
    source: "traffic",
  });
  assert.deepEqual(findingMeta({}), { verdict: undefined, source: undefined });
});

test("unwrapNotePayload supports flat and nested state-machine payloads", () => {
  const flat = unwrapNotePayload({ kind: "session-model-final", payload: { states: ["ready"], transitions: [] } });
  assert.deepEqual(flat.states, ["ready"]);
  const nested = unwrapNotePayload({
    kind: "session-model-final",
    payload: { grade: "traffic", payload: { states: ["tcp_connected"], transitions: [{}] } },
  });
  assert.deepEqual(nested.states, ["tcp_connected"]);
  assert.equal(nested.transitions.length, 1);
});

test("reconciliationItems accepts pairs and items, dedupes and caps", () => {
  const notes = [
    { kind: "code-reconciliation", payload: { items: [{ code: "0xF0", verdict: "matched", traffic: "a", static: "b" }] } },
    { kind: "code-reconciliation", payload: { pairs: [{ code: "0xF0", verdict: "matched", traffic: "a", static: "b" }] } },
    { kind: "code-reconciliation", payload: { payload: { items: [{ code: "0x04", verdict: "static-only", traffic_label: "t", static_label: "s" }] } } },
    { kind: "other", payload: {} },
  ];
  const items = reconciliationItems(notes);
  assert.equal(items.length, 2);
  assert.equal(items[0].code, "0xF0");
  assert.equal(items[1].code, "0x04");
});