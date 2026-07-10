/**
 * Regression guard for the SAML encode-fail orphan fix.
 *
 * encodeAuthnRequestForRedirect is essentially deflateRawSync — practically
 * impossible to force into a failure through the HTTP surface without a
 * mocking library (which the project intentionally avoids). Instead, this
 * test enforces the invariant statically: the encode-fail branch in
 * startNewSamlUiFlow MUST complete the flow as `failed`, otherwise a flow
 * would stay `running` until the SAML TTL sweeps it — the exact bug this
 * fix addresses.
 *
 * If someone drops the completeFlow call from that branch, this test fails.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER_SRC = readFileSync(
  fileURLToPath(new URL("../src/server.js", import.meta.url)),
  "utf8"
);

describe("startNewSamlUiFlow encode-fail branch", () => {
  it("marks the flow as failed instead of leaving it running", () => {
    // Isolate the helper body.
    const startIdx = SERVER_SRC.indexOf("async function startNewSamlUiFlow");
    assert.ok(startIdx >= 0, "startNewSamlUiFlow must exist");

    const nextFnIdx = SERVER_SRC.indexOf("async function processNewUiCallback", startIdx);
    assert.ok(nextFnIdx > startIdx, "helper must be delimited by the next top-level function");

    const helperBody = SERVER_SRC.slice(startIdx, nextFnIdx);

    // Find the encode-fail catch block by anchoring on the log line that
    // uniquely identifies it, then take everything up to the closing `}`
    // of the surrounding catch.
    const catchAnchor = 'appLog("warn", "saml_flow_start: encode error"';
    const catchIdx = helperBody.indexOf(catchAnchor);
    assert.ok(catchIdx >= 0, "encode-fail branch must exist");

    // Grab a reasonably-sized window after the catch anchor — the fix must
    // fall inside the same catch block.
    const window = helperBody.slice(catchIdx, catchIdx + 4000);

    assert.match(
      window,
      /samlFlowService\.completeFlow\([^)]*flow\.id[^)]*,\s*{[^}]*status:\s*"failed"/s,
      "encode-fail branch must call samlFlowService.completeFlow(flow.id, { status: 'failed', ... })"
    );

    assert.match(
      window,
      /errorCode:\s*"authn_request_encode_error"/,
      "encode-fail branch must record the authn_request_encode_error code"
    );

    // And the branch must still return `ok: false` with the flow attached
    // so callers can present the failed flow instead of a 500 blank.
    assert.match(window, /return\s*{[^}]*ok:\s*false[^}]*flow:/s, "branch must return the failed flow");
  });
});
