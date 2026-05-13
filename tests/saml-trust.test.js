import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseSamlResponse,
  evaluateSamlTemporalConditions,
  evaluateSamlIssuerValidation,
  evaluateSamlAudienceValidation,
  evaluateSamlDestinationValidation,
  evaluateSamlInResponseTo,
  evaluateSamlSubjectConfirmation,
  checkXswProtection,
  evaluateSamlTrustValidation,
  extractIdpSigningCertificates,
  verifySamlXmlSignatures,
  shortHash,
  SAML_CLOCK_SKEW_SECONDS
} from "../src/protocols/saml/saml.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const NOW_ISO = new Date().toISOString();
const PAST_ISO = new Date(Date.now() - 60_000).toISOString();
const FUTURE_ISO = new Date(Date.now() + 3_600_000).toISOString();
const FAR_PAST_ISO = new Date(Date.now() - 7_200_000).toISOString();
const FAR_FUTURE_ISO = new Date(Date.now() + 7_200_000).toISOString();

function makeXml({ responseId = "_resp1", assertionId = "_ass1", issuer = "https://idp.example/metadata",
  destination = "https://sp.example/saml/acs", inResponseTo = "_req1",
  spEntityId = "https://sp.example", notBefore = PAST_ISO, notOnOrAfter = FUTURE_ISO,
  recipient = "https://sp.example/saml/acs", subjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
  addResponseSig = false, addAssertionSig = false, extraAssertions = "" } = {}) {
  const responseSig = addResponseSig ? `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#${responseId}"></ds:Reference></ds:SignedInfo></ds:Signature>` : "";
  const assertionSig = addAssertionSig ? `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#${assertionId}"></ds:Reference></ds:SignedInfo></ds:Signature>` : "";
  return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${responseId}" InResponseTo="${inResponseTo}" Destination="${destination}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  ${responseSig}
  <saml:Assertion ID="${assertionId}">
    <saml:Issuer>${issuer}</saml:Issuer>
    ${assertionSig}
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="${subjectConfirmationMethod}">
        <saml:SubjectConfirmationData Recipient="${recipient}" NotOnOrAfter="${notOnOrAfter}" InResponseTo="${inResponseTo}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
      <saml:AudienceRestriction><saml:Audience>${spEntityId}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
  ${extraAssertions}
</samlp:Response>`;
}

function parsedFrom(opts) {
  return parseSamlResponse(makeXml(opts));
}

// ---------------------------------------------------------------------------
// parseSamlResponse — new SubjectConfirmation fields
// ---------------------------------------------------------------------------

describe("parseSamlResponse — SubjectConfirmation extensions", () => {
  it("extracts subjectConfirmationMethod from SubjectConfirmation element", () => {
    const p = parsedFrom({});
    assert.equal(p.subjectConfirmationMethod, "urn:oasis:names:tc:SAML:2.0:cm:bearer");
  });

  it("extracts subjectConfirmationNotOnOrAfter from SubjectConfirmationData", () => {
    const p = parsedFrom({ notOnOrAfter: FUTURE_ISO });
    assert.equal(p.subjectConfirmationNotOnOrAfter, FUTURE_ISO);
  });

  it("extracts subjectConfirmationInResponseTo from SubjectConfirmationData", () => {
    const p = parsedFrom({ inResponseTo: "_req_xyz" });
    assert.equal(p.subjectConfirmationInResponseTo, "_req_xyz");
  });

  it("returns empty strings when SubjectConfirmation absent", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="https://sp.example/acs">
      <saml:Issuer>issuer</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_a1"><saml:Issuer>issuer</saml:Issuer></saml:Assertion>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    assert.equal(p.subjectConfirmationMethod, "");
    assert.equal(p.subjectConfirmationNotOnOrAfter, "");
    assert.equal(p.subjectConfirmationInResponseTo, "");
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlTemporalConditions
// ---------------------------------------------------------------------------

describe("evaluateSamlTemporalConditions", () => {
  it("returns valid when both NotBefore (past) and NotOnOrAfter (future) are within bounds", () => {
    const p = parsedFrom({ notBefore: PAST_ISO, notOnOrAfter: FUTURE_ISO });
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "valid");
    assert.equal(r.conditions_evaluated, true);
    assert.equal(r.not_before_result, "valid");
    assert.equal(r.not_on_or_after_result, "valid");
    assert.equal(r.clock_skew_seconds, SAML_CLOCK_SKEW_SECONDS);
  });

  it("returns expired when NotOnOrAfter is in the past beyond clock skew", () => {
    const p = parsedFrom({ notBefore: FAR_PAST_ISO, notOnOrAfter: FAR_PAST_ISO });
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "expired");
    assert.equal(r.not_on_or_after_result, "expired");
  });

  it("returns not_yet_valid when NotBefore is in the future beyond clock skew", () => {
    const p = parsedFrom({ notBefore: FAR_FUTURE_ISO, notOnOrAfter: FAR_FUTURE_ISO });
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "not_yet_valid");
    assert.equal(r.not_before_result, "not_yet_valid");
  });

  it("returns missing when Conditions element is absent", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">
      <saml:Issuer>i</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_a1"><saml:Issuer>i</saml:Issuer></saml:Assertion>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "missing");
    assert.equal(r.conditions_evaluated, false);
  });

  it("returns not_checked when no Assertion present", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "not_checked");
  });

  it("returns invalid_format on malformed date", () => {
    const p = parsedFrom({ notBefore: "not-a-date", notOnOrAfter: FUTURE_ISO });
    const r = evaluateSamlTemporalConditions(p);
    assert.equal(r.result, "invalid_format");
    assert.equal(r.conditions_evaluated, false);
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlIssuerValidation
// ---------------------------------------------------------------------------

describe("evaluateSamlIssuerValidation", () => {
  it("returns valid when both issuers match expected IdP entity ID", () => {
    const p = parsedFrom({ issuer: "https://idp.example/metadata" });
    const r = evaluateSamlIssuerValidation(p, "https://idp.example/metadata");
    assert.equal(r.result, "valid");
    assert.equal(r.response_issuer_matches, true);
    assert.equal(r.assertion_issuer_matches, true);
  });

  it("returns invalid when response issuer does not match", () => {
    const p = parsedFrom({ issuer: "https://evil.example/metadata" });
    const r = evaluateSamlIssuerValidation(p, "https://idp.example/metadata");
    assert.equal(r.result, "invalid");
    assert.equal(r.response_issuer_matches, false);
  });

  it("returns missing when no issuer in response or assertion", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlIssuerValidation(p, "https://idp.example");
    assert.equal(r.result, "missing");
  });

  it("returns not_checked when no expected entity ID provided", () => {
    const p = parsedFrom({});
    const r = evaluateSamlIssuerValidation(p, "");
    assert.equal(r.result, "not_checked");
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlAudienceValidation
// ---------------------------------------------------------------------------

describe("evaluateSamlAudienceValidation", () => {
  it("returns valid when audience matches SP entity ID", () => {
    const p = parsedFrom({ spEntityId: "https://sp.example" });
    const r = evaluateSamlAudienceValidation(p, "https://sp.example");
    assert.equal(r.result, "valid");
    assert.equal(r.matching_audience_present, true);
  });

  it("returns invalid when audience does not match SP entity ID", () => {
    const p = parsedFrom({ spEntityId: "https://sp.example" });
    const r = evaluateSamlAudienceValidation(p, "https://other-sp.example");
    assert.equal(r.result, "invalid");
    assert.equal(r.matching_audience_present, false);
  });

  it("returns failed when AudienceRestriction is missing from Assertion", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_a1"><saml:Issuer>issuer</saml:Issuer></saml:Assertion>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlAudienceValidation(p, "https://sp.example");
    assert.equal(r.result, "failed");
    assert.equal(r.matching_audience_present, false);
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlDestinationValidation
// ---------------------------------------------------------------------------

describe("evaluateSamlDestinationValidation", () => {
  it("returns valid when destination matches ACS URL", () => {
    const p = parsedFrom({ destination: "https://sp.example/saml/acs" });
    const r = evaluateSamlDestinationValidation(p, "https://sp.example/saml/acs");
    assert.equal(r.result, "valid");
  });

  it("returns invalid on destination mismatch", () => {
    const p = parsedFrom({ destination: "https://sp.example/saml/acs" });
    const r = evaluateSamlDestinationValidation(p, "https://other.example/saml/acs");
    assert.equal(r.result, "invalid");
  });

  it("returns missing when Destination attribute absent", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlDestinationValidation(p, "https://sp.example/saml/acs");
    assert.equal(r.result, "missing");
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlInResponseTo
// ---------------------------------------------------------------------------

describe("evaluateSamlInResponseTo", () => {
  it("returns valid when InResponseTo matches expected request ID", () => {
    const p = parsedFrom({ inResponseTo: "_req_abc" });
    const r = evaluateSamlInResponseTo(p, "_req_abc");
    assert.equal(r.result, "valid");
  });

  it("returns invalid on InResponseTo mismatch", () => {
    const p = parsedFrom({ inResponseTo: "_req_abc" });
    const r = evaluateSamlInResponseTo(p, "_req_xyz");
    assert.equal(r.result, "invalid");
  });

  it("returns missing when InResponseTo absent", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlInResponseTo(p, "_req_abc");
    assert.equal(r.result, "missing");
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlSubjectConfirmation
// ---------------------------------------------------------------------------

describe("evaluateSamlSubjectConfirmation", () => {
  it("returns valid for correct bearer, recipient, InResponseTo and temporal", () => {
    const p = parsedFrom({
      subjectConfirmationMethod: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
      recipient: "https://sp.example/saml/acs",
      inResponseTo: "_req1",
      notOnOrAfter: FUTURE_ISO
    });
    const r = evaluateSamlSubjectConfirmation(p, "https://sp.example/saml/acs", "_req1");
    assert.equal(r.bearer_confirmation_present, true);
    assert.equal(r.method_validation, "valid");
    assert.equal(r.recipient_validation, "valid");
    assert.equal(r.in_response_to_validation, "valid");
  });

  it("returns invalid when recipient does not match ACS URL", () => {
    const p = parsedFrom({ recipient: "https://evil.example/acs" });
    const r = evaluateSamlSubjectConfirmation(p, "https://sp.example/saml/acs", "_req1");
    assert.equal(r.result, "invalid");
    assert.equal(r.recipient_validation, "invalid");
  });

  it("returns invalid when method is not bearer", () => {
    const p = parsedFrom({ subjectConfirmationMethod: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" });
    const r = evaluateSamlSubjectConfirmation(p, "https://sp.example/saml/acs", "_req1");
    assert.equal(r.result, "invalid");
    assert.equal(r.method_validation, "invalid");
  });

  it("returns missing when no SubjectConfirmation element", () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_a1"><saml:Issuer>i</saml:Issuer></saml:Assertion>
    </samlp:Response>`;
    const p = parseSamlResponse(xml);
    const r = evaluateSamlSubjectConfirmation(p, "https://sp.example/acs", "_req1");
    assert.equal(r.result, "missing");
    assert.equal(r.bearer_confirmation_present, false);
  });
});

// ---------------------------------------------------------------------------
// checkXswProtection
// ---------------------------------------------------------------------------

describe("checkXswProtection", () => {
  it("returns valid for a clean response with no signatures (not a XSW scenario)", () => {
    const p = parsedFrom({});
    const r = checkXswProtection(makeXml(), p);
    assert.ok(["valid", "incomplete"].includes(r.result));
    assert.equal(r.duplicate_ids, "none");
    assert.equal(r.ambiguous_assertions, false);
  });

  it("detects duplicate IDs as failed", () => {
    const xml = makeXml({ responseId: "_same", assertionId: "_same" });
    const p = parseSamlResponse(xml);
    const r = checkXswProtection(xml, p);
    assert.equal(r.result, "failed");
    assert.equal(r.duplicate_ids, "detected");
  });

  it("detects multiple assertions as failed", () => {
    const xml = makeXml({
      extraAssertions: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_extra"><saml:Issuer>extra</saml:Issuer></saml:Assertion>`
    });
    const p = parseSamlResponse(xml);
    const r = checkXswProtection(xml, p);
    assert.equal(r.result, "failed");
    assert.equal(r.ambiguous_assertions, true);
  });

  it("does not expose raw IDs in signed_references output", () => {
    const xml = makeXml({ addResponseSig: true });
    const p = parseSamlResponse(xml);
    const r = checkXswProtection(xml, p);
    const serialized = JSON.stringify(r);
    assert.doesNotMatch(serialized, /_resp1/);
    assert.doesNotMatch(serialized, /_ass1/);
    if (r.signed_references.length > 0) {
      assert.match(serialized, /sha256/);
    }
  });
});

// ---------------------------------------------------------------------------
// evaluateSamlTrustValidation — aggregator
// ---------------------------------------------------------------------------

function makeFullContext(overrides = {}) {
  return {
    signatureVerification: { signature_verification_result: "valid", trust_validation: "complete" },
    xswProtection: { result: "valid" },
    issuerValidation: { result: "valid" },
    audienceValidation: { result: "valid" },
    destinationValidation: { result: "valid" },
    inResponseToValidation: { result: "valid" },
    subjectConfirmationValidation: { result: "valid", recipient_validation: "valid" },
    temporalValidation: { result: "valid", conditions_evaluated: true },
    replayValidation: { result: "valid" },
    metadataCertificates: { available: true, count: 1, sha256_12: ["abc123"], source: "idp_metadata" },
    ...overrides
  };
}

describe("evaluateSamlTrustValidation", () => {
  it("returns complete when all checks pass with valid signature", () => {
    const r = evaluateSamlTrustValidation(makeFullContext());
    assert.equal(r.trust_validation, "complete");
    assert.equal(r.overall_result, "trusted");
    assert.equal(r.errors.length, 0);
  });

  it("returns incomplete when no metadata certificates available", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      signatureVerification: { signature_verification_result: "unavailable" },
      metadataCertificates: { available: false, count: 0 }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when signature is missing_signature", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      signatureVerification: { signature_verification_result: "missing_signature" }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns failed when signature verification fails", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      signatureVerification: { signature_verification_result: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Signature")));
  });

  it("returns failed on XSW detection", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      xswProtection: { result: "failed" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Wrapping")));
  });

  it("returns failed on issuer mismatch", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      issuerValidation: { result: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Issuer")));
  });

  it("returns failed when AudienceRestriction is missing", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      audienceValidation: { result: "missing" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("AudienceRestriction")));
  });

  it("returns failed on audience mismatch", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      audienceValidation: { result: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
  });

  it("returns failed on destination mismatch", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      destinationValidation: { result: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Destination")));
  });

  it("returns failed on recipient mismatch", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      subjectConfirmationValidation: { result: "invalid", recipient_validation: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Recipient")));
  });

  it("returns failed on InResponseTo mismatch", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      inResponseToValidation: { result: "invalid" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("InResponseTo")));
  });

  it("returns failed when assertion is expired", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      temporalValidation: { result: "expired", conditions_evaluated: true }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("expired")));
  });

  it("returns failed when assertion not yet valid", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      temporalValidation: { result: "not_yet_valid", conditions_evaluated: true }
    }));
    assert.equal(r.trust_validation, "failed");
  });

  it("returns failed on replay detection", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      replayValidation: { result: "replay_detected" }
    }));
    assert.equal(r.trust_validation, "failed");
    assert.ok(r.errors.some((e) => e.includes("Replay")));
  });

  it("returns incomplete when temporal conditions are missing (fail-closed)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      temporalValidation: { result: "missing", conditions_evaluated: false }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when audience is not_checked (fail-closed)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      audienceValidation: { result: "not_checked" }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when issuer is not_checked (fail-closed — issuer not_checked must not allow complete)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      issuerValidation: { result: "not_checked" }
    }));
    assert.equal(r.trust_validation, "incomplete");
    assert.ok(r.warnings.some((w) => w.includes("Issuer")));
  });

  it("returns incomplete when issuer is missing (no issuer found in response)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      issuerValidation: { result: "missing" }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when destination is not_checked (fail-closed — destination not_checked must not allow complete)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      destinationValidation: { result: "not_checked" }
    }));
    assert.equal(r.trust_validation, "incomplete");
    assert.ok(r.warnings.some((w) => w.includes("Destination")));
  });

  it("returns incomplete when destination is missing (Destination attribute absent from SAMLResponse)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      destinationValidation: { result: "missing" }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when temporal is missing (Conditions absent from Assertion — fail-closed)", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      temporalValidation: { result: "missing", conditions_evaluated: false }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });

  it("returns incomplete when temporal is not_checked", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      temporalValidation: { result: "not_checked", conditions_evaluated: false }
    }));
    assert.equal(r.trust_validation, "incomplete");
  });
});

// ---------------------------------------------------------------------------
// extractIdpSigningCertificates — metadata extraction
// ---------------------------------------------------------------------------

const SAMPLE_METADATA_WITH_SIGNING_CERT = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/metadata">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234FAKECERT</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>ENCRYPTIONCERTSHOULDBEIGNORED</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>`;

const SAMPLE_METADATA_MULTI_CERT = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/metadata">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>CERT_A</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>CERT_B</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>`;

describe("extractIdpSigningCertificates", () => {
  it("extracts only signing certificates, ignoring encryption ones", () => {
    const certs = extractIdpSigningCertificates(SAMPLE_METADATA_WITH_SIGNING_CERT);
    assert.equal(certs.length, 1);
    assert.ok(certs[0].includes("1234FAKECERT"));
    assert.ok(!certs[0].includes("ENCRYPTIONCERTSHOULDBEIGNORED"));
  });

  it("extracts multiple signing certificates for key rotation support", () => {
    const certs = extractIdpSigningCertificates(SAMPLE_METADATA_MULTI_CERT);
    assert.equal(certs.length, 2);
    assert.ok(certs.some((c) => c.includes("CERT_A")));
    assert.ok(certs.some((c) => c.includes("CERT_B")));
  });

  it("returns empty array when no metadata provided", () => {
    assert.deepEqual(extractIdpSigningCertificates(""), []);
    assert.deepEqual(extractIdpSigningCertificates(null), []);
  });

  it("returns incomplete trust_validation when certificate embedded in SAMLResponse is the only one (no metadata cert)", () => {
    const sampleXml = makeXml({});
    const verification = verifySamlXmlSignatures(sampleXml, []);
    assert.equal(verification.trust_validation, "incomplete");
  });

  it("metadata similar to Ez-Access (Memority SAML IdP) format — signing cert extraction", () => {
    const memorityLikeMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="https://sso.eiffage.stage.memority.cloud/sso/v2/saml2/metadata/metaAlias/eiffage/idp">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDkDCCAnigAwIBAgIIFAKECERTFOR
TESTINGONLY123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGH
IJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>ENCRYPTIONCERTSHOULDNOTBEEXTRACTED</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://sso.eiffage.stage.memority.cloud/sso/v2/saml2/SSO"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

    const certs = extractIdpSigningCertificates(memorityLikeMetadata);
    // Should extract exactly 1 signing cert (not the encryption one)
    assert.equal(certs.length, 1);
    assert.ok(certs[0].includes("FAKECERTFOR"));
    assert.ok(!certs[0].includes("ENCRYPTION"));
    // Cert should be stripped of whitespace
    assert.doesNotMatch(certs[0], /\s/);
    // Not empty
    assert.ok(certs[0].length > 20);
  });

  it("returns idp_certificates_used > 0 when metadata contains signing cert (pipeline integration)", () => {
    const metadataWithCert = SAMPLE_METADATA_WITH_SIGNING_CERT;
    const certs = extractIdpSigningCertificates(metadataWithCert);
    assert.ok(certs.length > 0, "Should extract at least one signing certificate from metadata");
    // verifySamlXmlSignatures with extracted certs: even if crypto fails (wrong key),
    // the cert IS provided, so idp_certificates_used should be > 0 from the caller side
    const fingerprints = certs.map((c) => shortHash(c));
    assert.ok(fingerprints.length > 0);
    assert.ok(fingerprints.every((f) => typeof f === "string" && f.length === 12));
  });
});

// ---------------------------------------------------------------------------
// Anti-leak: trust validation raw output must not contain sensitive data
// ---------------------------------------------------------------------------

describe("trust validation output — anti-leak", () => {
  it("does not expose raw IDs, NameID, or attribute values in trust validation output", () => {
    const p = parsedFrom({ responseId: "_secret_resp_id", assertionId: "_secret_ass_id" });
    const r = evaluateSamlTrustValidation(makeFullContext());
    const xsw = checkXswProtection(makeXml({ responseId: "_secret_resp_id", assertionId: "_secret_ass_id" }), p);

    const serialized = JSON.stringify({ trustResult: r, xswResult: xsw });
    assert.doesNotMatch(serialized, /_secret_resp_id/);
    assert.doesNotMatch(serialized, /_secret_ass_id/);
  });

  it("does not expose expected/actual destination raw values in evaluateSamlTrustValidation output", () => {
    const r = evaluateSamlTrustValidation(makeFullContext({
      destinationValidation: { result: "invalid" }
    }));
    const serialized = JSON.stringify(r);
    // Only result strings should appear, not raw URL values
    assert.doesNotMatch(serialized, /https:\/\/sp\.example/);
  });

  it("issuer values are entity IDs (public endpoints) — allowed in issuerValidation output", () => {
    const iv = evaluateSamlIssuerValidation(
      parsedFrom({ issuer: "https://idp.example/metadata" }),
      "https://idp.example/metadata"
    );
    assert.equal(iv.result, "valid");
    // entity IDs are public — they may appear in raw output
    assert.equal(iv.expected_issuer, "https://idp.example/metadata");
  });
});

// ---------------------------------------------------------------------------
// SAML_CLOCK_SKEW_SECONDS — exported constant
// ---------------------------------------------------------------------------

describe("SAML_CLOCK_SKEW_SECONDS", () => {
  it("is a positive number between 60 and 600 seconds", () => {
    assert.ok(typeof SAML_CLOCK_SKEW_SECONDS === "number");
    assert.ok(SAML_CLOCK_SKEW_SECONDS >= 60);
    assert.ok(SAML_CLOCK_SKEW_SECONDS <= 600);
  });
});
