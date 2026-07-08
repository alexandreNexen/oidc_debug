/**
 * Security tests for the OIDC debug application.
 *
 * Verifies that:
 *   - client_secret is never returned via API responses or server logs
 *   - sanitizeDiagnosticData redacts sensitive keys on the log path (redactObject/appLog)
 *   - input validation enforces length limits
 *   - OIDC display path shows real values (tokens, claims, scopes, payloads)
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";

import {
  analyzeTokens,
  maskSensitiveValue,
  redactObject,
  redactBodyText,
  sanitizeDiagnosticData,
  buildTokenExchangeRequest,
  buildUserInfoRequest,
  buildIntrospectionRequest,
  buildEffectiveConfig,
  normalizeProviderConfig,
  mergeDiscoveryIntoProviderConfig
} from "../src/protocols/oidc/oidc.js";

import { createFlowService } from "../src/protocols/oidc/services/flows.js";
import { validateServiceProviderInput } from "../src/protocols/oidc/services/serviceProviders.js";
import { renderFlowDetailsPage } from "../src/protocols/oidc/views/flowDetails.js";
import { renderFlowResultPage } from "../src/protocols/oidc/views/flowResult.js";
import { createSamlFlowService } from "../src/protocols/saml/services/flows.js";
import { renderSamlFlowDetailsPage } from "../src/protocols/saml/views/flowDetails.js";
import {
  parseSamlResponse,
  redactSamlRedirectUrl,
  redactSamlXml,
  shortHash,
  summarizeRelayState,
  summarizeSamlResponseXml,
  verifySamlXmlSignatures
} from "../src/protocols/saml/saml.js";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function containsSecret(obj, secret) {
  const serialized = JSON.stringify(obj);
  return serialized.includes(secret);
}

function createInMemoryFlowService() {
  let flows = [];
  let steps = [];
  let sequence = 0;

  return createFlowService({
    getFlows: () => flows,
    setFlows: (next) => {
      flows = next;
    },
    getSteps: () => steps,
    setSteps: (next) => {
      steps = next;
    },
    createId: (prefix) => `${prefix}_${++sequence}`
  });
}

function createInMemorySamlFlowService() {
  let flows = [];
  let steps = [];
  let sequence = 0;

  return createSamlFlowService({
    getFlows: () => flows,
    setFlows: (next) => {
      flows = next;
    },
    getSteps: () => steps,
    setSteps: (next) => {
      steps = next;
    },
    createId: (prefix) => `${prefix}_${++sequence}`
  });
}

const SAMPLE_SAML_XML = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response-secret-id" InResponseTo="_request-secret-id" Destination="http://localhost:3000/saml/acs/saml_sp_1">
  <saml:Issuer>https://idp.example/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_response-secret-id">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>DIGEST_SECRET_VALUE</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>SIGNATURE_SECRET_VALUE</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>CERTIFICATE_SECRET_VALUE</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
  <saml:Assertion ID="_assertion-secret-id">
    <saml:Issuer>https://idp.example/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
      <saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="http://localhost:3000/saml/acs/saml_sp_1"/></saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-05-13T10:00:00Z" NotOnOrAfter="2026-05-13T10:05:00Z">
      <saml:AudienceRestriction><saml:Audience>sp-entity</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>finance</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
    <saml:AuthnStatement SessionIndex="_session-secret-index"/>
  </saml:Assertion>
</samlp:Response>`;

// ---------------------------------------------------------------------------
// OIDC lifecycle status
// ---------------------------------------------------------------------------

describe("OIDC lifecycle status", () => {
  it("creates new OIDC flows as running and marks completed flows explicitly", () => {
    const flowService = createInMemoryFlowService();
    const flow = flowService.createFlow("sp_1", { serviceProviderName: "Test SP" });

    assert.equal(flow.status, "running");
    assert.equal(flow.completedAt, null);

    flowService.addFlowStep(flow.id, {
      stepName: "callback",
      status: "success",
      completedAt: "2026-05-12T10:00:00.000Z"
    });

    const completed = flowService.completeFlow(flow.id, {
      status: "success",
      lastStep: "userinfo"
    });

    assert.equal(completed.status, "success");
    assert.equal(completed.lastStep, "userinfo");
    assert.ok(completed.completedAt, "completedAt must be set");
    assert.ok(completed.updatedAt, "updatedAt must be set");
  });

  it("does not render ID Token analysis as pending once token analysis completed", () => {
    const html = renderFlowResultPage({
      flow: {
        id: "flow_1",
        status: "success",
        statusBadge: { label: "Success", tone: "success" },
        startedAt: "2026-05-12T10:00:00.000Z",
        durationMs: 42
      },
      serviceProvider: { name: "Test SP", clientId: "client" },
      steps: [
        { stepName: "authorize", status: "success" },
        { stepName: "callback", status: "success" },
        {
          stepName: "token",
          status: "success",
          responseData: {
            id_token_diagnostics: {
              id_token_received: "yes",
              signature_validation: "not implemented",
              overall_validation: "incomplete"
            }
          },
          rawAnalysisData: {
            validation: {
              signature: "not_implemented",
              overall: "incomplete"
            }
          }
        },
        { stepName: "userinfo", status: "success" }
      ]
    });

    assert.match(html, /ID Token analysis/);
    assert.doesNotMatch(html, /ID Token analysis[\s\S]*Pending/);
  });

  it("renders OIDC ID Token analysis without JWT signature validation wording", () => {
    const html = renderFlowDetailsPage({
      flow: {
        id: "flow_1",
        status: "success",
        statusBadge: { label: "Success", tone: "success" },
        runtime: { scopes: "openid profile email" }
      },
      serviceProvider: { name: "Test SP", clientId: "client" },
      steps: [
        { stepName: "authorize", status: "success", requestData: { scope: "openid profile email" } },
        { stepName: "callback", status: "success" },
        {
          stepName: "token",
          status: "success",
          responseData: {
            id_token: "received and decoded",
            id_token_diagnostics: {
              id_token_received: "yes",
              issuer_validation: "valid",
              audience_validation: "valid",
              expiration_validation: "valid",
              nonce_validation: "valid",
              signature_validation: "not implemented",
              overall_validation: "incomplete"
            }
          },
          rawAnalysisData: {
            source: "token_response.id_token",
            jwt: {
              header: { alg: "RS256", kid: "kid-1" },
              payload: { iss: "https://idp.example", aud: "client", exp: 1770000000, nonce: "nonce-1" }
            },
            validation: {
              issuer: "valid",
              audience: "valid",
              expiration: "valid",
              nonce: "valid",
              signature: "not_implemented",
              overall: "incomplete"
            },
            decoded: "yes",
            claims_readable: "yes"
          }
        },
        {
          stepName: "userinfo",
          status: "success",
          responseData: { raw_claims_available: "yes", received_claims: ["sub", "email"] },
          rawResponseData: { body: { claims: { sub: "user-1", email: "alice@example.test" } } }
        }
      ]
    });

    assert.match(html, /ID Token Analysis/);
    assert.match(html, /Issuer[\s\S]*valid/);
    assert.match(html, /Audience[\s\S]*valid/);
    assert.match(html, /Expiration[\s\S]*valid/);
    assert.match(html, /Nonce[\s\S]*valid/);
    assert.match(html, /Result[\s\S]*passed/);
    assert.match(html, />Raw<\/button>/);
    assert.match(html, /Scopes &amp; Claims/);
    assert.match(html, /Requested Scopes/);
    assert.match(html, /ID Token Claims/);
    assert.match(html, /Access Token Analysis/);
    assert.match(html, /Access Token Claims/);
    const scopesClaimsSection = html.match(/<section class="flow-section" data-section-panel="scopes-claims">[\s\S]*?<\/section>/)?.[0] || "";
    assert.doesNotMatch(scopesClaimsSection, /UserInfo/);
    assert.doesNotMatch(scopesClaimsSection, /Claims reçus/);
    assert.doesNotMatch(html, /Decoded, not signature-verified/i);
    assert.doesNotMatch(html, /Token incomplete/i);
    assert.doesNotMatch(html, /Signature not evaluated/i);
    assert.doesNotMatch(html, /Signature not implemented/i);
    assert.doesNotMatch(html, /not_implemented/i);
    assert.doesNotMatch(html, /overall_validation/i);
    assert.doesNotMatch(html, /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|client_secret|set-cookie/i);

    const rawJson = html.match(/data-raw-title="Raw ID Token Analysis"[\s\S]*?data-raw-json="([^"]+)"/)?.[1];
    assert.ok(rawJson, "ID Token Analysis Raw button should be present");
    const raw = JSON.parse(Buffer.from(rawJson, "base64").toString("utf8"));
    assert.deepEqual(raw.validation, {
      issuer: "valid",
      audience: "valid",
      expiration: "valid",
      nonce: "valid",
      overall: "passed"
    });
    assert.equal(raw.jwt.payload.iss, "https://idp.example");
    assert.equal(raw.jwt.payload.aud, "client");
    assert.equal(raw.validation.signature, undefined);
  });
});

// ---------------------------------------------------------------------------
// OIDC Access Token Analysis — format detection, redaction, legacy
// ---------------------------------------------------------------------------

describe("OIDC Access Token Analysis", () => {
  function base64Url(input) {
    return Buffer.from(input, "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  function makeJwt(header, payload) {
    return `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}.sig`;
  }

  function renderWithTokenStep(tokenResponseData) {
    return renderFlowDetailsPage({
      flow: {
        id: "flow_at",
        status: "success",
        statusBadge: { label: "Success", tone: "success" },
        runtime: {
          scopes: "openid profile email",
          provider: { issuer: "https://idp.example" },
          clientId: "client"
        }
      },
      serviceProvider: { name: "Test SP", clientId: "client" },
      steps: [
        { stepName: "authorize", status: "success", requestData: { scope: "openid profile email" } },
        { stepName: "callback", status: "success" },
        {
          stepName: "token",
          status: "success",
          responseData: {
            id_token: "received and decoded",
            access_token: tokenResponseData.access_token_present ? "received" : "missing",
            id_token_diagnostics: { id_token_received: "yes" },
            ...tokenResponseData
          }
        }
      ]
    });
  }

  function extractAccessTokenPanel(html) {
    const section = html.match(/<section class="flow-section" data-section-panel="scopes-claims">[\s\S]*?<\/section>/)?.[0] || "";
    return section.match(/Access Token Analysis[\s\S]*?<\/article>/)?.[0] || "";
  }

  it("renders Received/Format and validates checks when access token is a decodable JWT", () => {
    const now = Math.floor(Date.now() / 1000);
    const html = renderWithTokenStep({
      access_token_present: true,
      access_token_format: "jwt",
      access_token_header: { alg: "RS256", kid: "kid-at" },
      access_token_claims: {
        iss: "https://idp.example",
        aud: "client",
        exp: now + 3600,
        iat: now,
        scope: "openid profile",
        sub: "user-42",
        email: "alice@example.test"
      },
      access_token_decode_error: "",
      access_token_fingerprint: "abc123def456"
    });

    const panel = extractAccessTokenPanel(html);
    assert.ok(panel, "Access Token Analysis panel should be present");
    assert.match(panel, /Received[\s\S]*>yes</);
    assert.match(panel, /Format[\s\S]*>JWT</);
    assert.match(panel, /Issuer[\s\S]*>valid</);
    assert.match(panel, /Audience[\s\S]*>valid</);
    assert.match(panel, /Expiration[\s\S]*>valid</);
    assert.match(panel, /Nonce[\s\S]*>not applicable</);
    assert.match(panel, /Result[\s\S]*>passed</);
    assert.match(panel, /Access Token Claims/);
    assert.match(panel, /user-42/);
    assert.match(panel, /alice@example\.test/);
    assert.doesNotMatch(panel, /received \/ redacted/);
  });

  it("handles opaque access tokens with informational result, explanatory hint and raw value shown", () => {
    const html = renderWithTokenStep({
      access_token_present: true,
      access_token_format: "opaque",
      access_token_header: null,
      access_token_claims: null,
      access_token_decode_error: "",
      access_token_fingerprint: "fingerprint-opaque",
      access_token_value: "opaque-token-abc-123"
    });

    const panel = extractAccessTokenPanel(html);
    assert.match(panel, /Received[\s\S]*>yes</);
    assert.match(panel, /Format[\s\S]*>opaque</);
    assert.match(panel, /Issuer[\s\S]*>not available</);
    assert.match(panel, /Audience[\s\S]*>not available</);
    assert.match(panel, /Expiration[\s\S]*>not available</);
    assert.match(panel, /Nonce[\s\S]*>not applicable</);
    assert.match(panel, /Result[\s\S]*>informational</);
    assert.match(panel, /Access token received, but it is opaque and cannot be decoded as a JWT client-side\./);
    assert.match(panel, /opaque-token-abc-123/);
  });

  it("handles absent access tokens with not available everywhere", () => {
    const html = renderWithTokenStep({
      access_token_present: false,
      access_token_format: "not_available",
      access_token_header: null,
      access_token_claims: null,
      access_token_decode_error: "",
      access_token_fingerprint: ""
    });

    const panel = extractAccessTokenPanel(html);
    assert.match(panel, /Received[\s\S]*>no</);
    assert.match(panel, /Format[\s\S]*>not available</);
    assert.match(panel, /Result[\s\S]*>not available</);
    assert.match(panel, /No access token received\./);
  });

  it("handles unreadable JWT-shaped access tokens with a generic decode error", () => {
    const html = renderWithTokenStep({
      access_token_present: true,
      access_token_format: "unreadable",
      access_token_header: null,
      access_token_claims: null,
      access_token_decode_error: "Access token has JWT shape but could not be decoded.",
      access_token_fingerprint: "fingerprint-bad"
    });

    const panel = extractAccessTokenPanel(html);
    assert.match(panel, /Received[\s\S]*>yes</);
    assert.match(panel, /Format[\s\S]*>unreadable</);
    assert.match(panel, /Result[\s\S]*>informational</);
    assert.match(panel, /Access token has JWT shape but could not be decoded\./);
    assert.match(panel, /Access token received, but it could not be decoded as a JWT\./);
  });

  it("falls back to a legacy-friendly message when access token metadata is missing", () => {
    const html = renderWithTokenStep({});

    const panel = extractAccessTokenPanel(html);
    assert.match(panel, /Access token metadata is not available for this flow\. Run a new flow to capture access token diagnostics\./);
    assert.doesNotMatch(panel, /No access token received\./);
    assert.doesNotMatch(panel, />Received</);
    assert.doesNotMatch(panel, />Format</);
  });

  it("renders the raw JWT access token claims exactly as decoded", () => {
    const html = renderWithTokenStep({
      access_token_present: true,
      access_token_format: "jwt",
      access_token_header: { alg: "RS256", kid: "kid-leak" },
      access_token_claims: {
        iss: "https://idp.example",
        scope: "openid",
        sub: "secret-user-id",
        email: "alice@example.test"
      },
      access_token_decode_error: "",
      access_token_fingerprint: "leak-fingerprint"
    });

    const panel = extractAccessTokenPanel(html);
    assert.match(panel, /secret-user-id/);
    assert.match(panel, /alice@example\.test/);
    assert.doesNotMatch(panel, /received \/ redacted/);
  });

  it("keeps UserInfo claims out of the Scopes & Claims section", () => {
    const html = renderFlowDetailsPage({
      flow: {
        id: "flow_at_ui",
        status: "success",
        statusBadge: { label: "Success", tone: "success" },
        runtime: { scopes: "openid profile email" }
      },
      serviceProvider: { name: "Test SP", clientId: "client" },
      steps: [
        { stepName: "authorize", status: "success" },
        { stepName: "callback", status: "success" },
        {
          stepName: "token",
          status: "success",
          responseData: {
            id_token: "received and decoded",
            access_token: "received",
            access_token_present: true,
            access_token_format: "opaque",
            id_token_diagnostics: { id_token_received: "yes" }
          }
        },
        {
          stepName: "userinfo",
          status: "success",
          responseData: { raw_claims_available: "yes", received_claims: ["sub", "email"] }
        }
      ]
    });

    const section = html.match(/<section class="flow-section" data-section-panel="scopes-claims">[\s\S]*?<\/section>/)?.[0] || "";
    assert.ok(section, "Scopes & Claims section should be present");
    assert.doesNotMatch(section, /UserInfo/);
    assert.doesNotMatch(section, /Claims reçus/);
  });
});

// ---------------------------------------------------------------------------
// OIDC Introspection — request building and step rendering
// ---------------------------------------------------------------------------

describe("OIDC Introspection step", () => {
  function renderWithIntrospection(introspectionStep) {
    return renderFlowDetailsPage({
      flow: {
        id: "flow_intro",
        status: "success",
        statusBadge: { label: "Success", tone: "success" },
        runtime: { scopes: "openid test.read" }
      },
      serviceProvider: { name: "Test SP", clientId: "client" },
      steps: [
        { stepName: "authorize", status: "success" },
        { stepName: "callback", status: "success" },
        {
          stepName: "token",
          status: "success",
          responseData: {
            id_token: "received and decoded",
            access_token: "received",
            access_token_present: true,
            access_token_format: "opaque"
          }
        },
        introspectionStep,
        { stepName: "userinfo", status: "success", responseData: {} }
      ]
    });
  }

  function extractIntrospectionSection(html) {
    return html.match(/<section class="flow-section" data-section-panel="introspection">[\s\S]*?<\/section>/)?.[0] || "";
  }

  it("merges introspection_endpoint from discovery document", () => {
    const config = mergeDiscoveryIntoProviderConfig(normalizeProviderConfig({}), {
      issuer: "https://idp.example",
      token_endpoint: "https://idp.example/token",
      introspection_endpoint: "https://idp.example/introspect"
    });
    assert.equal(config.introspectionEndpoint, "https://idp.example/introspect");
  });

  it("builds a POST introspection request with token + token_type_hint and Basic auth", () => {
    const req = buildIntrospectionRequest({
      endpoint: "https://idp.example/introspect",
      accessToken: "secret-access-token-value",
      clientId: "client",
      clientSecret: "secret",
      tokenEndpointAuthMethod: "client_secret_basic"
    });
    assert.equal(req.method, "POST");
    assert.equal(req.headers["content-type"], "application/x-www-form-urlencoded");
    assert.match(req.headers.authorization, /^Basic /);
    assert.match(req.body, /token=secret-access-token-value/);
    assert.match(req.body, /token_type_hint=access_token/);
    assert.doesNotMatch(req.redactedBody, /secret-access-token-value/);
  });

  it("renders Introspection success with active=true, scopes and audience", () => {
    const html = renderWithIntrospection({
      stepName: "introspection",
      status: "success",
      httpMethod: "POST",
      endpoint: "https://idp.example/introspect",
      httpStatus: 200,
      requestData: { introspection_request: "sent", token_submitted: "access_token" },
      responseData: {
        introspection: "success",
        active: "yes",
        scopes: "openid, test.read",
        audience: "client",
        http_status: 200
      },
      rawRequestData: {
        method: "POST",
        url: "https://idp.example/introspect",
        body: { token: "actual-access-token-value", token_type_hint: "access_token" }
      },
      rawResponseData: {
        status: 200,
        ok: true,
        body: {
          active: true,
          scope: "openid test.read",
          client_id: "client",
          aud: "client",
          sub: "user-1",
          iss: "https://idp.example",
          exp: 1900000000,
          iat: 1899996400,
          token_type: "Bearer"
        }
      }
    });

    const section = extractIntrospectionSection(html);
    assert.ok(section, "Introspection section should be present");
    assert.match(section, /Introspection/);
    assert.match(section, /The SP asks the authorization server to inspect the access token metadata\./);
    assert.match(section, /Introspection request[\s\S]*>sent</);
    assert.match(section, /Token submitted[\s\S]*access_token/);
    assert.match(section, /Introspection<\/dt>[\s\S]*>success</);
    assert.match(section, /Active[\s\S]*>yes</);
    assert.match(section, /Scopes[\s\S]*openid, test\.read/);
    assert.match(section, /Audience[\s\S]*client/);
  });

  it("renders Introspection success with active=false and not returned scopes/audience", () => {
    const html = renderWithIntrospection({
      stepName: "introspection",
      status: "success",
      httpMethod: "POST",
      endpoint: "https://idp.example/introspect",
      httpStatus: 200,
      requestData: { introspection_request: "sent", token_submitted: "access_token" },
      responseData: {
        introspection: "success",
        active: "no",
        scopes: "not returned",
        audience: "not returned",
        http_status: 200
      },
      rawRequestData: { method: "POST", url: "https://idp.example/introspect", body: { token: "actual-access-token-value", token_type_hint: "access_token" } },
      rawResponseData: { status: 200, ok: true, body: { active: false } }
    });

    const section = extractIntrospectionSection(html);
    assert.match(section, /Introspection<\/dt>[\s\S]*>success</);
    assert.match(section, /Active[\s\S]*>no</);
    assert.match(section, /Scopes[\s\S]*not returned/);
    assert.match(section, /Audience[\s\S]*not returned/);
  });

  it("renders Introspection skipped when endpoint is missing", () => {
    const html = renderWithIntrospection({
      stepName: "introspection",
      status: "skipped",
      requestData: { introspection_request: "skipped", token_submitted: "not sent", skipped_reason: "introspection endpoint missing" },
      responseData: {
        introspection: "not available",
        active: "not available",
        scopes: "not available",
        audience: "not available",
        skipped_reason: "introspection endpoint missing"
      },
      rawRequestData: null,
      rawResponseData: null
    });

    const section = extractIntrospectionSection(html);
    assert.match(section, /Introspection request[\s\S]*>skipped</);
    assert.match(section, /Token submitted[\s\S]*>not sent</);
    assert.match(section, /Introspection<\/dt>[\s\S]*>not available</);
    assert.match(section, /Active[\s\S]*>not available</);
    assert.match(section, /Scopes[\s\S]*not available/);
    assert.match(section, /Audience[\s\S]*not available/);
  });

  it("renders Introspection failed with sanitized error details", () => {
    const html = renderWithIntrospection({
      stepName: "introspection",
      status: "error",
      httpMethod: "POST",
      endpoint: "https://idp.example/introspect",
      httpStatus: 500,
      requestData: { introspection_request: "sent", token_submitted: "access_token" },
      responseData: {
        introspection: "failed",
        active: "not available",
        scopes: "not available",
        audience: "not available",
        http_status: 500,
        introspection_error: "server_error"
      },
      rawRequestData: { method: "POST", url: "https://idp.example/introspect", body: { token: "actual-access-token-value", token_type_hint: "access_token" } },
      rawResponseData: { status: 500, ok: false, body: {} },
      errorData: { errorCode: "server_error", errorDescription: "Introspection endpoint did not return a successful response." }
    });

    const section = extractIntrospectionSection(html);
    assert.match(section, /Introspection<\/dt>[\s\S]*>failed</);
    assert.match(section, /Active[\s\S]*>not available</);
    assert.match(section, /Scopes[\s\S]*not available/);
    assert.match(section, /Audience[\s\S]*not available/);
  });

  it("exposes the raw access token and sub in the introspection panel raw data", () => {
    const rawAccessToken = "eyJraWQiOiJrIn0.eyJzdWIiOiJ1c2VyIn0.signature";
    const html = renderWithIntrospection({
      stepName: "introspection",
      status: "success",
      httpMethod: "POST",
      endpoint: "https://idp.example/introspect",
      httpStatus: 200,
      requestData: { introspection_request: "sent", token_submitted: "access_token" },
      responseData: {
        introspection: "success",
        active: "yes",
        scopes: "openid test.read",
        audience: "client",
        http_status: 200
      },
      rawRequestData: {
        method: "POST",
        url: "https://idp.example/introspect",
        body: { token: rawAccessToken, token_type_hint: "access_token" }
      },
      rawResponseData: {
        status: 200,
        ok: true,
        body: {
          active: true,
          scope: "openid test.read",
          sub: "user-1",
          aud: "client"
        }
      }
    });

    const section = extractIntrospectionSection(html);
    const rawJson = section.match(/data-raw-title="Raw Introspection Request"[\s\S]*?data-raw-json="([^"]+)"/)?.[1];
    assert.ok(rawJson, "Raw introspection request should be present");
    const rawReq = JSON.parse(Buffer.from(rawJson, "base64").toString("utf8"));
    assert.equal(rawReq.body.token, rawAccessToken);

    const rawRespJson = section.match(/data-raw-title="Raw Introspection Response"[\s\S]*?data-raw-json="([^"]+)"/)?.[1];
    assert.ok(rawRespJson, "Raw introspection response should be present");
    const rawResp = JSON.parse(Buffer.from(rawRespJson, "base64").toString("utf8"));
    assert.equal(rawResp.body.sub, "user-1");
  });
});

// ---------------------------------------------------------------------------
// OIDC Introspection endpoint mapping — discovery → provider → runtime → config
// ---------------------------------------------------------------------------

describe("OIDC Introspection endpoint mapping", () => {
  const DISCOVERY_DOC = {
    issuer: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage",
    authorization_endpoint: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/auth",
    token_endpoint: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/token",
    userinfo_endpoint: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/userinfo",
    introspection_endpoint: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/introspect",
    jwks_uri: "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/jwks"
  };

  it("normalizes introspectionEndpoint and preserves it across normalize cycles", () => {
    const normalized = normalizeProviderConfig({
      introspectionEndpoint: "https://idp.example/introspect"
    });
    assert.equal(normalized.introspectionEndpoint, "https://idp.example/introspect");

    const renormalized = normalizeProviderConfig(normalized);
    assert.equal(renormalized.introspectionEndpoint, "https://idp.example/introspect");
  });

  it("imports introspection_endpoint from the discovery document via mergeDiscoveryIntoProviderConfig", () => {
    const merged = mergeDiscoveryIntoProviderConfig(normalizeProviderConfig({}), DISCOVERY_DOC);
    assert.equal(
      merged.introspectionEndpoint,
      "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/introspect"
    );
  });

  it("threads the introspection endpoint through buildEffectiveConfig", () => {
    const provider = mergeDiscoveryIntoProviderConfig(normalizeProviderConfig({}), DISCOVERY_DOC);
    const effective = buildEffectiveConfig({
      providerConfig: provider,
      serviceProvider: { id: "sp", name: "SP", clientId: "client", clientType: "confidential", scopes: "openid" },
      clientSecret: "secret"
    });
    assert.equal(
      effective.introspectionEndpoint,
      "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/introspect"
    );
  });

  it("keeps legacy provider configs working when introspection_endpoint is absent", () => {
    const legacyDoc = { ...DISCOVERY_DOC };
    delete legacyDoc.introspection_endpoint;

    const merged = mergeDiscoveryIntoProviderConfig(normalizeProviderConfig({}), legacyDoc);
    assert.equal(merged.introspectionEndpoint, "");

    const effective = buildEffectiveConfig({
      providerConfig: merged,
      serviceProvider: { id: "sp", name: "SP", clientId: "client", clientType: "confidential", scopes: "openid" },
      clientSecret: "secret"
    });
    assert.equal(effective.introspectionEndpoint, "");
  });

  it("preserves an existing introspectionEndpoint when a re-imported discovery omits the field", () => {
    const initial = mergeDiscoveryIntoProviderConfig(normalizeProviderConfig({}), DISCOVERY_DOC);
    const docWithoutIntrospection = { ...DISCOVERY_DOC };
    delete docWithoutIntrospection.introspection_endpoint;

    const reMerged = mergeDiscoveryIntoProviderConfig(initial, docWithoutIntrospection);
    assert.equal(
      reMerged.introspectionEndpoint,
      "https://sso.eiffage.stage.memority.cloud/sso/v2/oauth2/eiffage/introspect"
    );
  });
});

// ---------------------------------------------------------------------------
// SAML diagnostics — safe raw data and trust wording
// ---------------------------------------------------------------------------

describe("SAML diagnostics", () => {
  it("redacts XMLDSig values, certificates, session indexes, IDs, NameID and attributes in SAML XML", () => {
    const redacted = redactSamlXml(SAMPLE_SAML_XML);

    assert.doesNotMatch(redacted, /SIGNATURE_SECRET_VALUE/);
    assert.doesNotMatch(redacted, /DIGEST_SECRET_VALUE/);
    assert.doesNotMatch(redacted, /CERTIFICATE_SECRET_VALUE/);
    assert.doesNotMatch(redacted, /_session-secret-index/);
    assert.doesNotMatch(redacted, /_response-secret-id/);
    assert.doesNotMatch(redacted, /_assertion-secret-id/);
    assert.doesNotMatch(redacted, /alice@example\.com/);
    assert.doesNotMatch(redacted, />admins</);
    assert.doesNotMatch(redacted, />finance</);

    assert.match(redacted, /\[redacted signature value sha256:[a-f0-9]{12}\]/);
    assert.match(redacted, /\[redacted digest value sha256:[a-f0-9]{12}\]/);
    assert.match(redacted, /\[redacted certificate sha256:[a-f0-9]{12}\]/);
    assert.match(redacted, /\[redacted session index sha256:[a-f0-9]{12}\]/);
    assert.match(redacted, /\[redacted nameid sha256:[a-f0-9]{12}\]/);
    assert.match(redacted, new RegExp(`ID="\\[redacted response id sha256:${shortHash("_response-secret-id")}\\]"`));
    assert.match(redacted, new RegExp(`URI="#\\[redacted reference id sha256:${shortHash("_response-secret-id")}\\]"`));
    assert.match(redacted, new RegExp(`ID="\\[redacted assertion id sha256:${shortHash("_assertion-secret-id")}\\]"`));
    assert.match(redacted, new RegExp(`SessionIndex="\\[redacted session index sha256:${shortHash("_session-secret-index")}\\]"`));
    assert.equal(redactSamlXml(redacted), redacted);
  });

  it("summarizes SAMLResponse raw diagnostics without exposing base64, signature, digest, certificate or personal values", () => {
    const summary = summarizeSamlResponseXml(SAMPLE_SAML_XML);
    const serialized = JSON.stringify(summary);

    assert.equal(summary.response_id.present, true);
    assert.equal(summary.assertion_id.present, true);
    assert.equal(summary.signatures.response, "present");
    assert.equal(summary.signatures.assertion, "missing");
    assert.equal(summary.certificates.embedded, "present");
    assert.deepEqual(summary.signatures.signature_algorithms, ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]);
    assert.deepEqual(summary.signatures.digest_algorithms, ["http://www.w3.org/2001/04/xmlenc#sha256"]);
    assert.doesNotMatch(serialized, /SIGNATURE_SECRET_VALUE|DIGEST_SECRET_VALUE|CERTIFICATE_SECRET_VALUE|alice@example\.com|admins|finance/);
  });

  it("redacts identity assertion values while keeping counts, names and hashes", () => {
    const parsed = parseSamlResponse(SAMPLE_SAML_XML);
    const serialized = JSON.stringify(parsed.attributes);

    assert.equal(parsed.nameIdPreview, "received / redacted");
    assert.equal(parsed.nameIdHash, shortHash("alice@example.com"));
    assert.equal(Object.keys(parsed.attributes).length, 2);
    assert.deepEqual(parsed.attributeNames, ["mail", "groups"]);
    assert.equal(parsed.attributes.groups.values_count, 2);
    assert.match(serialized, /received \/ redacted/);
    assert.doesNotMatch(serialized, /alice@example\.com|admins|finance/);
  });

  it("does not persist raw RelayState in new SAML flows and can still match callbacks by hash", () => {
    const flowService = createInMemorySamlFlowService();
    const relayState = "relay-state-secret-value";
    const flow = flowService.createFlow("saml_sp_1", {
      relayState,
      requestId: "_request",
      acsUrl: "http://localhost:3000/saml/acs/saml_sp_1"
    });

    assert.equal(flow.runtime.relayState, "received / redacted");
    assert.equal(flow.runtime.relayStateSha25612, shortHash(relayState));
    assert.equal(flowService.findRunningFlowByRelayState(relayState, 30 * 60 * 1000).id, flow.id);
    assert.ok(!JSON.stringify(flowService.listFlows()).includes(relayState));
  });

  it("summarizes Redirect parameters without exposing SAMLRequest, RelayState or Signature query values", () => {
    const url = "https://idp.example/sso?SAMLRequest=REQUEST_SECRET&RelayState=RELAY_SECRET&Signature=SIGNATURE_SECRET";
    const redacted = redactSamlRedirectUrl(url);
    const redactedAgain = redactSamlRedirectUrl(redacted);
    const relaySummary = summarizeRelayState("RELAY_SECRET");

    assert.doesNotMatch(redacted, /REQUEST_SECRET|RELAY_SECRET|SIGNATURE_SECRET/);
    assert.equal(redactedAgain, redacted);
    assert.equal(relaySummary.present, true);
    assert.equal(relaySummary.sha256_12, shortHash("RELAY_SECRET"));
    assert.ok(!("preview" in relaySummary));
  });

  it("marks trust validation as incomplete when signatures are present but trusted verification is unavailable", () => {
    const verification = verifySamlXmlSignatures(SAMPLE_SAML_XML, []);

    assert.equal(verification.response_signature_present, "present");
    assert.equal(verification.response_signature_verification, "unavailable");
    assert.equal(verification.trust_validation, "incomplete");
    assert.equal(
      verification.verification_note,
      "Signature detected, but no trusted IdP signing certificate from metadata was available for verification."
    );
  });

  it("renders an explicit warning that SAML Success does not mean trusted assertion and keeps Identity raw scoped", () => {
    const html = renderSamlFlowDetailsPage({
      flow: { id: "saml_flow_1", status: "success", startedAt: "2026-05-13T10:00:00.000Z", durationMs: 1, runtime: {} },
      serviceProvider: { id: "saml_sp_1", name: "SP" },
      steps: [
        { stepName: "authn_request_created", status: "success" },
        { stepName: "redirect_to_idp", status: "success" },
        { stepName: "saml_response_received", status: "success" },
        {
          stepName: "saml_response_decoded",
          status: "success",
          responseData: {
            assertion_present: "yes",
            subject_present: "yes",
            name_id_present: "yes",
            name_id_preview: "received / redacted",
            name_id_hash: shortHash("alice@example.com"),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            saml_status: "Success",
            attributes_count: 2,
            attribute_names: ["mail", "groups"],
            attributes_redacted: {
              mail: {
                values_count: 1,
                values: [{ present: "present", sha256_12: shortHash("alice@example.com"), redacted: "received / redacted" }]
              }
            },
            response_signature_present: "present",
            response_signature_verification: "unavailable",
            assertion_signature_present: "missing",
            assertion_signature_verification: "not_checked",
            signature_verification_result: "unavailable",
            trust_validation: "incomplete",
            idp_certificates_used: 0,
            diagnostic_comparisons: {
              in_response_to_vs_request_id: "match",
              destination_vs_acs_url: "match",
              audience_vs_sp_entity_id: "match",
              temporal_conditions: "present / not evaluated"
            }
          },
          rawResponseData: {
            assertion: {
              present: "yes",
              subject_present: "yes",
              name_id_present: "yes",
              name_id_preview: "received / redacted",
              name_id_hash: shortHash("alice@example.com"),
              name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              attributes_count: 2,
              attribute_names: ["mail", "groups"],
              attributes_redacted: {
                mail: {
                  values_count: 1,
                  values: [{ present: "present", sha256_12: shortHash("alice@example.com"), redacted: "received / redacted" }]
                }
              },
              session_index: { present: true, sha256_12: shortHash("_session-secret-index") },
              conditions_present: "yes",
              conditions_evaluated: "no",
              temporal_conditions_status: "present / not evaluated",
              audience_restriction_present: "yes",
              audience: "sp-entity",
              subject_confirmation_present: "yes",
              recipient: "http://localhost:3000/saml/acs/saml_sp_1",
              not_before: "2026-05-13T10:00:00Z",
              not_on_or_after: "2026-05-13T10:05:00Z"
            },
            signature: { trust_validation: "incomplete" }
          }
        }
      ]
    });

    assert.match(html, /Trust validation incomplete/);
    assert.match(html, /present \/ not evaluated/);
    assert.doesNotMatch(html, /alice@example\.com/);

    const rawJson = html.match(/data-raw-title="Raw identity summary"[\s\S]*?data-raw-json="([^"]+)"/)?.[1];
    assert.ok(rawJson, "Identity summary raw button must be present");
    const raw = JSON.parse(Buffer.from(rawJson, "base64").toString("utf8"));
    const serializedRaw = JSON.stringify(raw);

    assert.deepEqual(Object.keys(raw.assertion), [
      "present",
      "subject_present",
      "name_id_present",
      "name_id_preview",
      "name_id_hash",
      "name_id_format",
      "attributes_count",
      "attribute_names",
      "attributes_redacted"
    ]);
    assert.doesNotMatch(serializedRaw, /session_index|conditions_present|conditions_evaluated|temporal_conditions_status/);
    assert.doesNotMatch(serializedRaw, /audience_restriction_present|audience|subject_confirmation_present|recipient/);
    assert.doesNotMatch(serializedRaw, /not_before|not_on_or_after/);
  });
});

// ---------------------------------------------------------------------------
// analyzeTokens — display path exposes real values, must not add a "raw" key
// ---------------------------------------------------------------------------

describe("analyzeTokens", () => {
  const fakeTokenResponse = {
    access_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SIGNATURE_FAKE",
    id_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6OTk5OTk5OTk5OX0.SIGNATURE_FAKE",
    refresh_token: "refresh_opaque_value_abc123",
    expires_in: 3600,
    token_type: "Bearer"
  };

  it("exposes the raw access_token value for display", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.equal(result.accessToken.value, fakeTokenResponse.access_token);
  });

  it("exposes the raw id_token value for display", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.equal(result.idToken.value, fakeTokenResponse.id_token);
  });

  it("exposes the raw refresh_token value for display", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.equal(result.refreshToken.value, fakeTokenResponse.refresh_token);
    assert.equal(result.refreshToken.present, true);
  });

  it("does not expose the original tokenResponse as 'raw'", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.ok(!("raw" in result), "analyzeTokens output contains a 'raw' key exposing the full token response");
  });
});

// ---------------------------------------------------------------------------
// redactObject — must strip client_secret and tokens
// ---------------------------------------------------------------------------

describe("redactObject", () => {
  it("redacts client_secret", () => {
    const result = redactObject({ client_secret: "supersecret123" });
    assert.ok(!containsSecret(result, "supersecret123"), "client_secret found in redactObject output");
  });

  it("redacts access_token", () => {
    const result = redactObject({ access_token: "token_value_xyz" });
    assert.ok(!containsSecret(result, "token_value_xyz"), "access_token found in redactObject output");
  });

  it("redacts id_token", () => {
    const result = redactObject({ id_token: "jwt.payload.sig" });
    assert.ok(!containsSecret(result, "jwt.payload.sig"), "id_token found in redactObject output");
  });

  it("redacts Authorization header", () => {
    const result = redactObject({ authorization: "Basic dXNlcjpwYXNz" });
    assert.ok(!containsSecret(result, "dXNlcjpwYXNz"), "Authorization header value found in redactObject output");
  });

  it("redacts nested client_secret", () => {
    const result = redactObject({ request: { body: { client_secret: "nested_secret" } } });
    assert.ok(!containsSecret(result, "nested_secret"), "nested client_secret found in redactObject output");
  });

  it("preserves non-sensitive fields", () => {
    const result = redactObject({ client_id: "my-client", scope: "openid" });
    assert.equal(result.client_id, "my-client");
    assert.equal(result.scope, "openid");
  });
});

// ---------------------------------------------------------------------------
// sanitizeDiagnosticData — tokens become "received"/"missing", not their values
// ---------------------------------------------------------------------------

describe("sanitizeDiagnosticData", () => {
  it("replaces access_token value with presence indicator", () => {
    const result = sanitizeDiagnosticData({ access_token: "real_token" }, "");
    assert.ok(!containsSecret(result, "real_token"), "access_token value found after sanitizeDiagnosticData");
    const body = sanitizeDiagnosticData({ body: { access_token: "real_token" } }, "");
    assert.ok(!containsSecret(body, "real_token"), "access_token in body found after sanitizeDiagnosticData");
  });

  it("replaces id_token value with presence indicator", () => {
    const result = sanitizeDiagnosticData({ body: { id_token: "jwt.payload.sig" } }, "");
    assert.ok(!containsSecret(result, "jwt.payload.sig"), "id_token value found after sanitizeDiagnosticData");
  });

  it("replaces client_secret with ********", () => {
    const result = sanitizeDiagnosticData({ client_secret: "secret_val" }, "");
    assert.ok(!containsSecret(result, "secret_val"), "client_secret value found after sanitizeDiagnosticData");
  });

  it("replaces Authorization Bearer header value", () => {
    const result = sanitizeDiagnosticData({ authorization: "Bearer real_access_token" }, "");
    assert.ok(!containsSecret(result, "real_access_token"), "Bearer token found in sanitizeDiagnosticData output");
    assert.equal(result.authorization, "Bearer ********");
  });

  it("replaces Authorization Basic header value", () => {
    const result = sanitizeDiagnosticData({ authorization: "Basic dXNlcjpwYXNz" }, "");
    assert.ok(!containsSecret(result, "dXNlcjpwYXNz"), "Basic credentials found in sanitizeDiagnosticData output");
    assert.equal(result.authorization, "Basic ********");
  });

  it("replaces cookie header value", () => {
    const result = sanitizeDiagnosticData({ cookie: "session=abc123" }, "");
    assert.ok(!containsSecret(result, "abc123"), "Cookie value found in sanitizeDiagnosticData output");
  });
});

// ---------------------------------------------------------------------------
// redactBodyText — form-encoded and JSON bodies
// ---------------------------------------------------------------------------

describe("redactBodyText", () => {
  it("redacts client_secret in form-encoded body", () => {
    const body = "grant_type=authorization_code&code=auth_code_123&client_secret=mysecret&redirect_uri=https%3A%2F%2Fexample.com%2Fcb";
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes("mysecret"), "client_secret found in redacted form body");
    assert.ok(result.includes("grant_type=authorization_code"), "grant_type was incorrectly redacted");
  });

  it("redacts code in form-encoded body", () => {
    const body = "grant_type=authorization_code&code=auth_code_secret_value";
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes("auth_code_secret_value"), "authorization code value found in redacted form body");
  });

  it("redacts access_token in JSON body", () => {
    const body = JSON.stringify({ access_token: "real_token", token_type: "Bearer" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes("real_token"), "access_token found in redacted JSON body");
  });

  it("redacts client_secret in JSON body", () => {
    const body = JSON.stringify({ client_secret: "my_secret", client_id: "my_client" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes("my_secret"), "client_secret found in redacted JSON body");
    assert.ok(result.includes("my_client"), "client_id was incorrectly redacted");
  });
});

// ---------------------------------------------------------------------------
// buildTokenExchangeRequest — raw request must not expose secret in params
// ---------------------------------------------------------------------------

describe("buildTokenExchangeRequest", () => {
  const config = buildEffectiveConfig({
    providerConfig: normalizeProviderConfig({
      tokenEndpoint: "https://idp.example.com/token",
      redirectUri: "https://app.example.com/callback"
    }),
    serviceProvider: { clientId: "test_client", clientType: "confidential", scopes: "openid" },
    clientSecret: "super_secret_value",
    redirectUri: "https://app.example.com/callback"
  });

  const request = buildTokenExchangeRequest({
    config,
    code: "authorization_code_value",
    codeVerifier: "pkce_verifier_value"
  });

  it("does not include client_secret in params object", () => {
    assert.ok(!containsSecret(request.params || {}, "super_secret_value"), "client_secret found in request.params");
  });

  it("does not include raw authorization code in params", () => {
    // code IS in params (needed for the request), but its value should not leak via redactedBody
    const redacted = JSON.stringify(request.redactedBody || "");
    assert.ok(!redacted.includes("authorization_code_value"), "raw authorization code found in redactedBody");
  });

  it("does not include client_secret in redactedBody", () => {
    assert.ok(!containsSecret(request.redactedBody || "", "super_secret_value"), "client_secret found in redactedBody");
  });
});

// ---------------------------------------------------------------------------
// buildUserInfoRequest — Authorization header must be redactable
// ---------------------------------------------------------------------------

describe("buildUserInfoRequest", () => {
  it("places access_token in Authorization header (to be redacted by sanitize)", () => {
    const request = buildUserInfoRequest({
      endpoint: "https://idp.example.com/userinfo",
      accessToken: "raw_access_token_value"
    });
    // The raw request does contain the token in headers (it must, for the actual request)
    // but sanitizeDiagnosticData must redact it
    const sanitized = sanitizeDiagnosticData(request.headers || {}, "");
    assert.ok(
      !containsSecret(sanitized, "raw_access_token_value"),
      "access_token still visible in sanitized userInfo request headers"
    );
  });
});

// ---------------------------------------------------------------------------
// validateServiceProviderInput — length limits
// ---------------------------------------------------------------------------

describe("validateServiceProviderInput — length limits", () => {
  const base = {
    name: "Test SP",
    environment: "preprod",
    client_id: "client123",
    client_secret: "secret123",
    scopes: "openid profile"
  };

  it("rejects name exceeding 255 characters", () => {
    const input = { ...base, name: "a".repeat(256) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for name > 255 chars");
    assert.ok(result.errors.name, "name error should be present");
  });

  it("accepts name at exactly 255 characters", () => {
    const input = { ...base, name: "a".repeat(255) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.errors.name, "name error should not be present for exactly 255 chars");
  });

  it("rejects clientId exceeding 256 characters", () => {
    const input = { ...base, client_id: "c".repeat(257) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for clientId > 256 chars");
    assert.ok(result.errors.client_id, "client_id error should be present");
  });

  it("rejects scopes exceeding 512 characters", () => {
    const input = { ...base, scopes: "openid " + "scope ".repeat(100) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for scopes > 512 chars");
    assert.ok(result.errors.scopes, "scopes error should be present");
  });

  it("rejects clientSecret exceeding 512 characters", () => {
    const input = { ...base, client_secret: "s".repeat(513) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for clientSecret > 512 chars");
    assert.ok(result.errors.client_secret, "client_secret error should be present");
  });
});

// ---------------------------------------------------------------------------
// maskSensitiveValue — sensitive keys masked, non-sensitive preserved
// ---------------------------------------------------------------------------

describe("maskSensitiveValue", () => {
  it("masks client_secret fully for short values", () => {
    assert.equal(maskSensitiveValue("client_secret", "short"), "********");
  });

  it("partially masks long token values", () => {
    const token = "eyJhbGciOiJSUzI1NiJ9_long_token";
    const result = maskSensitiveValue("access_token", token);
    assert.ok(!result.includes(token), "full token value found in masked output");
    assert.ok(result.includes("..."), "masked output should contain '...' for long values");
  });

  it("does not mask non-sensitive keys", () => {
    assert.equal(maskSensitiveValue("client_id", "my-client"), "my-client");
    assert.equal(maskSensitiveValue("scope", "openid profile"), "openid profile");
  });
});

// ---------------------------------------------------------------------------
// Leak test — LEAK_TEST_CLIENT_SECRET_DO_NOT_EXPOSE must never appear in output
// ---------------------------------------------------------------------------

describe("client_secret leak prevention", () => {
  const LEAK_MARKER = "LEAK_TEST_CLIENT_SECRET_DO_NOT_EXPOSE";

  it("encrypted record does not contain the plaintext secret", () => {
    // Simulate what server.js encryptSecret does (without the key — test at the contract level)
    // redactObject should catch any object that has client_secret
    const objectWithSecret = { client_secret: LEAK_MARKER };
    const redacted = redactObject(objectWithSecret);
    assert.ok(!containsSecret(redacted, LEAK_MARKER), "LEAK: client_secret found in redactObject output");
  });

  it("sanitizeDiagnosticData removes the secret value", () => {
    const data = {
      body: { client_secret: LEAK_MARKER, grant_type: "authorization_code" },
      headers: { authorization: `Basic ${Buffer.from(`client:${LEAK_MARKER}`).toString("base64")}` }
    };
    const sanitized = sanitizeDiagnosticData(data);
    assert.ok(!containsSecret(sanitized, LEAK_MARKER), "LEAK: client_secret found in sanitizeDiagnosticData output");
  });

  it("redactBodyText removes secret from form-encoded body", () => {
    const body = `grant_type=authorization_code&client_secret=${encodeURIComponent(LEAK_MARKER)}&code=abc`;
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret found in redactBodyText output");
  });

  it("redactBodyText removes secret from JSON body", () => {
    const body = JSON.stringify({ client_secret: LEAK_MARKER, client_id: "legit" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret found in redactBodyText JSON output");
  });

  it("maskSensitiveValue masks the secret", () => {
    const result = maskSensitiveValue("client_secret", LEAK_MARKER);
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret value found in maskSensitiveValue output");
  });

  it("validateServiceProviderInput does not echo back the secret in errors", () => {
    const input = { name: "Test", environment: "preprod", client_id: "id", client_secret: LEAK_MARKER, scopes: "openid" };
    const result = validateServiceProviderInput(input, { mode: "create" });
    // values object will contain the secret — this is intentional (it's used by the service layer to encrypt)
    // but it must not be echoed back via errors or warnings
    const errorsAndWarnings = JSON.stringify({ errors: result.errors, warnings: result.warnings });
    assert.ok(!errorsAndWarnings.includes(LEAK_MARKER), "LEAK: client_secret found in validation errors/warnings");
  });
});

// ---------------------------------------------------------------------------
// XSS prevention — malicious claims must be inoffensive in all output paths
// ---------------------------------------------------------------------------

describe("XSS prevention in output", () => {
  const XSS_PAYLOAD = '<script>alert("xss")</script>';

  it("escapeHtml neutralizes script tags", async () => {
    const { escapeHtml } = await import("../src/common/views/layout.js");
    const result = escapeHtml(XSS_PAYLOAD);
    assert.ok(!result.includes("<script>"), "XSS: <script> tag found after escapeHtml");
    assert.ok(result.includes("&lt;script&gt;"), "escapeHtml did not encode <script> to &lt;script&gt;");
  });

  it("sanitizeDiagnosticData does not execute or inject script payloads", () => {
    const data = {
      name: XSS_PAYLOAD,
      email: `user@example.com${XSS_PAYLOAD}`,
      sub: "normal_value"
    };
    const sanitized = sanitizeDiagnosticData(data);
    // Values should pass through unchanged (sanitize is for secrets, not XSS)
    // XSS safety comes from escapeHtml in views — verify the raw value is preserved for escaping later
    assert.equal(sanitized.name, XSS_PAYLOAD, "sanitizeDiagnosticData should preserve non-sensitive string values");
    assert.equal(sanitized.sub, "normal_value");
  });

  it("redactObject preserves non-sensitive XSS payload (escaping is the view's responsibility)", () => {
    const obj = { name: XSS_PAYLOAD, client_id: "legit" };
    const result = redactObject(obj);
    assert.equal(result.name, XSS_PAYLOAD, "non-sensitive field should pass through redactObject unchanged");
    assert.equal(result.client_id, "legit");
  });
});

// ---------------------------------------------------------------------------
// Key separation — session signing key != encryption key
// ---------------------------------------------------------------------------

describe("application key derivation separation", () => {
  it("session signing key differs from encryption key when derived from the same master", () => {
    const master = "a-strong-master-secret-value-minimum-32-chars!!";
    const signingKey = crypto.createHmac("sha256", master).update("oidc-debug:session:v1").digest("hex");
    const encKey = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    assert.notEqual(signingKey, encKey, "Session signing key and encryption key must differ");
  });

  it("key derivation is deterministic for the same master secret", () => {
    const master = "another-master-secret-value-32-chars!!!!!";
    const key1 = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    const key2 = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    assert.equal(key1, key2, "Key derivation must be deterministic");
  });

  it("different master secrets produce different derived keys", () => {
    const key1 = crypto.createHmac("sha256", "master-secret-one-32chars!!!!!!!!").update("oidc-debug:encryption:v1").digest("hex");
    const key2 = crypto.createHmac("sha256", "master-secret-two-32chars!!!!!!!!").update("oidc-debug:encryption:v1").digest("hex");
    assert.notEqual(key1, key2, "Different master secrets must produce different derived keys");
  });
});
