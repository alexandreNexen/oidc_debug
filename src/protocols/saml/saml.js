import crypto from "node:crypto";
import { createRequire } from "node:module";
import zlib from "node:zlib";

const _require = createRequire(import.meta.url);
let _SignedXml = null;
let _DOMParser = null;
try {
  _SignedXml = _require("xml-crypto").SignedXml;
  _DOMParser = _require("@xmldom/xmldom").DOMParser;
} catch {
  // xml-crypto not installed — signature verification unavailable
}

const REDACTED_VALUE = "[redacted]";
const MAX_REDACTED_XML_LENGTH = 12000;

export function generateAuthnRequestId() {
  return `_${crypto.randomBytes(16).toString("hex")}`;
}

export function generateRelayState() {
  return crypto.randomBytes(24).toString("base64url");
}

export function buildAuthnRequestXml({ requestId, issueInstant, destination, acsUrl, spEntityId, nameIdFormat }) {
  const nameIdPolicy = nameIdFormat
    ? `<samlp:NameIDPolicy Format="${nameIdFormat}" AllowCreate="true"/>`
    : `<samlp:NameIDPolicy AllowCreate="true"/>`;

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<samlp:AuthnRequest`,
    `  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`,
    `  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`,
    `  ID="${requestId}"`,
    `  Version="2.0"`,
    `  IssueInstant="${issueInstant}"`,
    `  Destination="${destination}"`,
    `  AssertionConsumerServiceURL="${acsUrl}"`,
    `  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`,
    `  <saml:Issuer>${spEntityId}</saml:Issuer>`,
    `  ${nameIdPolicy}`,
    `</samlp:AuthnRequest>`
  ].join("\n");
}

export function encodeAuthnRequestForRedirect(xml) {
  const deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"));
  return deflated.toString("base64");
}

export function buildSsoRedirectUrl(ssoUrl, samlRequestParam, relayState) {
  const target = new URL(ssoUrl);
  target.searchParams.set("SAMLRequest", samlRequestParam);
  target.searchParams.set("RelayState", relayState);
  return target.toString();
}

export function shortHash(value = "", length = 12) {
  if (value === null || value === undefined || value === "") return "";
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex").slice(0, length);
}

function byteLength(value = "") {
  return Buffer.byteLength(String(value), "utf8");
}

function redactedPreview(value = "") {
  const text = String(value || "");
  if (!text) return "";
  return `${text.slice(0, 4)}...[redacted:${shortHash(text)}]`;
}

export function maskSamlValue(value = "") {
  const text = String(value || "").trim();
  if (!text) return "";
  const emailMatch = text.match(/^(.{1,2})[^@]*(@.+)$/);
  if (emailMatch) {
    return `${emailMatch[1]}***${emailMatch[2]}`;
  }
  return `${text.slice(0, 2)}***[redacted]`;
}

export function summarizeSensitiveValue(value = "", { includePreview = false } = {}) {
  const text = String(value || "");
  if (!text) {
    return { present: false };
  }

  return {
    present: true,
    size_bytes: byteLength(text),
    sha256_12: shortHash(text),
    ...(includePreview ? { preview: redactedPreview(text) } : {})
  };
}

export function summarizeEncodedSamlParam(value = "") {
  const summary = summarizeSensitiveValue(value);
  return summary.present ? summary : { present: false };
}

export function summarizeRelayState(value = "") {
  return summarizeSensitiveValue(value, { includePreview: true });
}

function redactXmlTextContent(xml, localName, label) {
  const pattern = new RegExp(`(<(?:[^:>]+:)?${localName}[^>]*>)([\\s\\S]*?)(<\\/(?:[^:>]+:)?${localName}>)`, "gi");
  return xml.replace(pattern, (_match, open, value, close) => {
    const text = String(value || "").trim();
    const marker = text ? `[redacted ${label} sha256:${shortHash(text)}]` : REDACTED_VALUE;
    return `${open}${marker}${close}`;
  });
}

export function redactSamlXml(xml = "", { maxLength = MAX_REDACTED_XML_LENGTH } = {}) {
  if (!xml) return "";

  let redacted = String(xml)
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted private key]")
    .replace(/(<(?:[^:>]+:)?X509Certificate[^>]*>)([\s\S]*?)(<\/(?:[^:>]+:)?X509Certificate>)/gi, (_match, open, value, close) => {
      const normalized = String(value || "").replace(/\s+/g, "");
      return `${open}[redacted certificate sha256:${shortHash(normalized)}]${close}`;
    });

  redacted = redactXmlTextContent(redacted, "NameID", "nameid");
  redacted = redactXmlTextContent(redacted, "AttributeValue", "attribute_value");
  redacted = redacted.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, (match) => `${maskSamlValue(match)} [sha256:${shortHash(match)}]`);

  if (redacted.length <= maxLength) {
    return redacted;
  }

  return `${redacted.slice(0, maxLength)}\n...[truncated ${redacted.length - maxLength} chars after redaction]`;
}

export function redactSamlRedirectUrl(url = "") {
  if (!url) return "";
  try {
    const target = new URL(url);
    for (const key of ["SAMLRequest", "SAMLResponse", "RelayState", "Signature"]) {
      const value = target.searchParams.get(key);
      if (value) {
        target.searchParams.set(key, `[redacted sha256:${shortHash(value)} size:${byteLength(value)}]`);
      }
    }
    return target.toString();
  } catch {
    return "[redacted invalid url]";
  }
}

function extractXmlAttr(xml, pattern) {
  const match = xml.match(pattern);
  return match ? match[1].trim() : "";
}

function extractXmlText(xml, pattern) {
  const match = xml.match(pattern);
  return match ? match[1].trim() : "";
}

function extractXmlElement(xml, localName) {
  const pattern = new RegExp(`<(?:[^:>]+:)?${localName}\\b[\\s\\S]*?<\\/(?:[^:>]+:)?${localName}>`, "i");
  const match = xml.match(pattern);
  return match ? match[0] : "";
}

function extractXmlAttrFromElement(element, attrName) {
  return extractXmlAttr(element, new RegExp(`${attrName}="([^"]+)"`, "i"));
}

function hasXmlElement(xml, localName) {
  return new RegExp(`<[^>]*:?${localName}\\b`, "i").test(xml);
}

function directResponseSignaturePresent(xml, assertionXml) {
  const assertionIndex = assertionXml ? xml.indexOf(assertionXml) : -1;
  const responseScope = assertionIndex >= 0 ? xml.slice(0, assertionIndex) : xml;
  return hasXmlElement(responseScope, "Signature");
}

export function parseIdpMetadata(xml) {
  const entityId =
    extractXmlAttr(xml, /EntityDescriptor[^>]+entityID="([^"]+)"/i) ||
    extractXmlAttr(xml, /EntityDescriptor[^>]+entityID='([^']+)'/i);

  // Prefer HTTP-Redirect SSO, fall back to HTTP-POST
  const ssoRedirect =
    extractXmlAttr(xml, /SingleSignOnService[^>]+Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]+Location="([^"]+)"/i) ||
    extractXmlAttr(xml, /SingleSignOnService[^>]+Location="([^"]+)"[^>]+Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"/i);

  const ssoPost =
    extractXmlAttr(xml, /SingleSignOnService[^>]+Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]+Location="([^"]+)"/i) ||
    extractXmlAttr(xml, /SingleSignOnService[^>]+Location="([^"]+)"[^>]+Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"/i);

  const certificate = extractXmlText(xml, /<(?:[^:>]+:)?X509Certificate[^>]*>\s*([A-Za-z0-9+/=\s]+?)\s*<\/(?:[^:>]+:)?X509Certificate>/i);

  return {
    entityId,
    ssoUrl: ssoRedirect || ssoPost || "",
    ssoBinding: ssoRedirect ? "HTTP-Redirect" : ssoPost ? "HTTP-POST" : "",
    hasCertificate: Boolean(certificate)
  };
}

export function decodeSamlResponse(base64) {
  return Buffer.from(base64, "base64").toString("utf8");
}

export function parseSamlResponse(xml) {
  const assertionXml = extractXmlElement(xml, "Assertion");
  const subjectXml = assertionXml ? extractXmlElement(assertionXml, "Subject") : "";
  const conditionsXml = assertionXml ? extractXmlElement(assertionXml, "Conditions") : "";
  const subjectConfirmationXml = assertionXml ? extractXmlElement(assertionXml, "SubjectConfirmation") : "";
  const audience = assertionXml ? extractXmlText(assertionXml, /<(?:[^:>]+:)?Audience[^>]*>([^<]+)<\/(?:[^:>]+:)?Audience>/i) : "";
  const statusCode = extractXmlAttr(xml, /StatusCode[^>]+Value="([^"]+)"/i);
  const isSuccess =
    statusCode === "urn:oasis:names:tc:SAML:2.0:status:Success" ||
    statusCode.endsWith(":Success");

  const issuer = extractXmlText(xml, /<(?:[^:>]+:)?Issuer[^>]*>([^<]+)<\/(?:[^:>]+:)?Issuer>/i);
  const assertionIssuer = assertionXml ? extractXmlText(assertionXml, /<(?:[^:>]+:)?Issuer[^>]*>([^<]+)<\/(?:[^:>]+:)?Issuer>/i) : "";
  const nameId = subjectXml ? extractXmlText(subjectXml, /<(?:[^:>]+:)?NameID[^>]*>([^<]+)<\/(?:[^:>]+:)?NameID>/i) : "";
  const nameIdFormat = subjectXml ? extractXmlAttr(subjectXml, /<(?:[^:>]+:)?NameID[^>]+Format="([^"]+)"/i) : "";
  const inResponseTo = extractXmlAttr(xml, /InResponseTo="([^"]+)"/i);
  const destination = extractXmlAttr(xml, /<[^>]*:?Response[^>]+Destination="([^"]+)"/i);
  const statusMessage = extractXmlText(xml, /<(?:[^:>]+:)?StatusMessage[^>]*>([^<]+)<\/(?:[^:>]+:)?StatusMessage>/i);
  const statusDetailPresent = hasXmlElement(xml, "StatusDetail");
  const recipient = subjectConfirmationXml ? extractXmlAttrFromElement(subjectConfirmationXml, "Recipient") : "";
  const notBefore = conditionsXml ? extractXmlAttrFromElement(conditionsXml, "NotBefore") : "";
  const notOnOrAfter = conditionsXml ? extractXmlAttrFromElement(conditionsXml, "NotOnOrAfter") : "";

  const attributes = {};
  const attributeNames = [];
  const attrRegex = /<(?:[^:>]+:)?Attribute[^>]+Name="([^"]+)"[^>]*>([\s\S]*?)<\/(?:[^:>]+:)?Attribute>/gi;
  let attrMatch;
  while ((attrMatch = attrRegex.exec(xml)) !== null) {
    const attrName = attrMatch[1];
    const attrBody = attrMatch[2];
    const values = [];
    const valRegex = /<(?:[^:>]+:)?AttributeValue[^>]*>([^<]*)<\/(?:[^:>]+:)?AttributeValue>/gi;
    let valMatch;
    while ((valMatch = valRegex.exec(attrBody)) !== null) {
      const value = valMatch[1].trim();
      values.push({
        present: value ? "present" : "empty",
        sha256_12: value ? shortHash(value) : "",
        redacted: REDACTED_VALUE
      });
    }
    attributeNames.push(attrName);
    attributes[attrName] = {
      values_count: values.length,
      values
    };
  }

  return {
    statusCode,
    statusMessage,
    statusDetailPresent,
    isSuccess,
    issuer,
    assertionIssuer,
    assertionPresent: Boolean(assertionXml),
    subjectPresent: Boolean(subjectXml),
    nameIdPresent: Boolean(nameId),
    nameIdMasked: nameId ? `[redacted nameid sha256:${shortHash(nameId)}]` : "",
    nameIdPreview: nameId ? maskSamlValue(nameId) : "",
    nameIdHash: nameId ? shortHash(nameId) : "",
    nameIdFormat,
    attributes,
    attributeNames,
    inResponseTo,
    destination,
    recipient,
    conditionsPresent: Boolean(conditionsXml),
    audienceRestrictionPresent: hasXmlElement(assertionXml, "AudienceRestriction"),
    audience,
    subjectConfirmationPresent: Boolean(subjectConfirmationXml),
    notBefore,
    notOnOrAfter,
    responseSignaturePresent: directResponseSignaturePresent(xml, assertionXml),
    assertionSignaturePresent: assertionXml ? hasXmlElement(assertionXml, "Signature") : false
  };
}

export function extractIdpSigningCertificates(metadataXml) {
  if (!metadataXml) return [];
  const certs = [];

  // Prefer KeyDescriptor use="signing"
  const signingKeyRe = /<KeyDescriptor[^>]+use="signing"[^>]*>([\s\S]*?)<\/KeyDescriptor>/gi;
  let m;
  while ((m = signingKeyRe.exec(metadataXml)) !== null) {
    const cm = /<(?:[^:>]+:)?X509Certificate[^>]*>([\s\S]*?)<\/(?:[^:>]+:)?X509Certificate>/i.exec(m[1]);
    if (cm) {
      const raw = cm[1].replace(/\s+/g, "");
      if (raw) certs.push(raw);
    }
  }

  // Fall back: any KeyDescriptor that is NOT use="encryption"
  if (certs.length === 0) {
    const anyKeyRe = /<KeyDescriptor(?![^>]*use="encryption")[^>]*>([\s\S]*?)<\/KeyDescriptor>/gi;
    while ((m = anyKeyRe.exec(metadataXml)) !== null) {
      const cm = /<(?:[^:>]+:)?X509Certificate[^>]*>([\s\S]*?)<\/(?:[^:>]+:)?X509Certificate>/i.exec(m[1]);
      if (cm) {
        const raw = cm[1].replace(/\s+/g, "");
        if (raw) certs.push(raw);
      }
    }
  }

  return [...new Set(certs)];
}

function convertCertToPem(rawBase64) {
  const cleaned = String(rawBase64 || "").replace(/\s+/g, "");
  if (!cleaned) return "";
  const lines = cleaned.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

function isAssertionLevelNode(node) {
  let current = node.parentNode;
  while (current) {
    if (current.localName === "Assertion") return true;
    if (current.localName === "Response") return false;
    current = current.parentNode;
  }
  return false;
}

function tryVerifySignatureNodes(xml, sigNodes, rawCerts) {
  if (sigNodes.length === 0) return { verification: "not checked" };

  let lastError = "";

  for (const sigNode of sigNodes) {
    for (const rawCert of rawCerts) {
      try {
        const pem = convertCertToPem(rawCert);
        const sig = new _SignedXml({ publicCert: pem });
        sig.loadSignature(sigNode);
        const valid = sig.checkSignature(xml);
        if (valid) return { verification: "valid" };
        const errMsg = (sig.validationErrors || []).map(String).join("; ");
        lastError = errMsg.slice(0, 120) || "Signature invalid.";
      } catch (err) {
        lastError = String(err.message || err).slice(0, 120);
      }
    }
  }

  return { verification: "invalid", error: lastError || "Signature verification failed." };
}

export function verifySamlXmlSignatures(responseXml, rawCerts = []) {
  const hasAnySigRegex = hasXmlElement(responseXml, "Signature");

  if (!_SignedXml || !_DOMParser) {
    return {
      response_signature_present: hasAnySigRegex ? "present" : "missing",
      assertion_signature_present: "not extracted",
      response_signature_verification: "not checked",
      assertion_signature_verification: "not checked",
      signature_verification_result: "unsupported",
      verification_note: "xml-crypto library not available; install xml-crypto to enable verification."
    };
  }

  let doc;
  try {
    doc = new _DOMParser({
      errorHandler: { warning() {}, error() {}, fatalError(e) { throw e; } }
    }).parseFromString(responseXml, "application/xml");
  } catch {
    return {
      response_signature_present: hasAnySigRegex ? "present" : "missing",
      assertion_signature_present: "not extracted",
      response_signature_verification: "not checked",
      assertion_signature_verification: "not checked",
      signature_verification_result: "error",
      verification_note: "XML parsing failed during signature verification."
    };
  }

  const allSigNodes = Array.from(doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature"));
  const assertionSigNodes = allSigNodes.filter(isAssertionLevelNode);
  const responseSigNodes = allSigNodes.filter((n) => !isAssertionLevelNode(n));

  const responsePresent = responseSigNodes.length > 0 ? "present" : "missing";
  const assertionPresent = assertionSigNodes.length > 0 ? "present" : "missing";
  const hasAnySig = responseSigNodes.length > 0 || assertionSigNodes.length > 0;

  if (!hasAnySig) {
    return {
      response_signature_present: "missing",
      assertion_signature_present: "missing",
      response_signature_verification: "not checked",
      assertion_signature_verification: "not checked",
      signature_verification_result: "missing signature",
      verification_note: "No XML Signature element detected in SAMLResponse."
    };
  }

  if (rawCerts.length === 0) {
    return {
      response_signature_present: responsePresent,
      assertion_signature_present: assertionPresent,
      response_signature_verification: "not checked",
      assertion_signature_verification: "not checked",
      signature_verification_result: "missing certificate",
      verification_note: "Signature detected but no IdP signing certificate found in metadata."
    };
  }

  const responseVerif = tryVerifySignatureNodes(responseXml, responseSigNodes, rawCerts);
  const assertionVerif = tryVerifySignatureNodes(responseXml, assertionSigNodes, rawCerts);

  let overall;
  if (responseVerif.verification === "invalid" || assertionVerif.verification === "invalid") {
    overall = "invalid";
  } else if (responseVerif.verification === "valid" || assertionVerif.verification === "valid") {
    overall = "valid";
  } else if (responseVerif.verification === "error" || assertionVerif.verification === "error") {
    overall = "error";
  } else {
    overall = "not checked";
  }

  return {
    response_signature_present: responsePresent,
    assertion_signature_present: assertionPresent,
    response_signature_verification: responseVerif.verification,
    assertion_signature_verification: assertionVerif.verification,
    signature_verification_result: overall,
    verification_note: "Signature verification checks cryptographic integrity using the IdP signing certificate.",
    ...(responseVerif.error ? { response_verification_error: responseVerif.error } : {}),
    ...(assertionVerif.error ? { assertion_verification_error: assertionVerif.error } : {})
  };
}

export async function fetchIdpMetadataFromUrl(url) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(10000),
    headers: { accept: "application/xml, text/xml, */*" }
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching IdP metadata.`);
  }

  return response.text();
}
