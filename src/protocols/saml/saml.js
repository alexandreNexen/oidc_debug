import crypto from "node:crypto";
import zlib from "node:zlib";

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

function extractXmlAttr(xml, pattern) {
  const match = xml.match(pattern);
  return match ? match[1].trim() : "";
}

function extractXmlText(xml, pattern) {
  const match = xml.match(pattern);
  return match ? match[1].trim() : "";
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

  const certificate = extractXmlText(xml, /<[^:>]*:?X509Certificate[^>]*>\s*([A-Za-z0-9+/=\s]+?)\s*<\/[^>]+X509Certificate>/i);

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
  const statusCode = extractXmlAttr(xml, /StatusCode[^>]+Value="([^"]+)"/i);
  const isSuccess =
    statusCode === "urn:oasis:names:tc:SAML:2.0:status:Success" ||
    statusCode.endsWith(":Success");

  const issuer = extractXmlText(xml, /<[^>]*:?Issuer[^>]*>([^<]+)<\/[^>]+Issuer>/i);
  const nameId = extractXmlText(xml, /<[^>]*:?NameID[^>]*>([^<]+)<\/[^>]+NameID>/i);
  const nameIdFormat = extractXmlAttr(xml, /<[^>]*:?NameID[^>]+Format="([^"]+)"/i);
  const inResponseTo = extractXmlAttr(xml, /InResponseTo="([^"]+)"/i);
  const destination = extractXmlAttr(xml, /<[^>]*:?Response[^>]+Destination="([^"]+)"/i);

  const attributes = {};
  const attrRegex = /<[^>]*:?Attribute[^>]+Name="([^"]+)"[^>]*>([\s\S]*?)<\/[^>]+Attribute>/gi;
  let attrMatch;
  while ((attrMatch = attrRegex.exec(xml)) !== null) {
    const attrName = attrMatch[1];
    const attrBody = attrMatch[2];
    const values = [];
    const valRegex = /<[^>]*:?AttributeValue[^>]*>([^<]*)<\/[^>]+AttributeValue>/gi;
    let valMatch;
    while ((valMatch = valRegex.exec(attrBody)) !== null) {
      values.push(valMatch[1].trim());
    }
    attributes[attrName] = values.length === 1 ? values[0] : values;
  }

  return {
    statusCode,
    isSuccess,
    issuer,
    nameId,
    nameIdFormat,
    attributes,
    inResponseTo,
    destination
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
