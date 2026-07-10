import "dotenv/config";

export const ezAccessEnvironments = {
  preprod: {
    key: "preprod",
    label: "Preprod",
    discoveryUrl: process.env.EZ_ACCESS_PREPROD_DISCOVERY_URL || null
  },
  prod: {
    key: "prod",
    label: "Prod",
    discoveryUrl: process.env.EZ_ACCESS_PROD_DISCOVERY_URL || null
  }
};

export function getEzAccessEnvironment(key = "") {
  return ezAccessEnvironments[key] || null;
}

export function listEzAccessEnvironments() {
  return Object.values(ezAccessEnvironments);
}
