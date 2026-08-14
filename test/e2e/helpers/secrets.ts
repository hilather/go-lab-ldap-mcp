export const adminToken = process.env.LABLDAP_E2E_ADMIN_TOKEN ?? "e2e-admin-token";
export const readToken = process.env.LABLDAP_E2E_READ_TOKEN ?? "e2e-read-token";
export const bindPassword = process.env.LABLDAP_E2E_BIND_PASSWORD ?? "lab-example-password-12";
export const scenarioName = process.env.LABLDAP_E2E_SCENARIO_NAME ?? "example-lab";
export const compiledRevision =
  process.env.LABLDAP_E2E_REVISION ?? "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

export function secretsToMask(): string[] {
  return [adminToken, readToken, bindPassword].filter((value) => value.length > 0);
}
