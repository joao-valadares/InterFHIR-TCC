import { Contract, ZeroAddress, ZeroHash, keccak256, toUtf8Bytes } from "ethers";

import { mapActionCode, mapPurposeCode, mapResourceTypeCode } from "../middleware/src/abac/policy-mask.js";
import { POLICY_TREATMENT_OBSERVATION } from "../middleware/src/authorization/policy-definition.js";
import { readPatientAnaAddress, type PublicNetworkConfiguration } from "./network-config.js";

export interface InstitutionBootstrapEntry {
  slug: "hospital-a" | "clinic-b";
  organizationReference: string;
  practitionerReference: string;
}

export interface ExpectedInstitutionRecord {
  gatewayAccount: string;
  metadataCommitment: string;
}

export interface InstitutionBootstrapConfiguration {
  organizationAccount: string;
  practitionerAccount: string;
  gatewayAccount: string;
}

export interface InstitutionPreflightRecord {
  slug: InstitutionBootstrapEntry["slug"];
  organizationReference: string;
  practitionerReference: string;
  configuration: InstitutionBootstrapConfiguration;
  organizationHash: string;
  practitionerHash: string;
  metadataCommitment: string;
  organization: unknown;
  institution: unknown;
  practitioner: unknown;
  pepAuthorized: boolean;
  createOrganization: boolean;
  createInstitution: boolean;
  createPractitioner: boolean;
  authorizePep: boolean;
}

export interface BootstrapPreflight {
  patientAddress: string;
  patientConsentController: boolean;
  institutions: InstitutionPreflightRecord[];
  policy: {
    latestVersion: number;
    current: unknown;
    create: boolean;
  };
}

export const INSTITUTION_BOOTSTRAP_ENTRIES: InstitutionBootstrapEntry[] = [
  {
    slug: "hospital-a",
    organizationReference: "Organization/hospital-a",
    practitionerReference: "Practitioner/ana"
  },
  {
    slug: "clinic-b",
    organizationReference: "Organization/clinic-b",
    practitionerReference: "Practitioner/bruno"
  }
];

export async function preflightInstitutionalBootstrap(
  accessControl: Contract,
  institutionRegistry: Contract,
  consentRegistry: Contract,
  network: PublicNetworkConfiguration
): Promise<BootstrapPreflight> {
  const patientAddress = readPatientAnaAddress(network);
  const [patientConsentController, institutionSnapshots, policySnapshot] = await Promise.all([
    consentRegistry.getFunction("patientConsentControllers")(patientAddress),
    Promise.all(INSTITUTION_BOOTSTRAP_ENTRIES.map(async (institution) => {
      const configuration = institutionConfiguration(network, institution);
      const organizationHash = identifierHash(institution.organizationReference);
      const practitionerHash = identifierHash(institution.practitionerReference);
      const metadataCommitment = identifierHash(
        `institution-metadata:${institution.organizationReference}:${configuration.gatewayAccount}:v1`
      );
      const [organization, institutionRecord, practitioner, pepAuthorized] = await Promise.all([
        accessControl.getFunction("organizations")(organizationHash),
        institutionRegistry.getFunction("getInstitution")(organizationHash),
        accessControl.getFunction("practitioners")(practitionerHash),
        accessControl.getFunction("authorizedPeps")(configuration.gatewayAccount)
      ]);
      return {
        institution,
        configuration,
        organizationHash,
        practitionerHash,
        metadataCommitment,
        organization,
        institutionRecord,
        practitioner,
        pepAuthorized: Boolean(pepAuthorized)
      };
    })),
    Promise.all([
      accessControl.getFunction("latestPolicyVersion")(identifierHash(POLICY_TREATMENT_OBSERVATION.policyId)),
      accessControl.getFunction("getActivePolicy")(
        identifierHash(POLICY_TREATMENT_OBSERVATION.policyId),
        POLICY_TREATMENT_OBSERVATION.version
      )
    ])
  ]);

  if (!Boolean(patientConsentController)) {
    throw new Error("BOOTSTRAP_DIVERGENCE:patient-controller:Patient/pat-ana");
  }

  const institutions = institutionSnapshots.map(({
    institution,
    configuration,
    organizationHash,
    practitionerHash,
    metadataCommitment,
    organization,
    institutionRecord,
    practitioner,
    pepAuthorized
  }) => {
    const organizationMissing = isZeroAddress(tupleValue(organization, "account", 0));
    if (!organizationMissing) {
      assertOrganizationRecordMatches(organization, configuration.organizationAccount, institution.organizationReference);
    }

    const institutionMissing = isZeroAddress(tupleValue(institutionRecord, "gatewayAccount", 0));
    if (!institutionMissing) {
      assertInstitutionRecordMatches(
        institutionRecord,
        { gatewayAccount: configuration.gatewayAccount, metadataCommitment },
        institution.organizationReference
      );
    }

    const practitionerMissing = isZeroAddress(tupleValue(practitioner, "account", 0));
    if (!practitionerMissing) {
      assertPractitionerRecordMatches(
        practitioner,
        configuration.practitionerAccount,
        organizationHash,
        institution.practitionerReference
      );
    }

    return {
      slug: institution.slug,
      organizationReference: institution.organizationReference,
      practitionerReference: institution.practitionerReference,
      configuration,
      organizationHash,
      practitionerHash,
      metadataCommitment,
      organization,
      institution: institutionRecord,
      practitioner,
      pepAuthorized,
      createOrganization: organizationMissing,
      createInstitution: institutionMissing,
      createPractitioner: practitionerMissing,
      authorizePep: !pepAuthorized
    };
  });

  const [latestVersionValue, current] = policySnapshot;
  const latestVersion = Number(latestVersionValue);
  const policyIdHash = identifierHash(POLICY_TREATMENT_OBSERVATION.policyId);
  const policyMissing = String(tupleValue(current, "policyId", 0)).toLowerCase() === ZeroHash.toLowerCase();
  if (policyMissing) {
    if (latestVersion !== 0) throw new Error("BOOTSTRAP_DIVERGENCE:policy-latest-version");
  } else {
    assertPolicyRecordMatches(current, latestVersion);
  }

  return {
    patientAddress,
    patientConsentController: Boolean(patientConsentController),
    institutions,
    policy: { latestVersion, current, create: policyMissing }
  };
}

export async function verifyExistingInstitutionalBootstrap(
  accessControl: Contract,
  institutionRegistry: Contract,
  consentRegistry: Contract,
  network: PublicNetworkConfiguration
): Promise<BootstrapPreflight> {
  const preflight = await preflightInstitutionalBootstrap(accessControl, institutionRegistry, consentRegistry, network);
  const missing = preflight.institutions.flatMap((institution) => [
    institution.createOrganization ? `organization:${institution.organizationReference}` : undefined,
    institution.createInstitution ? `institution:${institution.organizationReference}` : undefined,
    institution.createPractitioner ? `practitioner:${institution.practitionerReference}` : undefined,
    institution.authorizePep ? `pep:${institution.organizationReference}` : undefined
  ]).filter((value): value is string => value !== undefined);
  if (preflight.policy.create) missing.push("policy:POLICY_TREATMENT_OBSERVATION@1");
  if (missing.length > 0) throw new Error(`BOOTSTRAP_STATE_INCOMPLETE:${missing[0]}`);
  return preflight;
}

export async function bootstrapInstitutionalState(
  accessControl: Contract,
  institutionRegistry: Contract,
  consentRegistry: Contract,
  network: PublicNetworkConfiguration
): Promise<{ preflight: BootstrapPreflight; writes: string[] }> {
  const preflight = await preflightInstitutionalBootstrap(accessControl, institutionRegistry, consentRegistry, network);
  const writes = await applyInstitutionalBootstrap(accessControl, institutionRegistry, preflight);
  return { preflight, writes };
}

export async function applyInstitutionalBootstrap(
  accessControl: Contract,
  institutionRegistry: Contract,
  preflight: BootstrapPreflight
): Promise<string[]> {
  const writes: string[] = [];
  for (const institution of preflight.institutions) {
    if (institution.createOrganization) {
      await send(accessControl.getFunction("registerOrganization")(
        institution.configuration.organizationAccount,
        institution.organizationHash
      ));
      writes.push(`organization:${institution.organizationReference}`);
    }
    if (institution.createInstitution) {
      await send(accessControl.getFunction("registerInstitution")(
        institution.organizationHash,
        institution.configuration.gatewayAccount,
        institution.metadataCommitment
      ));
      writes.push(`institution:${institution.organizationReference}`);
    }
    if (institution.createPractitioner) {
      await send(accessControl.getFunction("registerPractitioner")(
        institution.configuration.practitionerAccount,
        institution.practitionerHash,
        institution.organizationHash,
        1,
        1,
        true
      ));
      writes.push(`practitioner:${institution.practitionerReference}`);
    }
    if (institution.authorizePep) {
      await send(accessControl.getFunction("setPepAuthorization")(institution.configuration.gatewayAccount, true));
      writes.push(`pep:${institution.organizationReference}`);
    }
  }

  if (preflight.policy.create) {
    await send(accessControl.getFunction("createPolicyVersion")({
      policyId: identifierHash(POLICY_TREATMENT_OBSERVATION.policyId),
      version: POLICY_TREATMENT_OBSERVATION.version,
      definitionHash: POLICY_TREATMENT_OBSERVATION.definitionHash,
      resourceTypeCode: mapResourceTypeCode(POLICY_TREATMENT_OBSERVATION.resourceType),
      actionCode: mapActionCode(POLICY_TREATMENT_OBSERVATION.action),
      purposeCode: mapPurposeCode(POLICY_TREATMENT_OBSERVATION.purpose),
      requiredMask: POLICY_TREATMENT_OBSERVATION.requiredAttributes,
      requiredRoleCode: POLICY_TREATMENT_OBSERVATION.requiredRoleCode ?? 0,
      requiredSpecialtyCode: POLICY_TREATMENT_OBSERVATION.requiredSpecialtyCode ?? 0,
      effectiveFrom: 0,
      effectiveUntil: 0,
      active: true
    }));
    writes.push("policy:POLICY_TREATMENT_OBSERVATION@1");
  }
  return writes;
}

export function assertInstitutionRecordMatches(
  actual: unknown,
  expected: ExpectedInstitutionRecord,
  reference: string
): void {
  const gatewayAccount = String(tupleValue(actual, "gatewayAccount", 0));
  const metadataCommitment = String(tupleValue(actual, "metadataCommitment", 1));
  const active = Boolean(tupleValue(actual, "active", 2));
  if (
    !active ||
    gatewayAccount.toLowerCase() !== expected.gatewayAccount.toLowerCase() ||
    metadataCommitment.toLowerCase() !== expected.metadataCommitment.toLowerCase()
  ) {
    throw new Error(`BOOTSTRAP_DIVERGENCE:institution:${reference}`);
  }
}

function assertOrganizationRecordMatches(actual: unknown, expectedAccount: string, reference: string): void {
  if (
    !Boolean(tupleValue(actual, "active", 1)) ||
    String(tupleValue(actual, "account", 0)).toLowerCase() !== expectedAccount.toLowerCase()
  ) {
    throw new Error(`BOOTSTRAP_DIVERGENCE:organization:${reference}`);
  }
}

function assertPractitionerRecordMatches(
  actual: unknown,
  expectedAccount: string,
  expectedOrganizationHash: string,
  reference: string
): void {
  if (
    !Boolean(tupleValue(actual, "licenseActive", 4)) ||
    !Boolean(tupleValue(actual, "active", 5)) ||
    String(tupleValue(actual, "account", 0)).toLowerCase() !== expectedAccount.toLowerCase() ||
    String(tupleValue(actual, "organizationHash", 1)).toLowerCase() !== expectedOrganizationHash.toLowerCase() ||
    Number(tupleValue(actual, "roleCode", 2)) !== 1 ||
    Number(tupleValue(actual, "specialtyCode", 3)) !== 1
  ) {
    throw new Error(`BOOTSTRAP_DIVERGENCE:practitioner:${reference}`);
  }
}

function assertPolicyRecordMatches(current: unknown, latestVersion: number): void {
  if (
    latestVersion !== POLICY_TREATMENT_OBSERVATION.version ||
    String(tupleValue(current, "definitionHash", 2)).toLowerCase() !== POLICY_TREATMENT_OBSERVATION.definitionHash.toLowerCase() ||
    Number(tupleValue(current, "resourceTypeCode", 3)) !== mapResourceTypeCode(POLICY_TREATMENT_OBSERVATION.resourceType) ||
    Number(tupleValue(current, "actionCode", 4)) !== mapActionCode(POLICY_TREATMENT_OBSERVATION.action) ||
    Number(tupleValue(current, "purposeCode", 5)) !== mapPurposeCode(POLICY_TREATMENT_OBSERVATION.purpose) ||
    Number(tupleValue(current, "requiredMask", 6)) !== POLICY_TREATMENT_OBSERVATION.requiredAttributes ||
    Number(tupleValue(current, "requiredRoleCode", 7)) !== (POLICY_TREATMENT_OBSERVATION.requiredRoleCode ?? 0) ||
    Number(tupleValue(current, "requiredSpecialtyCode", 8)) !== (POLICY_TREATMENT_OBSERVATION.requiredSpecialtyCode ?? 0) ||
    !Boolean(tupleValue(current, "active", 11))
  ) {
    throw new Error("BOOTSTRAP_DIVERGENCE:policy:POLICY_TREATMENT_OBSERVATION@1");
  }
}

function institutionConfiguration(
  network: PublicNetworkConfiguration,
  institution: InstitutionBootstrapEntry
): InstitutionBootstrapConfiguration {
  const entry = network.institutions[institution.slug];
  if (!entry) throw new Error(`NETWORK_INSTITUTION_MISSING:${institution.slug}`);
  return {
    organizationAccount: requireAddress(entry.walletAddresses.organization, `${institution.slug}:organization`),
    practitionerAccount: requireAddress(entry.walletAddresses.practitioner, `${institution.slug}:practitioner`),
    gatewayAccount: requireAddress(entry.walletAddresses.pep, `${institution.slug}:pep`)
  };
}

function tupleValue(value: unknown, name: string, index: number): unknown {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string | number, unknown>;
  return record[name] ?? record[index];
}

function isZeroAddress(value: unknown): boolean {
  return String(value).toLowerCase() === ZeroAddress.toLowerCase();
}

function requireAddress(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`NETWORK_ADDRESS_INVALID:${name}`);
  }
  return value;
}

function identifierHash(value: string): string {
  return keccak256(toUtf8Bytes(value));
}

async function send(transaction: Promise<{ wait(): Promise<unknown> }>): Promise<void> {
  await (await transaction).wait();
}
