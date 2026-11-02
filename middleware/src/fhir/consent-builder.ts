import {
  NETWORK_POLICY_EXTENSION_URL,
  NETWORK_POLICY_SYSTEM,
  type PatientConsentScope
} from "../authorization/authorization-model.js";
import {
  createPatientConsentScope
} from "../authorization/consent-scope.js";
import { formatNetworkPolicyReference } from "../authorization/policy-definition.js";

export interface PatientConsentResource {
  resourceType: "Consent";
  status: "active";
  scope: {
    coding: Array<{
      system: "http://terminology.hl7.org/CodeSystem/consentscope";
      code: "patient-privacy";
    }>;
  };
  patient: { reference: string };
  organization: Array<{ reference: string }>;
  extension: Array<{
    url: string;
    valueIdentifier: { system: string; value: string };
  }>;
  provision: {
    type: "permit";
    period: { start: string; end: string };
    actor: Array<{
      role: { coding: Array<{ code: "performer" }> };
      reference: { reference: string };
    }>;
    action: Array<{ coding: Array<{ code: "read" }> }>;
    purpose: Array<{
      system: "http://terminology.hl7.org/CodeSystem/v3-ActReason";
      code: string;
    }>;
    data: Array<{
      meaning: "instance";
      reference: { reference: string };
    }>;
  };
}

export function buildPatientConsentResource(scope: PatientConsentScope): PatientConsentResource {
  const validated = createPatientConsentScope(scope);
  const actor = validated.practitionerReference
    ? [{
        role: { coding: [{ code: "performer" as const }] },
        reference: { reference: validated.practitionerReference }
      }]
    : [];

  return {
    resourceType: "Consent",
    status: "active",
    scope: {
      coding: [{
        system: "http://terminology.hl7.org/CodeSystem/consentscope",
        code: "patient-privacy"
      }]
    },
    patient: { reference: validated.patientReference },
    organization: [{ reference: validated.granteeOrganizationReference }],
    extension: [{
      url: NETWORK_POLICY_EXTENSION_URL,
      valueIdentifier: {
        system: NETWORK_POLICY_SYSTEM,
        value: formatNetworkPolicyReference(validated.policyId, validated.policyVersion)
      }
    }],
    provision: {
      type: "permit",
      period: {
        start: validated.validFrom,
        end: validated.validUntil
      },
      actor,
      action: [{ coding: [{ code: "read" }] }],
      purpose: [{
        system: "http://terminology.hl7.org/CodeSystem/v3-ActReason",
        code: validated.purposeOfUse
      }],
      data: [{
        meaning: "instance",
        reference: { reference: validated.resourceReference }
      }]
    }
  };
}
