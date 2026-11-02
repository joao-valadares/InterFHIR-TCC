export interface AccessAuditEvaluation {
  granted: boolean;
  reasonCode: string;
  policyId: string;
  policyVersion: number;
  consentReference: string;
  consentVersion: string;
  requestHash: string;
}

export interface AuditEventInput {
  requestId?: string;
  action?: string;
  granted?: boolean;
  outcomeReason?: string;
  patientReference?: string;
  practitionerReference?: string;
  organizationReference?: string;
  resourceReference?: string;
  requestHash?: string;
  transactionHash?: string;
  recordedAt: string;
  custodianOrganizationReference?: string;
  vaultId?: string;
  policyId?: string;
  policyVersion?: number;
  consentReference?: string;
  consentVersion?: string;
  institutionReference?: string;
  evaluation?: AccessAuditEvaluation;
}

export function createAccessAuditEvent(input: AuditEventInput) {
  const evaluation = input.evaluation;
  const reasonCode = evaluation?.reasonCode ?? input.outcomeReason ?? "ACCESS_DENIED";
  const requestHash = evaluation?.requestHash ?? input.requestHash ?? "unknown";
  const granted = evaluation?.granted ?? input.granted ?? false;
  const policyId = evaluation?.policyId ?? input.policyId;
  const policyVersion = evaluation?.policyVersion ?? input.policyVersion;
  const consentReference = evaluation?.consentReference ?? input.consentReference;
  const consentVersion = evaluation?.consentVersion ?? input.consentVersion;
  const institutionReference =
    evaluation && input.institutionReference
      ? input.institutionReference
      : input.institutionReference ?? input.organizationReference ?? input.custodianOrganizationReference;

  const extension = [
    ...(input.requestId ? [{ url: "https://interfhir.local/fhir/StructureDefinition/access-request-id", valueString: input.requestId }] : []),
    {
      url: "https://interfhir.local/fhir/StructureDefinition/access-decision-reason",
      valueCode: reasonCode
    },
    {
      url: "https://interfhir.local/fhir/StructureDefinition/access-request-hash",
      valueString: requestHash
    },
    ...(input.transactionHash
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/blockchain-transaction-hash",
            valueString: input.transactionHash
          }
        ]
      : []),
    ...(policyId !== undefined
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/policy-id",
            valueString: policyId
          }
        ]
      : []),
    ...(policyVersion !== undefined
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/policy-version",
            valueInteger: policyVersion
          }
        ]
      : []),
    ...(consentReference !== undefined
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/consent-reference",
            valueString: consentReference
          }
        ]
      : []),
    ...(consentVersion !== undefined
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/consent-version",
            valueString: consentVersion
          }
        ]
      : []),
    ...(institutionReference
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/institution-reference",
            valueString: institutionReference
          }
        ]
      : []),
    ...(input.vaultId
      ? [
          {
            url: "https://interfhir.local/fhir/StructureDefinition/custodian-vault-id",
            valueString: input.vaultId
          }
        ]
      : [])
  ];

  return {
    resourceType: "AuditEvent",
    type: {
      system: "http://terminology.hl7.org/CodeSystem/audit-event-type",
      code: "rest"
    },
    subtype: [
      {
        system: "http://hl7.org/fhir/restful-interaction",
        code: (input.action ?? "read").toLowerCase()
      }
    ],
    action: (input.action ?? "read").toUpperCase().startsWith("R") ? "R" : "E",
    recorded: input.recordedAt,
    outcome: granted ? "0" : "4",
    outcomeDesc: reasonCode,
    agent: [
      ...(input.practitionerReference
        ? [{ who: { reference: input.practitionerReference }, requestor: true }]
        : []),
      ...(institutionReference
        ? [{ who: { reference: institutionReference }, requestor: false }]
        : [])
    ],
    source: {
      observer: { display: "InterFHIR Middleware" }
    },
    extension
  };
}
