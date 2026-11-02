export type AuthenticatedPrincipal =
  | {
      kind: "patient";
      sub: string;
      patientReference: string;
      issuer: string;
      audience: string[];
      exp: number;
      jti: string;
    }
  | {
      kind: "practitioner";
      sub: string;
      practitionerReference: string;
      organizationReference: string;
      roleCode: string;
      specialtyCode: string;
      issuer: string;
      audience: string[];
      exp: number;
      jti: string;
    }
  | {
      kind: "administrator";
      sub: string;
      organizationReference: string;
      issuer: string;
      audience: string[];
      exp: number;
      jti: string;
    }
  | {
      kind: "service";
      clientId: string;
      organizationReference: string;
      practitionerReference: string;
      purposeOfUse: string[];
      certificateThumbprint: string;
      assertionHash: string;
      exp: number;
      jti: string;
    };

export type HumanAuthenticatedPrincipal = Exclude<AuthenticatedPrincipal, { kind: "service" }>;

export type InstitutionalAuthenticatedPrincipal = Extract<AuthenticatedPrincipal, { kind: "service" }>;

export function isHumanAuthenticatedPrincipal(
  principal: AuthenticatedPrincipal
): principal is HumanAuthenticatedPrincipal {
  return principal.kind !== "service";
}
