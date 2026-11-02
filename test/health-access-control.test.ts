import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

const ROLE_PRACTITIONER = 1 << 0;
const ORG_AUTHORIZED = 1 << 1;
const LICENSE_ACTIVE = 1 << 2;
const RESOURCE_OBSERVATION = 1 << 3;
const ACTION_READ = 1 << 4;
const PURPOSE_TREATMENT = 1 << 5;
const CONSENT_ACTIVE = 1 << 6;
const CONSENT_PERIOD_VALID = 1 << 7;
const INTEGRITY_VALID = 1 << 9;
const DATA_SUBJECT_MATCH = 1 << 10;
const REQUESTER_MATCHES_CONSENT = 1 << 11;

const REQUIRED_TREATMENT_OBSERVATION_MASK =
  ROLE_PRACTITIONER |
  ORG_AUTHORIZED |
  LICENSE_ACTIVE |
  RESOURCE_OBSERVATION |
  ACTION_READ |
  PURPOSE_TREATMENT |
  CONSENT_ACTIVE |
  CONSENT_PERIOD_VALID |
  INTEGRITY_VALID |
  DATA_SUBJECT_MATCH |
  REQUESTER_MATCHES_CONSENT;

const RESOURCE_TYPE_OBSERVATION = 1;
const ACTION_READ_CODE = 1;
const ACTION_WRITE_CODE = 2;
const PURPOSE_TREATMENT_CODE = 1;
const PURPOSE_RESEARCH_CODE = 2;
const REASON_PERMIT = 1;
const REASON_CONSENT_NOT_FOUND = 2;
const REASON_CONSENT_NOT_ACTIVE = 3;
const REASON_CONSENT_OUT_OF_PERIOD = 4;
const REASON_CONSENT_SCOPE_MISMATCH = 5;
const REASON_RESOURCE_HASH_MISMATCH = 6;
const REASON_REQUESTER_NOT_AUTHORIZED = 7;
const REASON_POLICY_NOT_ACTIVE = 8;
const REASON_ATTRIBUTES_NOT_COMPLIANT = 9;
const REASON_DECISION_NOT_GRANTED = 12;
const REASON_DECISION_EXPIRED = 13;
const REASON_PATIENT_REVOKED = 14;
const REASON_LEGACY_AUTHORIZATION_DISABLED = 15;

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

describe("HealthAccessControl", function () {
  async function deployFixture() {
    const [owner, patient, practitioner, organization, otherRequester] = await ethers.getSigners();
    const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
    const HealthAccessControl = await ethers.getContractFactory("HealthAccessControl");
    const attributes = await AttributeRegistry.deploy();
    const consents = await ConsentRegistry.deploy();
    const audit = await AuditRegistry.deploy();
    const resources = await ResourceRegistry.deploy();
    const accessControl = await HealthAccessControl.deploy(
      await attributes.getAddress(),
      await consents.getAddress(),
      await audit.getAddress(),
      await resources.getAddress()
    );

    await attributes.transferOwnership(await accessControl.getAddress());
    await resources.transferOwnership(await accessControl.getAddress());
    await consents.authorizeWriter(await accessControl.getAddress(), true);
    await (consents as any).authorizePatientConsentController(await accessControl.getAddress(), true);
    await audit.authorizeWriter(await accessControl.getAddress(), true);

    return { accessControl, attributes, consents, audit, resources, owner, patient, practitioner, organization, otherRequester };
  }

  async function setupTreatmentObservationScenario(options?: {
    activePolicy?: boolean;
    validFrom?: number;
    validUntil?: number;
  }) {
    const fixture = await deployFixture();
    const policyId = id("policy:observation:treatment:read");
    const consentHash = id("Consent/cons-1");
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const resourceHash = id("Observation/obs-1/content-v1");
    const now = 1_800_000_000;
    const activePolicy = options?.activePolicy ?? true;
    const validFrom = options?.validFrom ?? now - 60;
    const validUntil = options?.validUntil ?? now + 3600;

    await fixture.accessControl.registerOrganization(fixture.organization.address, organizationHash);
    await fixture.accessControl.registerPractitioner(fixture.practitioner.address, actorHash, organizationHash, 1, 1, true);
    await fixture.accessControl.createPolicy(
      policyId,
      RESOURCE_TYPE_OBSERVATION,
      ACTION_READ_CODE,
      PURPOSE_TREATMENT_CODE,
      REQUIRED_TREATMENT_OBSERVATION_MASK,
      activePolicy
    );
    await fixture.accessControl.registerResourceHash(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash);
    await fixture.accessControl.connect(fixture.patient).registerConsent({
      consentHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom,
      validUntil,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    });

    return {
      ...fixture,
      policyId,
      consentHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceHash,
      now
    };
  }

  async function setupVersionedInstitutionalScenario() {
    const fixture = await deployFixture();
    const policyId = id("policy:observation:treatment:versioned");
    const consentIdHash = id("Consent/maria-hospital-a-versioned");
    const consentProjectionHash = id("projection:maria-hospital-a-versioned");
    const patientHash = id("Patient/maria-versioned");
    const actorHash = id("Practitioner/ana-versioned");
    const organizationHash = id("Organization/hospital-a-versioned");
    const resourceIdHash = id("Observation/obs-versioned");
    const resourceHash = id("Observation/obs-versioned/content-v1");
    const now = 1_800_000_000;

    await fixture.accessControl.registerOrganization(fixture.organization.address, organizationHash);
    await fixture.accessControl.registerPractitioner(fixture.practitioner.address, actorHash, organizationHash, 1, 1, true);
    await fixture.accessControl.createPolicyVersion({
      policyId,
      version: 1,
      definitionHash: id("policy-definition-versioned-v1"),
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      requiredMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
      requiredRoleCode: 1,
      requiredSpecialtyCode: 1,
      effectiveFrom: now - 60,
      effectiveUntil: now + 3600,
      active: true
    });
    await fixture.accessControl.registerResourceHash(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash);
    await fixture.accessControl.connect(fixture.patient).registerPatientConsent({
      consentIdHash,
      consentProjectionHash,
      patientHash,
      actorConstraintHash: ethers.ZeroHash,
      granteeOrganizationHash: organizationHash,
      resourceIdHash,
      policyIdHash: policyId,
      policyVersion: 1,
      consentVersion: 1,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 30,
      validUntil: now + 1800,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    });
    await fixture.accessControl.registerInstitution(organizationHash, fixture.otherRequester.address, id("metadata-versioned"));
    await fixture.accessControl.setPepAuthorization(fixture.otherRequester.address, true);

    const request = institutionalRequest(
      { patientHash, actorHash, organizationHash, resourceIdHash, resourceHash, now },
      consentIdHash,
      consentProjectionHash
    );
    return {
      ...fixture,
      policyId,
      consentIdHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceHash,
      now,
      pep: fixture.otherRequester,
      request
    };
  }

  it("registers an organization and practitioner as authorized network participants", async function () {
    const { accessControl, owner, practitioner, organization } = await deployFixture();
    const practitionerHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");

    await expect(accessControl.registerOrganization(organization.address, organizationHash))
      .to.emit(accessControl, "OrganizationRegistered")
      .withArgs(organization.address, organizationHash, owner.address);

    await expect(
      accessControl.registerPractitioner(
        practitioner.address,
        practitionerHash,
        organizationHash,
        1,
        1,
        true
      )
    )
      .to.emit(accessControl, "PractitionerRegistered")
      .withArgs(practitioner.address, practitionerHash, organizationHash, true, owner.address);

    const registeredOrganization = await accessControl.organizations(organizationHash);
    expect(registeredOrganization.account).to.equal(organization.address);
    expect(registeredOrganization.active).to.equal(true);

    const registeredPractitioner = await accessControl.practitioners(practitionerHash);
    expect(registeredPractitioner.account).to.equal(practitioner.address);
    expect(registeredPractitioner.organizationHash).to.equal(organizationHash);
    expect(registeredPractitioner.licenseActive).to.equal(true);
  });

  it("prevents non-owners from registering participants or policies through HealthAccessControl", async function () {
    const { accessControl, patient, organization } = await deployFixture();
    const organizationHash = id("Organization/hospital-a");
    const policyId = id("policy:observation:treatment:read");

    await expect(
      accessControl.connect(patient).registerOrganization(organization.address, organizationHash)
    ).to.be.revertedWith("ONLY_OWNER");

    await expect(
      accessControl
        .connect(patient)
        .createPolicy(
          policyId,
          RESOURCE_TYPE_OBSERVATION,
          ACTION_READ_CODE,
          PURPOSE_TREATMENT_CODE,
          REQUIRED_TREATMENT_OBSERVATION_MASK,
          true
        )
    ).to.be.revertedWith("ONLY_OWNER");
  });

  it("registers an ABAC policy mask for treatment access to Observation resources", async function () {
    const { accessControl } = await deployFixture();
    const policyId = id("policy:observation:treatment:read");

    await expect(
      accessControl.createPolicy(
        policyId,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        REQUIRED_TREATMENT_OBSERVATION_MASK,
        true
      )
    )
      .to.emit(accessControl, "PolicyCreated")
      .withArgs(
        policyId,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        REQUIRED_TREATMENT_OBSERVATION_MASK,
        true
      );

    const policy = await accessControl.policies(policyId);
    expect(policy.requiredMask).to.equal(REQUIRED_TREATMENT_OBSERVATION_MASK);
    expect(policy.active).to.equal(true);
  });

  it("stores immutable policy versions and deactivates only the selected version", async function () {
    const { accessControl } = await deployFixture();
    const policyId = id("POLICY_TREATMENT_OBSERVATION");
    const policy = {
      policyId,
      version: 1,
      definitionHash: id("policy-definition-v1"),
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      requiredMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
      requiredRoleCode: 1,
      requiredSpecialtyCode: 1,
      effectiveFrom: 1_799_999_000,
      effectiveUntil: 1_800_010_000,
      active: true
    };

    await expect(accessControl.createPolicyVersion(policy))
      .to.emit(accessControl, "PolicyVersionCreated")
      .withArgs(policyId, 1, policy.definitionHash, true, (await accessControl.owner()));
    await expect(accessControl.createPolicyVersion({ ...policy, version: 1, definitionHash: id("changed") }))
      .to.be.revertedWith("POLICY_VERSION_ALREADY_EXISTS");

    const versionTwo = { ...policy, version: 2, definitionHash: id("policy-definition-v2") };
    await accessControl.createPolicyVersion(versionTwo);
    expect((await accessControl.getActivePolicy(policyId, 1)).definitionHash).to.equal(policy.definitionHash);
    expect((await accessControl.getActivePolicy(policyId, 2)).definitionHash).to.equal(versionTwo.definitionHash);

    await expect(accessControl.deactivatePolicy(policyId, 1))
      .to.emit(accessControl, "PolicyVersionDeactivated")
      .withArgs(policyId, 1, (await accessControl.owner()));
    expect((await accessControl.getActivePolicy(policyId, 1)).active).to.equal(false);
    expect((await accessControl.getActivePolicy(policyId, 2)).active).to.equal(true);
  });

  it("registers a patient Consent only against an active matching policy version", async function () {
    const { accessControl, consents, patient, practitioner, organization } = await deployFixture();
    const policyId = id("POLICY_TREATMENT_OBSERVATION");
    const policyVersion = 1;
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const consentIdHash = id("Consent/maria-hospital-a");
    const now = 1_800_000_000;

    await accessControl.registerOrganization(organization.address, organizationHash);
    await accessControl.registerPractitioner(practitioner.address, actorHash, organizationHash, 1, 1, true);
    await accessControl.createPolicyVersion({
      policyId,
      version: policyVersion,
      definitionHash: id("policy-definition-v1"),
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      requiredMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
      requiredRoleCode: 1,
      requiredSpecialtyCode: 1,
      effectiveFrom: now - 60,
      effectiveUntil: now + 3600,
      active: true
    });
    await accessControl.registerResourceHash(resourceIdHash, RESOURCE_TYPE_OBSERVATION, id("resource-v1"));

    await expect(accessControl.connect(patient).registerPatientConsent({
      consentIdHash,
      consentProjectionHash: id("projection-v1"),
      patientHash,
      actorConstraintHash: actorHash,
      granteeOrganizationHash: organizationHash,
      resourceIdHash,
      policyIdHash: policyId,
      policyVersion,
      consentVersion: 1,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now,
      validUntil: now + 1800,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    }))
      .to.emit(consents, "PatientConsentRegistered")
      .withArgs(consentIdHash, patientHash, 1, policyId, await accessControl.getAddress());

    const consent = await consents.patientConsents(consentIdHash, 1);
    const projection = await consents.patientConsentProjections(consentIdHash, 1);
    expect(projection.policyIdHash).to.equal(policyId);
    expect(projection.policyVersion).to.equal(1);
    expect(projection.consentVersion).to.equal(1);
    expect(consent.active).to.equal(true);

    await expect(accessControl.connect(patient).registerPatientConsent({
      consentIdHash: id("Consent/maria-hospital-a-invalid-policy"),
      consentProjectionHash: id("projection-invalid"),
      patientHash,
      actorConstraintHash: actorHash,
      granteeOrganizationHash: organizationHash,
      resourceIdHash,
      policyIdHash: policyId,
      policyVersion: 2,
      consentVersion: 1,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now,
      validUntil: now + 1800,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    })).to.be.revertedWith("POLICY_VERSION_NOT_ACTIVE");
  });

  it("does not verify a cached legacy decision after the legacy path is disabled", async function () {
    const scenario = await setupTreatmentObservationScenario();
    const request = {
      patientHash: scenario.patientHash,
      actorHash: scenario.actorHash,
      organizationHash: scenario.organizationHash,
      resourceIdHash: scenario.resourceIdHash,
      resourceHash: scenario.resourceHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      attributesMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
      requestTime: scenario.now
    };

    await scenario.accessControl.connect(scenario.practitioner).requestAccess(request);
    expect(await scenario.accessControl.connect(scenario.practitioner).verifyAccess.staticCall(request, scenario.now + 1)).to.equal(false);
    await expect(scenario.accessControl.connect(scenario.practitioner).verifyAccess(request, scenario.now + 1))
      .to.emit(scenario.accessControl, "AccessVerified")
      .withArgs(scenario.practitioner.address, scenario.patientHash, scenario.actorHash, scenario.resourceIdHash, false, REASON_LEGACY_AUTHORIZATION_DISABLED);
  });

  it("enforces canonical policy role and specialty requirements from the registry", async function () {
    const roleMismatch = await setupVersionedInstitutionalScenario();
    await roleMismatch.accessControl.registerPractitioner(
      roleMismatch.practitioner.address,
      roleMismatch.actorHash,
      roleMismatch.organizationHash,
      2,
      1,
      true
    );
    expect((await roleMismatch.accessControl.connect(roleMismatch.pep).requestInstitutionalAccess.staticCall(roleMismatch.request))[0]).to.equal(false);

    const specialtyMismatch = await setupVersionedInstitutionalScenario();
    await specialtyMismatch.accessControl.registerPractitioner(
      specialtyMismatch.practitioner.address,
      specialtyMismatch.actorHash,
      specialtyMismatch.organizationHash,
      1,
      2,
      true
    );
    expect((await specialtyMismatch.accessControl.connect(specialtyMismatch.pep).requestInstitutionalAccess.staticCall(specialtyMismatch.request))[0]).to.equal(false);
  });

  it("does not use legacy directed Consent as a canonical institutional authorization source", async function () {
    const scenario = await setupTreatmentObservationScenario();
    const pep = scenario.otherRequester;
    const consentIdHash = id("Consent/cons-directed-1");
    const consentProjectionHash = id("projection:cons-directed-1");
    const request = institutionalRequest(scenario, consentIdHash, consentProjectionHash);
    await scenario.accessControl.registerInstitution(scenario.organizationHash, pep.address, id("metadata"));
    await scenario.accessControl.setPepAuthorization(pep.address, true);
    await scenario.accessControl.connect(scenario.patient).registerDirectedConsent({
      consentIdHash,
      consentProjectionHash,
      patientHash: scenario.patientHash,
      granteeOrganizationHash: scenario.organizationHash,
      actorConstraintHash: ethers.ZeroHash,
      resourceIdHash: scenario.resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: scenario.now - 60,
      validUntil: scenario.now + 3600,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    });

    expect((await scenario.accessControl.connect(pep).requestInstitutionalAccess.staticCall(request))[0]).to.equal(false);
    await (await scenario.accessControl.connect(pep).requestInstitutionalAccess(request)).wait();
  });

  it("rejects a non-PEP and denies a divergent consent projection", async function () {
    const scenario = await setupTreatmentObservationScenario();
    const consentIdHash = id("Consent/cons-directed-2");
    const consentProjectionHash = id("projection:cons-directed-2");
    const request = institutionalRequest(scenario, consentIdHash, consentProjectionHash);
    await scenario.accessControl.registerInstitution(scenario.organizationHash, scenario.organization.address, id("metadata"));
    await scenario.accessControl.connect(scenario.patient).registerDirectedConsent({
      consentIdHash,
      consentProjectionHash,
      patientHash: scenario.patientHash,
      granteeOrganizationHash: scenario.organizationHash,
      actorConstraintHash: scenario.actorHash,
      resourceIdHash: scenario.resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: scenario.now - 60,
      validUntil: scenario.now + 3600,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    });
    await expect(scenario.accessControl.connect(scenario.otherRequester).requestInstitutionalAccess(request)).to.be.revertedWith("PEP_NOT_AUTHORIZED");
    await scenario.accessControl.setPepAuthorization(scenario.otherRequester.address, true);
    expect((await scenario.accessControl.connect(scenario.otherRequester).requestInstitutionalAccess.staticCall({
      ...request,
      consentProjectionHash: id("projection:tampered")
    }))[0]).to.equal(false);
  });

  it("allows an authorized custodian PEP to evaluate an interinstitutional request", async function () {
    const scenario = await setupVersionedInstitutionalScenario();
    const custodianPep = scenario.organization;
    await scenario.accessControl.setPepAuthorization(custodianPep.address, true);

    expect((await scenario.accessControl.connect(custodianPep).requestInstitutionalAccess.staticCall(scenario.request))[0]).to.equal(true);
    await (await scenario.accessControl.connect(custodianPep).requestInstitutionalAccess(scenario.request)).wait();
    expect(await scenario.accessControl.connect(custodianPep).verifyInstitutionalAccess.staticCall(scenario.request, scenario.now + 1)).to.equal(true);
  });

  it("re-evaluates an institutional decision after patient Consent revocation", async function () {
    const scenario = await setupVersionedInstitutionalScenario();
    expect((await scenario.accessControl.connect(scenario.pep).requestInstitutionalAccess.staticCall(scenario.request))[0]).to.equal(true);
    await scenario.accessControl.connect(scenario.pep).requestInstitutionalAccess(scenario.request);
    expect(await scenario.accessControl.connect(scenario.pep).verifyInstitutionalAccess.staticCall(scenario.request, scenario.now + 1)).to.equal(true);
    await (await scenario.accessControl.connect(scenario.pep).verifyInstitutionalAccess(scenario.request, scenario.now + 1)).wait();

    await scenario.accessControl.connect(scenario.patient).revokePatientConsent(scenario.consentIdHash, 1);
    expect(await scenario.accessControl.connect(scenario.pep).verifyInstitutionalAccess.staticCall(scenario.request, scenario.now + 2)).to.equal(false);
  });

  it("re-evaluates institutional decisions after policy or registry deactivation", async function () {
    const deactivations = [
      ["policy", async (scenario: Awaited<ReturnType<typeof setupVersionedInstitutionalScenario>>) => scenario.accessControl.deactivatePolicy(scenario.policyId, 1)],
      ["organization", async (scenario: Awaited<ReturnType<typeof setupVersionedInstitutionalScenario>>) => scenario.accessControl.setOrganizationActive(scenario.organizationHash, false)],
      ["practitioner", async (scenario: Awaited<ReturnType<typeof setupVersionedInstitutionalScenario>>) => scenario.accessControl.setPractitionerActive(scenario.actorHash, false)],
      ["license", async (scenario: Awaited<ReturnType<typeof setupVersionedInstitutionalScenario>>) => scenario.accessControl.setPractitionerLicenseActive(scenario.actorHash, false)],
      ["institution", async (scenario: Awaited<ReturnType<typeof setupVersionedInstitutionalScenario>>) => scenario.accessControl.setInstitutionActive(scenario.organizationHash, false)]
    ] as const;

    for (const [label, deactivate] of deactivations) {
      const scenario = await setupVersionedInstitutionalScenario();
      await scenario.accessControl.connect(scenario.pep).requestInstitutionalAccess(scenario.request);
      await deactivate(scenario);
      expect(await scenario.accessControl.connect(scenario.pep).verifyInstitutionalAccess.staticCall(scenario.request, scenario.now + 1), label).to.equal(false);
    }
  });

  it("binds enforcement finalization to the institution gateway that made the decision", async function () {
    const scenario = await setupVersionedInstitutionalScenario();
    await scenario.accessControl.connect(scenario.pep).requestInstitutionalAccess(scenario.request);
    const requestHash = await scenario.accessControl.computeInstitutionalRequestHash(scenario.request, scenario.pep.address);
    const otherPep = scenario.practitioner;
    await scenario.accessControl.setPepAuthorization(otherPep.address, true);

    await expect(scenario.accessControl.connect(otherPep).finalizeEnforcement(requestHash, true, REASON_PERMIT))
      .to.be.revertedWith("PEP_INSTITUTION_MISMATCH");
    await expect(scenario.accessControl.connect(scenario.pep).finalizeEnforcement(requestHash, true, REASON_PERMIT))
      .to.emit(scenario.accessControl, "EnforcementFinalized");
  });
});

function institutionalRequest(
  scenario: {
    patientHash: string;
    actorHash: string;
    organizationHash: string;
    resourceIdHash: string;
    resourceHash: string;
    now: number;
  },
  consentIdHash: string,
  consentProjectionHash: string
) {
  return {
    shareIdHash: id("share:1"),
    manifestIdHash: id("manifest:1"),
    consentIdHash,
    consentProjectionHash,
    patientHash: scenario.patientHash,
    actorHash: scenario.actorHash,
    organizationHash: scenario.organizationHash,
    resourceIdHash: scenario.resourceIdHash,
    resourceHash: scenario.resourceHash,
    assertionHash: id("assertion:1"),
    resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
    actionCode: ACTION_READ_CODE,
    purposeCode: PURPOSE_TREATMENT_CODE,
    attributesMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
    requestTime: scenario.now
  };
}
