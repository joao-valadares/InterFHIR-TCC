import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

const RESOURCE_TYPE_OBSERVATION = 1;
const ACTION_READ_CODE = 1;
const PURPOSE_TREATMENT_CODE = 1;
const REQUIRED_MASK = 0b111111111111;
const REASON_PERMIT = 1;
const REASON_PATIENT_REVOKED = 14;

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

describe("InterFHIR registries", function () {
  it("stores organizations and practitioners in AttributeRegistry", async function () {
    const [owner, practitioner, organization] = await ethers.getSigners();
    const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
    const registry = await AttributeRegistry.deploy();
    const practitionerHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");

    await expect(registry.registerOrganization(organization.address, organizationHash))
      .to.emit(registry, "OrganizationRegistered")
      .withArgs(organization.address, organizationHash, owner.address);

    await expect(registry.registerPractitioner(practitioner.address, practitionerHash, organizationHash, 1, 1, true))
      .to.emit(registry, "PractitionerRegistered")
      .withArgs(practitioner.address, practitionerHash, organizationHash, true, owner.address);

    expect(await registry.practitionerHashByAccount(practitioner.address)).to.equal(practitionerHash);
  });

  it("prevents non-owners from managing AttributeRegistry participants", async function () {
    const [owner, attacker, organization] = await ethers.getSigners();
    const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
    const registry = await AttributeRegistry.deploy();
    const organizationHash = id("Organization/hospital-a");

    await expect(registry.connect(attacker).registerOrganization(organization.address, organizationHash)).to.be.revertedWith(
      "ONLY_OWNER"
    );

    await registry.transferOwnership(attacker.address);

    await expect(registry.registerOrganization(organization.address, organizationHash)).to.be.revertedWith("ONLY_OWNER");
    await expect(registry.connect(attacker).registerOrganization(organization.address, organizationHash))
      .to.emit(registry, "OrganizationRegistered")
      .withArgs(organization.address, organizationHash, attacker.address);

    expect(owner.address).to.not.equal(attacker.address);
  });

  it("stores and revokes patient consent in ConsentRegistry", async function () {
    const [patient] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const consentHash = id("Consent/cons-1");
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const now = 1_800_000_000;

    await expect(
      registry.connect(patient).registerConsent({
        consentHash,
        patientHash,
        actorHash,
        organizationHash,
        resourceIdHash,
        resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
        actionCode: ACTION_READ_CODE,
        purposeCode: PURPOSE_TREATMENT_CODE,
        validFrom: now - 60,
        validUntil: now + 3600,
        policyMask: REQUIRED_MASK
      })
    )
      .to.emit(registry, "ConsentRegistered")
      .withArgs(consentHash, patientHash, actorHash);

    expect(await registry.findConsentHash(patientHash, actorHash, organizationHash, resourceIdHash)).to.equal(consentHash);

    await expect(registry.connect(patient).revokeConsent(consentHash))
      .to.emit(registry, "ConsentRevoked")
      .withArgs(consentHash, patientHash, patient.address);

    const consent = await registry.consents(consentHash);
    expect(consent.active).to.equal(false);
  });

  it("rejects duplicate active consents for the same hash or scope", async function () {
    const [patient] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const now = 1_800_000_000;
    const input = {
      consentHash: id("Consent/cons-1"),
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 60,
      validUntil: now + 3600,
      policyMask: REQUIRED_MASK
    };

    await registry.connect(patient).registerConsent(input);

    await expect(registry.connect(patient).registerConsent(input)).to.be.revertedWith("CONSENT_ALREADY_ACTIVE");
    await expect(
      registry.connect(patient).registerConsent({
        ...input,
        consentHash: id("Consent/cons-2")
      })
    ).to.be.revertedWith("CONSENT_SCOPE_ALREADY_ACTIVE");
  });

  it("allows a new consent for the same scope after revocation", async function () {
    const [patient] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const now = 1_800_000_000;
    const firstConsentHash = id("Consent/cons-1");
    const secondConsentHash = id("Consent/cons-2");
    const input = {
      consentHash: firstConsentHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 60,
      validUntil: now + 3600,
      policyMask: REQUIRED_MASK
    };

    await registry.connect(patient).registerConsent(input);
    await registry.connect(patient).revokeConsent(firstConsentHash);
    await registry.connect(patient).registerConsent({
      ...input,
      consentHash: secondConsentHash
    });

    expect(await registry.findConsentHash(patientHash, actorHash, organizationHash, resourceIdHash)).to.equal(secondConsentHash);
  });

  it("rejects consent records with empty pseudonymized scope fields", async function () {
    const [patient] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const now = 1_800_000_000;
    const input = {
      consentHash: id("Consent/cons-1"),
      patientHash: ethers.ZeroHash,
      actorHash: id("Practitioner/ana"),
      organizationHash: id("Organization/hospital-a"),
      resourceIdHash: id("Observation/obs-1"),
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 60,
      validUntil: now + 3600,
      policyMask: REQUIRED_MASK
    };

    await expect(registry.connect(patient).registerConsent(input)).to.be.revertedWith("INVALID_PATIENT_HASH");
    await expect(
      registry.connect(patient).registerConsent({
        ...input,
        patientHash: id("Patient/maria"),
        actorHash: ethers.ZeroHash
      })
    ).to.be.revertedWith("INVALID_ACTOR_HASH");
    await expect(
      registry.connect(patient).registerConsent({
        ...input,
        patientHash: id("Patient/maria"),
        organizationHash: ethers.ZeroHash
      })
    ).to.be.revertedWith("INVALID_ORGANIZATION_HASH");
    await expect(
      registry.connect(patient).registerConsent({
        ...input,
        patientHash: id("Patient/maria"),
        resourceIdHash: ethers.ZeroHash
      })
    ).to.be.revertedWith("INVALID_RESOURCE_ID_HASH");
  });

  it("evaluates whether a consent matches scope and time without exposing clinical data", async function () {
    const [patient] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const consentHash = id("Consent/cons-1");
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const otherActorHash = id("Practitioner/bruno");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const now = 1_800_000_000;

    await registry.connect(patient).registerConsent({
      consentHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 60,
      validUntil: now + 3600,
      policyMask: REQUIRED_MASK
    });

    expect(
      await registry.isConsentValid(
        patientHash,
        actorHash,
        organizationHash,
        resourceIdHash,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        now
      )
    ).to.equal(true);

    expect(
      await registry.isConsentValid(
        patientHash,
        otherActorHash,
        organizationHash,
        resourceIdHash,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        now
      )
    ).to.equal(false);

    expect(
      await registry.isConsentValid(
        patientHash,
        actorHash,
        organizationHash,
        resourceIdHash,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        now + 7200
      )
    ).to.equal(false);

    await registry.connect(patient).revokeConsent(consentHash);

    expect(
      await registry.isConsentValid(
        patientHash,
        actorHash,
        organizationHash,
        resourceIdHash,
        RESOURCE_TYPE_OBSERVATION,
        ACTION_READ_CODE,
        PURPOSE_TREATMENT_CODE,
        now
      )
    ).to.equal(false);
  });

  it("prevents unauthorized writers from registering consent for another data subject", async function () {
    const [owner, patient, attacker] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    const consentHash = id("Consent/cons-1");
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const now = 1_800_000_000;
    const input = {
      consentHash,
      patientHash,
      actorHash,
      organizationHash,
      resourceIdHash,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: now - 60,
      validUntil: now + 3600,
      policyMask: REQUIRED_MASK
    };

    await expect(registry.connect(attacker).registerConsentFor(input, patient.address)).to.be.revertedWith(
      "NOT_AUTHORIZED_WRITER"
    );

    await registry.authorizeWriter(attacker.address, true);
    await expect(registry.connect(attacker).registerConsentFor(input, patient.address))
      .to.emit(registry, "ConsentRegistered")
      .withArgs(consentHash, patientHash, actorHash);

    const consent = await registry.consents(consentHash);
    expect(consent.dataSubject).to.equal(patient.address);
    expect(owner.address).to.not.equal(attacker.address);
  });

  it("versions patient Consents and requires the exact version for revocation and supersession", async function () {
    const [owner, patient, writer, organization] = await ethers.getSigners();
    const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
    const registry = await ConsentRegistry.deploy();
    await registry.authorizeWriter(writer.address, true);
    const consentIdHash = id("Consent/maria-hospital-a");
    const patientHash = id("Patient/maria");
    const organizationHash = id("Organization/hospital-a");
    const resourceIdHash = id("Observation/obs-1");
    const base = {
      consentIdHash,
      consentProjectionHash: id("projection-v1"),
      patientHash,
      actorConstraintHash: ethers.ZeroHash,
      granteeOrganizationHash: organizationHash,
      resourceIdHash,
      policyIdHash: id("POLICY_TREATMENT_OBSERVATION"),
      policyVersion: 1,
      consentVersion: 1,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: 1_800_000_000,
      validUntil: 1_800_003_600,
      policyMask: REQUIRED_MASK
    };

    await expect(registry.connect(patient).registerPatientConsent(base)).to.be.revertedWith(
      "PATIENT_CONSENT_CONTROLLER_ONLY"
    );
    await expect(registry.connect(writer).registerPatientConsentFor(base, patient.address)).to.be.revertedWith(
      "PATIENT_CONSENT_CONTROLLER_ONLY"
    );
    const nextVersion = { ...base, consentVersion: 2, consentProjectionHash: id("projection-v2") };
    await expect(registry.connect(patient).supersedePatientConsent(nextVersion, 1)).to.be.revertedWith(
      "PATIENT_CONSENT_CONTROLLER_ONLY"
    );
    await expect(registry.connect(writer).supersedePatientConsentFor(nextVersion, 1, patient.address)).to.be.revertedWith(
      "PATIENT_CONSENT_CONTROLLER_ONLY"
    );
    await (registry as any).authorizePatientConsentController(writer.address, true);

    await expect(registry.connect(writer).registerPatientConsentFor(base, patient.address))
      .to.emit(registry, "PatientConsentRegistered")
      .withArgs(consentIdHash, patientHash, 1, base.policyIdHash, writer.address);

    await expect(registry.connect(writer).supersedePatientConsentFor(nextVersion, 1, patient.address))
      .to.emit(registry, "PatientConsentSuperseded")
      .withArgs(consentIdHash, 1, 2, writer.address);
    expect((await registry.patientConsents(consentIdHash, 1)).active).to.equal(false);
    expect((await registry.patientConsentProjections(consentIdHash, 1)).status).to.equal(3);
    expect((await registry.patientConsents(consentIdHash, 2)).active).to.equal(true);

    await expect(registry.connect(writer).revokePatientConsentFor(consentIdHash, 2, patient.address))
      .to.emit(registry, "PatientConsentRevoked")
      .withArgs(consentIdHash, 2, patientHash, patient.address);
    expect((await registry.patientConsents(consentIdHash, 2)).active).to.equal(false);
    await expect(registry.connect(patient).revokePatientConsent(consentIdHash, 2)).to.be.revertedWith(
      "PATIENT_CONSENT_CONTROLLER_ONLY"
    );
    expect(owner.address).to.not.equal(organization.address);
  });

  it("deactivates organizations, practitioners and licenses immediately", async function () {
    const [owner, practitioner, organization] = await ethers.getSigners();
    const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
    const registry = await AttributeRegistry.deploy();
    const organizationHash = id("Organization/hospital-a");
    const practitionerHash = id("Practitioner/ana");
    await registry.registerOrganization(organization.address, organizationHash);
    await registry.registerPractitioner(practitioner.address, practitionerHash, organizationHash, 1, 1, true);

    await expect(registry.setOrganizationActive(organizationHash, false))
      .to.emit(registry, "OrganizationActiveChanged")
      .withArgs(organizationHash, false, owner.address);
    await expect(registry.setPractitionerActive(practitionerHash, false))
      .to.emit(registry, "PractitionerActiveChanged")
      .withArgs(practitionerHash, false, owner.address);
    await expect(registry.setPractitionerLicenseActive(practitionerHash, false))
      .to.emit(registry, "PractitionerLicenseChanged")
      .withArgs(practitionerHash, false, owner.address);
    expect((await registry.getPractitioner(practitionerHash)).active).to.equal(false);
    expect((await registry.getPractitioner(practitionerHash)).licenseActive).to.equal(false);
  });

  it("records access decisions in AuditRegistry without clinical data", async function () {
    const [requester] = await ethers.getSigners();
    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    const registry = await AuditRegistry.deploy();
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const resourceIdHash = id("Observation/obs-1");
    const resourceHash = id("Observation/obs-1/content-v1");
    const policyId = id("policy:observation:treatment:read");

    await expect(
      registry.recordDecision(requester.address, patientHash, actorHash, resourceIdHash, resourceHash, policyId, true, REASON_PERMIT)
    )
      .to.emit(registry, "AccessDecisionRecorded")
      .withArgs(1, requester.address, patientHash, actorHash, resourceIdHash, resourceHash, policyId, true, REASON_PERMIT);

    const decision = await registry.decisions(1);
    expect(decision.requester).to.equal(requester.address);
    expect(decision.granted).to.equal(true);
    expect(decision.reasonCode).to.equal(REASON_PERMIT);
  });

  it("prevents unauthorized accounts from writing audit decisions", async function () {
    const [requester, attacker] = await ethers.getSigners();
    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    const registry = await AuditRegistry.deploy();
    const patientHash = id("Patient/maria");
    const actorHash = id("Practitioner/ana");
    const resourceIdHash = id("Observation/obs-1");
    const resourceHash = id("Observation/obs-1/content-v1");
    const policyId = id("policy:observation:treatment:read");

    await expect(
      registry
        .connect(attacker)
        .recordDecision(requester.address, patientHash, actorHash, resourceIdHash, resourceHash, policyId, true, REASON_PERMIT)
    ).to.be.revertedWith("NOT_AUTHORIZED_WRITER");
  });

  it("records consent revocations in AuditRegistry without clinical data", async function () {
    const [patient] = await ethers.getSigners();
    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    const registry = await AuditRegistry.deploy();
    const consentHash = id("Consent/cons-1");
    const patientHash = id("Patient/maria");

    await expect(registry.recordConsentRevocation(consentHash, patientHash, patient.address, REASON_PATIENT_REVOKED))
      .to.emit(registry, "ConsentRevocationRecorded")
      .withArgs(1, consentHash, patientHash, patient.address, REASON_PATIENT_REVOKED);

    const revocation = await registry.revocations(1);
    expect(revocation.consentHash).to.equal(consentHash);
    expect(revocation.patientHash).to.equal(patientHash);
    expect(revocation.revokedBy).to.equal(patient.address);
    expect(revocation.reasonCode).to.equal(REASON_PATIENT_REVOKED);
  });

  it("stores resource integrity hashes without clinical data", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
    const registry = await ResourceRegistry.deploy();
    const resourceIdHash = id("Observation/obs-1");
    const resourceHash = id("Observation/obs-1/content-v1");

    await expect(registry.registerResourceHash(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash))
      .to.emit(registry, "ResourceHashRegistered")
      .withArgs(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash, owner.address);

    expect(await registry.isResourceHashValid(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash)).to.equal(true);
    expect(await registry.isResourceHashValid(resourceIdHash, RESOURCE_TYPE_OBSERVATION, id("tampered"))).to.equal(false);

    await expect(
      registry.connect(attacker).registerResourceHash(resourceIdHash, RESOURCE_TYPE_OBSERVATION, resourceHash)
    ).to.be.revertedWith("ONLY_OWNER");
  });

  it("anchors manifest commitments and transitions versions without clinical payloads", async function () {
    const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
    const registry = await ResourceRegistry.deploy();
    const manifestIdHash = id("manifest:vault:hospital-a:Observation/obs-1:v1");
    const activeV1 = id("manifest-v1-active");
    const supersededV1 = id("manifest-v1-superseded");
    const activeV2 = id("manifest-v2-active");
    const manifestRegistry = registry as any;

    await expect(
      manifestRegistry.anchorManifestVersion(
        manifestIdHash,
        1,
        activeV1,
        ethers.ZeroHash
      )
    )
      .to.emit(registry, "ManifestVersionAnchored")
      .withArgs(manifestIdHash, 1, activeV1, 1, (await ethers.getSigners())[0].address);

    await expect(
      manifestRegistry.supersedeAndAnchorManifestVersion(
        manifestIdHash,
        1,
        activeV1,
        supersededV1,
        2,
        activeV2
      )
    )
      .to.emit(registry, "ManifestVersionAnchored")
      .withArgs(manifestIdHash, 2, activeV2, 1, (await ethers.getSigners())[0].address);

    const first = await manifestRegistry.manifests(manifestIdHash, 1);
    const second = await manifestRegistry.manifests(manifestIdHash, 2);
    expect(first.commitment).to.equal(supersededV1);
    expect(first.status).to.equal(2);
    expect(second.commitment).to.equal(activeV2);
    expect(second.status).to.equal(1);
    expect(await manifestRegistry.latestManifestVersion(manifestIdHash)).to.equal(2);
  });

  it("rejects inconsistent manifest versions and commitments", async function () {
    const [, attacker] = await ethers.getSigners();
    const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
    const registry = await ResourceRegistry.deploy();
    const manifestRegistry = registry as any;
    const manifestIdHash = id("manifest:vault:hospital-a:Observation/obs-1:v1");
    const activeV1 = id("manifest-v1-active");

    await expect(
      manifestRegistry.anchorManifestVersion(
        manifestIdHash,
        2,
        activeV1,
        ethers.ZeroHash
      )
    ).to.be.revertedWith("INVALID_MANIFEST_VERSION");

    await manifestRegistry.anchorManifestVersion(
      manifestIdHash,
      1,
      activeV1,
      ethers.ZeroHash
    );

    await expect(
      manifestRegistry.supersedeAndAnchorManifestVersion(
        manifestIdHash,
        1,
        id("wrong-current"),
        id("superseded"),
        2,
        id("active-v2")
      )
    ).to.be.revertedWith("MANIFEST_COMMITMENT_MISMATCH");

    await expect(
      manifestRegistry
        .connect(attacker)
        .revokeManifestVersion(
          manifestIdHash,
          1,
          activeV1,
          id("revoked")
        )
    ).to.be.revertedWith("ONLY_OWNER");
  });

  it("anchors manifest revocation and rejects delivery-state reuse", async function () {
    const [owner] = await ethers.getSigners();
    const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
    const registry = await ResourceRegistry.deploy();
    const manifestRegistry = registry as any;
    const manifestIdHash = id("manifest:vault:hospital-a:Observation/obs-1:v1");
    const activeCommitment = id("manifest-v1-active");
    const revokedCommitment = id("manifest-v1-revoked");

    await manifestRegistry.anchorManifestVersion(
      manifestIdHash,
      1,
      activeCommitment,
      ethers.ZeroHash
    );
    await expect(
      manifestRegistry.revokeManifestVersion(
        manifestIdHash,
        1,
        activeCommitment,
        revokedCommitment
      )
    )
      .to.emit(registry, "ManifestStatusChanged")
      .withArgs(
        manifestIdHash,
        1,
        activeCommitment,
        revokedCommitment,
        3,
        owner.address
      );

    const revoked = await manifestRegistry.manifests(manifestIdHash, 1);
    expect(revoked.commitment).to.equal(revokedCommitment);
    expect(revoked.status).to.equal(3);
    await expect(
      manifestRegistry.supersedeAndAnchorManifestVersion(
        manifestIdHash,
        1,
        revokedCommitment,
        id("superseded"),
        2,
        id("active-v2")
      )
    ).to.be.revertedWith("MANIFEST_NOT_ACTIVE");
  });
});
