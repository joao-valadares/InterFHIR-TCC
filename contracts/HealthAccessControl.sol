// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AttributeRegistry} from "./AttributeRegistry.sol";
import {AuditRegistry} from "./AuditRegistry.sol";
import {ConsentRegistry} from "./ConsentRegistry.sol";
import {ResourceRegistry} from "./ResourceRegistry.sol";
import {InstitutionRegistry} from "./InstitutionRegistry.sol";

contract HealthAccessControl {
    uint16 private constant ATTRIBUTE_ROLE_PRACTITIONER = 1 << 0;
    uint16 private constant ATTRIBUTE_ORG_AUTHORIZED = 1 << 1;
    uint16 private constant ATTRIBUTE_LICENSE_ACTIVE = 1 << 2;
    uint16 private constant ATTRIBUTE_RESOURCE_TYPE = 1 << 3;
    uint16 private constant ATTRIBUTE_ACTION = 1 << 4;
    uint16 private constant ATTRIBUTE_PURPOSE_TREATMENT = 1 << 5;
    uint16 private constant ATTRIBUTE_CONSENT_ACTIVE = 1 << 6;
    uint16 private constant ATTRIBUTE_CONSENT_PERIOD = 1 << 7;
    uint16 private constant ATTRIBUTE_PURPOSE_PAYMENT = 1 << 8;
    uint16 private constant ATTRIBUTE_INTEGRITY = 1 << 9;
    uint16 private constant ATTRIBUTE_DATA_SUBJECT = 1 << 10;
    uint16 private constant ATTRIBUTE_REQUESTER_CONSENT = 1 << 11;

    struct Policy {
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint16 requiredMask;
        bool active;
    }

    struct PolicyVersion {
        bytes32 policyId;
        uint32 version;
        bytes32 definitionHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint16 requiredMask;
        uint16 requiredRoleCode;
        uint16 requiredSpecialtyCode;
        uint64 effectiveFrom;
        uint64 effectiveUntil;
        bool active;
    }

    struct RegisterConsentInput {
        bytes32 consentHash;
        bytes32 patientHash;
        bytes32 actorHash;
        bytes32 organizationHash;
        bytes32 resourceIdHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint64 validFrom;
        uint64 validUntil;
        uint16 policyMask;
    }

    struct AccessRequest {
        bytes32 patientHash;
        bytes32 actorHash;
        bytes32 organizationHash;
        bytes32 resourceIdHash;
        bytes32 resourceHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint16 attributesMask;
        uint64 requestTime;
    }

    struct InstitutionalAccessRequest {
        bytes32 shareIdHash;
        bytes32 manifestIdHash;
        bytes32 consentIdHash;
        bytes32 consentProjectionHash;
        bytes32 patientHash;
        bytes32 actorHash;
        bytes32 organizationHash;
        bytes32 resourceIdHash;
        bytes32 resourceHash;
        bytes32 assertionHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint16 attributesMask;
        uint64 requestTime;
    }

    struct StoredAccessDecision {
        address requester;
        uint64 expiresAt;
        uint64 decisionId;
        bool granted;
        bytes32 policyId;
        bytes32 organizationHash;
        address gatewayAccount;
    }

    uint64 public constant ACCESS_DECISION_TTL = 300;
    uint8 public constant REASON_PERMIT = 1;
    uint8 public constant REASON_CONSENT_NOT_FOUND = 2;
    uint8 public constant REASON_CONSENT_NOT_ACTIVE = 3;
    uint8 public constant REASON_CONSENT_OUT_OF_PERIOD = 4;
    uint8 public constant REASON_CONSENT_SCOPE_MISMATCH = 5;
    uint8 public constant REASON_RESOURCE_HASH_MISMATCH = 6;
    uint8 public constant REASON_REQUESTER_NOT_AUTHORIZED = 7;
    uint8 public constant REASON_POLICY_NOT_ACTIVE = 8;
    uint8 public constant REASON_ATTRIBUTES_NOT_COMPLIANT = 9;
    uint8 public constant REASON_CONSENT_MASK_NOT_MET = 10;
    uint8 public constant REASON_DECISION_NOT_FOUND = 11;
    uint8 public constant REASON_DECISION_NOT_GRANTED = 12;
    uint8 public constant REASON_DECISION_EXPIRED = 13;
    uint8 public constant REASON_PATIENT_REVOKED = 14;
    uint8 public constant REASON_LEGACY_AUTHORIZATION_DISABLED = 15;

    address public immutable owner;
    AttributeRegistry public immutable attributeRegistry;
    ConsentRegistry public immutable consentRegistry;
    AuditRegistry public immutable auditRegistry;
    ResourceRegistry public immutable resourceRegistry;
    InstitutionRegistry public immutable institutionRegistry;
    mapping(address => bool) public authorizedPeps;

    mapping(bytes32 => Policy) public policies;
    mapping(bytes32 => mapping(uint32 => PolicyVersion)) public policyVersions;
    mapping(bytes32 => uint32) public latestPolicyVersion;
    mapping(bytes32 => StoredAccessDecision) public accessDecisions;

    event OrganizationRegistered(address indexed account, bytes32 indexed organizationHash, address indexed registeredBy);
    event PractitionerRegistered(
        address indexed account,
        bytes32 indexed practitionerHash,
        bytes32 indexed organizationHash,
        bool licenseActive,
        address registeredBy
    );
    event PolicyCreated(
        bytes32 indexed policyId,
        uint16 resourceTypeCode,
        uint16 actionCode,
        uint16 purposeCode,
        uint16 requiredMask,
        bool active
    );
    event PolicyVersionCreated(
        bytes32 indexed policyId,
        uint32 indexed version,
        bytes32 indexed definitionHash,
        bool active,
        address registeredBy
    );
    event PolicyVersionDeactivated(bytes32 indexed policyId, uint32 indexed version, address indexed deactivatedBy);
    event ConsentRegistered(bytes32 indexed consentHash, bytes32 indexed patientHash, bytes32 indexed actorHash);
    event ConsentRevoked(bytes32 indexed consentHash, bytes32 indexed patientHash, address indexed revokedBy);
    event AccessRequested(
        address indexed requester,
        bytes32 indexed patientHash,
        bytes32 indexed actorHash,
        bytes32 resourceIdHash
    );
    event AccessGranted(
        address indexed requester,
        bytes32 indexed patientHash,
        bytes32 indexed actorHash,
        bytes32 resourceIdHash,
        bytes32 resourceHash,
        bytes32 policyId
    );
    event AccessDenied(
        address indexed requester,
        bytes32 indexed patientHash,
        bytes32 indexed actorHash,
        bytes32 resourceIdHash,
        uint8 reasonCode
    );
    event AccessVerified(
        address indexed requester,
        bytes32 indexed patientHash,
        bytes32 indexed actorHash,
        bytes32 resourceIdHash,
        bool verified,
        uint8 reasonCode
    );
    event EnforcementFinalized(bytes32 indexed requestHash, bool delivered, uint8 reasonCode, address indexed finalizedBy);

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    constructor(address attributeRegistry_, address consentRegistry_, address auditRegistry_, address resourceRegistry_) {
        require(attributeRegistry_ != address(0), "INVALID_ATTRIBUTE_REGISTRY");
        require(consentRegistry_ != address(0), "INVALID_CONSENT_REGISTRY");
        require(auditRegistry_ != address(0), "INVALID_AUDIT_REGISTRY");
        require(resourceRegistry_ != address(0), "INVALID_RESOURCE_REGISTRY");

        owner = msg.sender;
        attributeRegistry = AttributeRegistry(attributeRegistry_);
        consentRegistry = ConsentRegistry(consentRegistry_);
        auditRegistry = AuditRegistry(auditRegistry_);
        resourceRegistry = ResourceRegistry(resourceRegistry_);
        institutionRegistry = new InstitutionRegistry();
    }

    function organizations(bytes32 organizationHash) external view returns (AttributeRegistry.Organization memory) {
        return attributeRegistry.getOrganization(organizationHash);
    }

    function practitioners(bytes32 practitionerHash) external view returns (AttributeRegistry.Practitioner memory) {
        return attributeRegistry.getPractitioner(practitionerHash);
    }

    function registerOrganization(address account, bytes32 organizationHash) external onlyOwner {
        attributeRegistry.registerOrganization(account, organizationHash);

        emit OrganizationRegistered(account, organizationHash, msg.sender);
    }

    function registerInstitution(bytes32 organizationHash, address gatewayAccount, bytes32 metadataCommitment) external onlyOwner {
        institutionRegistry.registerInstitution(organizationHash, gatewayAccount, metadataCommitment);
    }

    function setInstitutionActive(bytes32 organizationHash, bool active) external onlyOwner {
        institutionRegistry.setInstitutionActive(organizationHash, active);
    }

    function setInstitutionGateway(bytes32 organizationHash, address gatewayAccount) external onlyOwner {
        institutionRegistry.setInstitutionGateway(organizationHash, gatewayAccount);
    }

    function setPepAuthorization(address pep, bool allowed) external onlyOwner {
        require(pep != address(0), "INVALID_PEP");
        authorizedPeps[pep] = allowed;
    }

    function registerPractitioner(
        address account,
        bytes32 practitionerHash,
        bytes32 organizationHash,
        uint16 roleCode,
        uint16 specialtyCode,
        bool licenseActive
    ) external onlyOwner {
        attributeRegistry.registerPractitioner(
            account,
            practitionerHash,
            organizationHash,
            roleCode,
            specialtyCode,
            licenseActive
        );

        emit PractitionerRegistered(account, practitionerHash, organizationHash, licenseActive, msg.sender);
    }

    function setOrganizationActive(bytes32 organizationHash, bool active) external onlyOwner {
        attributeRegistry.setOrganizationActive(organizationHash, active);
    }

    function setPractitionerActive(bytes32 practitionerHash, bool active) external onlyOwner {
        attributeRegistry.setPractitionerActive(practitionerHash, active);
    }

    function setPractitionerLicenseActive(bytes32 practitionerHash, bool active) external onlyOwner {
        attributeRegistry.setPractitionerLicenseActive(practitionerHash, active);
    }

    function createPolicy(
        bytes32 policyId,
        uint16 resourceTypeCode,
        uint16 actionCode,
        uint16 purposeCode,
        uint16 requiredMask,
        bool active
    ) external onlyOwner {
        require(policyId != bytes32(0), "INVALID_POLICY_ID");
        require(requiredMask != 0, "INVALID_POLICY_MASK");

        _registerPolicyVersion(
            PolicyVersion({
                policyId: policyId,
                version: 1,
                definitionHash: keccak256(
                    abi.encode(policyId, uint32(1), resourceTypeCode, actionCode, purposeCode, requiredMask)
                ),
                resourceTypeCode: resourceTypeCode,
                actionCode: actionCode,
                purposeCode: purposeCode,
                requiredMask: requiredMask,
                requiredRoleCode: 0,
                requiredSpecialtyCode: 0,
                effectiveFrom: 0,
                effectiveUntil: 0,
                active: active
            })
        );

        emit PolicyCreated(policyId, resourceTypeCode, actionCode, purposeCode, requiredMask, active);
    }

    function createPolicyVersion(PolicyVersion calldata policy) external onlyOwner {
        _registerPolicyVersion(policy);
    }

    function deactivatePolicy(bytes32 policyId, uint32 version) external onlyOwner {
        PolicyVersion storage policy = policyVersions[policyId][version];
        require(policy.policyId != bytes32(0), "POLICY_VERSION_NOT_FOUND");
        require(policy.active, "POLICY_VERSION_NOT_ACTIVE");
        policy.active = false;
        emit PolicyVersionDeactivated(policyId, version, msg.sender);
    }

    function getActivePolicy(bytes32 policyId, uint32 version) external view returns (PolicyVersion memory) {
        return policyVersions[policyId][version];
    }

    function registerResourceHash(bytes32 resourceIdHash, uint16 resourceTypeCode, bytes32 resourceHash) external onlyOwner {
        resourceRegistry.registerResourceHash(resourceIdHash, resourceTypeCode, resourceHash);
    }

    function anchorManifestVersion(
        bytes32 manifestIdHash,
        uint64 version,
        bytes32 commitment,
        bytes32 previousVersionCommitment
    ) external onlyOwner {
        resourceRegistry.anchorManifestVersion(
            manifestIdHash,
            version,
            commitment,
            previousVersionCommitment
        );
    }

    function supersedeAndAnchorManifestVersion(
        bytes32 manifestIdHash,
        uint64 currentVersion,
        bytes32 expectedCurrentCommitment,
        bytes32 supersededCommitment,
        uint64 nextVersion,
        bytes32 nextCommitment
    ) external onlyOwner {
        resourceRegistry.supersedeAndAnchorManifestVersion(
            manifestIdHash,
            currentVersion,
            expectedCurrentCommitment,
            supersededCommitment,
            nextVersion,
            nextCommitment
        );
    }

    function revokeManifestVersion(
        bytes32 manifestIdHash,
        uint64 version,
        bytes32 expectedCurrentCommitment,
        bytes32 revokedCommitment
    ) external onlyOwner {
        resourceRegistry.revokeManifestVersion(
            manifestIdHash,
            version,
            expectedCurrentCommitment,
            revokedCommitment
        );
    }

    function getManifestRecord(
        bytes32 manifestIdHash,
        uint64 version
    ) external view returns (bytes32 commitment, uint8 status, bool exists) {
        return resourceRegistry.manifests(manifestIdHash, version);
    }

    function registerConsent(RegisterConsentInput calldata input) external {
        ConsentRegistry.RegisterConsentInput memory registryInput = ConsentRegistry.RegisterConsentInput({
            consentHash: input.consentHash,
            patientHash: input.patientHash,
            actorHash: input.actorHash,
            organizationHash: input.organizationHash,
            resourceIdHash: input.resourceIdHash,
            resourceTypeCode: input.resourceTypeCode,
            actionCode: input.actionCode,
            purposeCode: input.purposeCode,
            validFrom: input.validFrom,
            validUntil: input.validUntil,
            policyMask: input.policyMask
        });

        consentRegistry.registerConsentFor(registryInput, msg.sender);

        emit ConsentRegistered(input.consentHash, input.patientHash, input.actorHash);
    }

    function registerDirectedConsent(ConsentRegistry.RegisterDirectedConsentInput calldata input) external {
        consentRegistry.registerDirectedConsentFor(input, msg.sender);
    }

    function registerPatientConsent(ConsentRegistry.RegisterPatientConsentInput calldata input) external {
        _requirePatientConsentPolicy(input);
        consentRegistry.registerPatientConsentFor(input, msg.sender);
    }

    function revokePatientConsent(bytes32 consentIdHash, uint32 consentVersion) external {
        ConsentRegistry.DirectedConsentRecord memory consent = consentRegistry.getPatientConsent(
            consentIdHash,
            consentVersion
        );
        require(consent.consentIdHash != bytes32(0), "CONSENT_NOT_FOUND");
        require(msg.sender == consent.dataSubject || msg.sender == owner, "NOT_CONSENT_SUBJECT");

        consentRegistry.revokePatientConsentFor(consentIdHash, consentVersion, msg.sender);
        auditRegistry.recordConsentRevocation(consentIdHash, consent.patientHash, msg.sender, REASON_PATIENT_REVOKED);
    }

    function supersedePatientConsent(
        ConsentRegistry.RegisterPatientConsentInput calldata input,
        uint32 previousConsentVersion
    ) external {
        _requirePatientConsentPolicy(input);
        ConsentRegistry.DirectedConsentRecord memory previous = consentRegistry.getPatientConsent(
            input.consentIdHash,
            previousConsentVersion
        );
        require(previous.consentIdHash != bytes32(0), "CONSENT_NOT_FOUND");
        require(msg.sender == previous.dataSubject || msg.sender == owner, "NOT_CONSENT_SUBJECT");

        consentRegistry.supersedePatientConsentFor(input, previousConsentVersion, msg.sender);
    }

    function requestInstitutionalAccess(InstitutionalAccessRequest calldata request) external returns (bool granted, uint64 decisionId) {
        if (!authorizedPeps[msg.sender]) revert("PEP_NOT_AUTHORIZED");
        if (!_isCurrentInstitutionalAuthorization(request)) return (false, 0);
        ConsentRegistry.PatientConsentProjection memory projection = consentRegistry.getActivePatientConsentProjection(request.consentIdHash);
        PolicyVersion memory policy = policyVersions[projection.policyIdHash][projection.policyVersion];
        uint64 storedDecisionId = _recordInstitutionalPermit(request, projection.policyIdHash);
        bytes32 requestHash = computeInstitutionalRequestHash(request, msg.sender);
        accessDecisions[requestHash] = StoredAccessDecision({
            requester: msg.sender,
            expiresAt: request.requestTime + ACCESS_DECISION_TTL,
            decisionId: storedDecisionId,
            granted: true,
            policyId: policy.policyId,
            organizationHash: request.organizationHash,
            gatewayAccount: msg.sender
        });
        return (true, storedDecisionId);
    }

    function verifyInstitutionalAccess(InstitutionalAccessRequest calldata request, uint64 verificationTime) external returns (bool) {
        if (!authorizedPeps[msg.sender]) revert("PEP_NOT_AUTHORIZED");
        StoredAccessDecision memory decision = accessDecisions[computeInstitutionalRequestHash(request, msg.sender)];
        return decision.requester == msg.sender
            && decision.granted
            && decision.organizationHash == request.organizationHash
            && decision.gatewayAccount == msg.sender
            && verificationTime <= decision.expiresAt
            && _isCurrentInstitutionalAuthorization(request);
    }

    function finalizeEnforcement(bytes32 requestHash, bool delivered, uint8 reasonCode) external {
        StoredAccessDecision memory decision = accessDecisions[requestHash];
        require(decision.requester != address(0), "DECISION_NOT_FOUND");
        require(decision.gatewayAccount == msg.sender, "PEP_INSTITUTION_MISMATCH");
        InstitutionRegistry.Institution memory institution = institutionRegistry.getInstitution(decision.organizationHash);
        require(institution.active, "INSTITUTION_INACTIVE");
        require(authorizedPeps[msg.sender], "PEP_NOT_AUTHORIZED");
        emit EnforcementFinalized(requestHash, delivered, reasonCode, msg.sender);
    }

    function revokeConsent(bytes32 consentHash) external {
        ConsentRegistry.ConsentRecord memory consent = consentRegistry.getConsent(consentHash);
        require(consent.consentHash != bytes32(0), "CONSENT_NOT_FOUND");
        require(msg.sender == consent.dataSubject || msg.sender == owner, "NOT_CONSENT_SUBJECT");

        consentRegistry.revokeConsent(consentHash);
        auditRegistry.recordConsentRevocation(consentHash, consent.patientHash, msg.sender, REASON_PATIENT_REVOKED);

        emit ConsentRevoked(consentHash, consent.patientHash, msg.sender);
    }

    function requestAccess(AccessRequest calldata request) external returns (bool) {
        emit AccessRequested(msg.sender, request.patientHash, request.actorHash, request.resourceIdHash);
        return _deny(request, REASON_LEGACY_AUTHORIZATION_DISABLED);
    }

    function verifyAccess(AccessRequest calldata request, uint64) external returns (bool) {
        emit AccessVerified(
            msg.sender,
            request.patientHash,
            request.actorHash,
            request.resourceIdHash,
            false,
            REASON_LEGACY_AUTHORIZATION_DISABLED
        );
        return false;
    }

    function computeRequestHash(AccessRequest calldata request, address requester) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                requester,
                request.patientHash,
                request.actorHash,
                request.organizationHash,
                request.resourceIdHash,
                request.resourceHash,
                request.resourceTypeCode,
                request.actionCode,
                request.purposeCode,
                request.attributesMask,
                request.requestTime
            )
        );
    }

    function computeInstitutionalRequestHash(InstitutionalAccessRequest calldata request, address pep) public pure returns (bytes32) {
        return keccak256(abi.encode(pep, request));
    }

    function _deny(AccessRequest calldata request, uint8 reasonCode) private returns (bool) {
        uint256 decisionId = auditRegistry.recordDecision(
            msg.sender,
            request.patientHash,
            request.actorHash,
            request.resourceIdHash,
            request.resourceHash,
            bytes32(0),
            false,
            reasonCode
        );

        bytes32 requestHash = computeRequestHash(request, msg.sender);
        accessDecisions[requestHash] = StoredAccessDecision({
            requester: msg.sender,
            expiresAt: request.requestTime,
            decisionId: uint64(decisionId),
            granted: false,
            policyId: bytes32(0),
            organizationHash: bytes32(0),
            gatewayAccount: address(0)
        });

        emit AccessDenied(msg.sender, request.patientHash, request.actorHash, request.resourceIdHash, reasonCode);
        return false;
    }

    function _registerPolicyVersion(PolicyVersion memory input) private {
        require(input.policyId != bytes32(0), "INVALID_POLICY_ID");
        require(input.version != 0, "INVALID_POLICY_VERSION");
        require(input.definitionHash != bytes32(0), "INVALID_POLICY_DEFINITION_HASH");
        require(input.requiredMask != 0, "INVALID_POLICY_MASK");
        require(input.effectiveUntil == 0 || input.effectiveUntil > input.effectiveFrom, "INVALID_POLICY_PERIOD");

        PolicyVersion storage current = policyVersions[input.policyId][input.version];
        require(current.policyId == bytes32(0), "POLICY_VERSION_ALREADY_EXISTS");
        policyVersions[input.policyId][input.version] = input;

        if (input.version > latestPolicyVersion[input.policyId]) {
            latestPolicyVersion[input.policyId] = input.version;
        }
        policies[input.policyId] = Policy({
            resourceTypeCode: input.resourceTypeCode,
            actionCode: input.actionCode,
            purposeCode: input.purposeCode,
            requiredMask: input.requiredMask,
            active: input.active
        });

        emit PolicyVersionCreated(input.policyId, input.version, input.definitionHash, input.active, msg.sender);
    }

    function _requirePatientConsentPolicy(ConsentRegistry.RegisterPatientConsentInput calldata input) private view {
        PolicyVersion memory policy = policyVersions[input.policyIdHash][input.policyVersion];
        require(policy.policyId != bytes32(0), "POLICY_VERSION_NOT_ACTIVE");
        require(policy.active, "POLICY_VERSION_NOT_ACTIVE");
        require(
            policy.resourceTypeCode == input.resourceTypeCode
                && policy.actionCode == input.actionCode
                && policy.purposeCode == input.purposeCode,
            "POLICY_SCOPE_MISMATCH"
        );
        require(_policyEffectiveAt(policy, input.validFrom), "POLICY_NOT_EFFECTIVE");
        require(_policyEffectiveAt(policy, input.validUntil), "POLICY_EXPIRED");
        require((input.policyMask & policy.requiredMask) == policy.requiredMask, "POLICY_MASK_NOT_MET");
    }

    function _policyEffectiveAt(PolicyVersion memory policy, uint64 timestamp) private pure returns (bool) {
        return timestamp >= policy.effectiveFrom && (policy.effectiveUntil == 0 || timestamp <= policy.effectiveUntil);
    }

    function _policyRoleAndSpecialtyMatch(
        PolicyVersion memory policy,
        AttributeRegistry.Practitioner memory practitioner
    ) private pure returns (bool) {
        return (policy.requiredRoleCode == 0 || practitioner.roleCode == policy.requiredRoleCode)
            && (policy.requiredSpecialtyCode == 0 || practitioner.specialtyCode == policy.requiredSpecialtyCode);
    }

    function _deriveAttributes(
        AttributeRegistry.Practitioner memory practitioner,
        AttributeRegistry.Organization memory organization,
        bytes32 resourceIdHash,
        uint16 resourceTypeCode,
        bytes32 resourceHash,
        bool dataSubjectMatches,
        bool requesterMatchesConsent,
        bool consentActive,
        bool consentPeriodValid,
        uint16 actionCode,
        uint16 purposeCode
    ) private view returns (uint16 attributes) {
        if (practitioner.active) attributes |= ATTRIBUTE_ROLE_PRACTITIONER;
        if (organization.active && practitioner.organizationHash != bytes32(0)) attributes |= ATTRIBUTE_ORG_AUTHORIZED;
        if (practitioner.licenseActive) attributes |= ATTRIBUTE_LICENSE_ACTIVE;
        bool integrityValid = resourceRegistry.isResourceHashValid(resourceIdHash, resourceTypeCode, resourceHash);
        if (integrityValid) {
            attributes |= ATTRIBUTE_RESOURCE_TYPE;
            attributes |= ATTRIBUTE_INTEGRITY;
        }
        if (actionCode != 0) attributes |= ATTRIBUTE_ACTION;
        if (purposeCode == 1) attributes |= ATTRIBUTE_PURPOSE_TREATMENT;
        if (purposeCode == 2) attributes |= ATTRIBUTE_PURPOSE_PAYMENT;
        if (consentActive) attributes |= ATTRIBUTE_CONSENT_ACTIVE;
        if (consentPeriodValid) attributes |= ATTRIBUTE_CONSENT_PERIOD;
        if (dataSubjectMatches) attributes |= ATTRIBUTE_DATA_SUBJECT;
        if (requesterMatchesConsent) attributes |= ATTRIBUTE_REQUESTER_CONSENT;
    }

    function _deriveInstitutionalRequestAttributes(
        InstitutionalAccessRequest calldata request,
        ConsentRegistry.DirectedConsentRecord memory consent,
        AttributeRegistry.Practitioner memory practitioner,
        AttributeRegistry.Organization memory organization
    ) private view returns (uint16) {
        return _deriveAttributes(
            practitioner,
            organization,
            request.resourceIdHash,
            request.resourceTypeCode,
            request.resourceHash,
            consent.patientHash == request.patientHash,
            consent.actorConstraintHash == bytes32(0) || consent.actorConstraintHash == request.actorHash,
            consent.active,
            request.requestTime >= consent.validFrom && request.requestTime <= consent.validUntil,
            request.actionCode,
            request.purposeCode
        );
    }

    function _isCurrentInstitutionalAuthorization(
        InstitutionalAccessRequest calldata request
    ) private view returns (bool) {
        InstitutionRegistry.Institution memory institution = institutionRegistry.getInstitution(request.organizationHash);
        if (!institution.active) return false;

        AttributeRegistry.Organization memory organization = attributeRegistry.getOrganization(request.organizationHash);
        AttributeRegistry.Practitioner memory practitioner = attributeRegistry.getPractitioner(request.actorHash);
        if (
            !organization.active || !practitioner.active || !practitioner.licenseActive
                || practitioner.organizationHash != request.organizationHash
        ) return false;

        ConsentRegistry.DirectedConsentRecord memory consent = consentRegistry.getDirectedConsent(request.consentIdHash);
        if (
            consent.consentIdHash == bytes32(0) || !consent.active
                || consent.consentProjectionHash != request.consentProjectionHash
                || consent.patientHash != request.patientHash
                || consent.granteeOrganizationHash != request.organizationHash
                || consent.resourceIdHash != request.resourceIdHash
                || (consent.actorConstraintHash != bytes32(0) && consent.actorConstraintHash != request.actorHash)
                || request.requestTime < consent.validFrom || request.requestTime > consent.validUntil
                || consent.resourceTypeCode != request.resourceTypeCode
                || consent.actionCode != request.actionCode
                || consent.purposeCode != request.purposeCode
        ) return false;

        ConsentRegistry.PatientConsentProjection memory projection = consentRegistry.getActivePatientConsentProjection(
            request.consentIdHash
        );
        if (
            !projection.active || projection.status != 1
                || projection.policyIdHash == bytes32(0) || projection.policyVersion == 0
                || projection.consentVersion == 0
                || consentRegistry.activePatientConsentVersion(request.consentIdHash) != projection.consentVersion
                || projection.consentProjectionHash != request.consentProjectionHash
        ) return false;

        PolicyVersion memory policy = policyVersions[projection.policyIdHash][projection.policyVersion];
        if (
            policy.policyId != projection.policyIdHash || policy.version != projection.policyVersion || !policy.active
                || policy.resourceTypeCode != request.resourceTypeCode
                || policy.actionCode != request.actionCode
                || policy.purposeCode != request.purposeCode
                || !_policyEffectiveAt(policy, request.requestTime)
                || !_policyRoleAndSpecialtyMatch(policy, practitioner)
                || !resourceRegistry.isResourceHashValid(request.resourceIdHash, request.resourceTypeCode, request.resourceHash)
        ) return false;

        uint16 effectiveAttributes = _deriveInstitutionalRequestAttributes(request, consent, practitioner, organization);
        return (effectiveAttributes & policy.requiredMask) == policy.requiredMask
            && (effectiveAttributes & consent.policyMask) == consent.policyMask;
    }

    function _recordInstitutionalPermit(
        InstitutionalAccessRequest calldata request,
        bytes32 policyId
    ) private returns (uint64) {
        return uint64(
            auditRegistry.recordDecision(
                msg.sender,
                request.patientHash,
                request.actorHash,
                request.resourceIdHash,
                request.resourceHash,
                policyId,
                true,
                REASON_PERMIT
            )
        );
    }

}
