// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ConsentRegistry {
    uint8 public constant CONSENT_STATUS_ACTIVE = 1;
    uint8 public constant CONSENT_STATUS_REVOKED = 2;
    uint8 public constant CONSENT_STATUS_SUPERSEDED = 3;

    struct DirectedConsentRecord {
        bytes32 consentIdHash;
        bytes32 consentProjectionHash;
        bytes32 patientHash;
        bytes32 granteeOrganizationHash;
        bytes32 actorConstraintHash;
        bytes32 resourceIdHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint64 validFrom;
        uint64 validUntil;
        bool active;
        uint16 policyMask;
        address dataSubject;
    }

    struct PatientConsentProjection {
        bytes32 policyIdHash;
        uint32 policyVersion;
        uint32 consentVersion;
        bytes32 consentProjectionHash;
        bool active;
        uint8 status;
    }

    struct RegisterDirectedConsentInput {
        bytes32 consentIdHash;
        bytes32 consentProjectionHash;
        bytes32 patientHash;
        bytes32 granteeOrganizationHash;
        bytes32 actorConstraintHash;
        bytes32 resourceIdHash;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint64 validFrom;
        uint64 validUntil;
        uint16 policyMask;
    }

    struct RegisterPatientConsentInput {
        bytes32 consentIdHash;
        bytes32 consentProjectionHash;
        bytes32 patientHash;
        bytes32 actorConstraintHash;
        bytes32 granteeOrganizationHash;
        bytes32 resourceIdHash;
        bytes32 policyIdHash;
        uint32 policyVersion;
        uint32 consentVersion;
        uint16 resourceTypeCode;
        uint16 actionCode;
        uint16 purposeCode;
        uint64 validFrom;
        uint64 validUntil;
        uint16 policyMask;
    }
    struct ConsentRecord {
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
        bool active;
        uint16 policyMask;
        address dataSubject;
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

    address public immutable owner;

    mapping(bytes32 => ConsentRecord) public consents;
    mapping(bytes32 => DirectedConsentRecord) public directedConsents;
    mapping(bytes32 => mapping(uint32 => DirectedConsentRecord)) public patientConsents;
    mapping(bytes32 => mapping(uint32 => PatientConsentProjection)) public patientConsentProjections;
    mapping(bytes32 => PatientConsentProjection) public activePatientConsentProjections;
    mapping(bytes32 => uint32) public activePatientConsentVersion;
    mapping(bytes32 => bytes32) private consentHashByScope;
    mapping(address => bool) public authorizedWriters;
    mapping(address => bool) public patientConsentControllers;

    event ConsentRegistered(bytes32 indexed consentHash, bytes32 indexed patientHash, bytes32 indexed actorHash);
    event ConsentRevoked(bytes32 indexed consentHash, bytes32 indexed patientHash, address indexed revokedBy);
    event PatientConsentRegistered(
        bytes32 indexed consentIdHash,
        bytes32 indexed patientHash,
        uint32 indexed consentVersion,
        bytes32 policyIdHash,
        address registeredBy
    );
    event PatientConsentRevoked(
        bytes32 indexed consentIdHash,
        uint32 indexed consentVersion,
        bytes32 indexed patientHash,
        address revokedBy
    );
    event PatientConsentSuperseded(
        bytes32 indexed consentIdHash,
        uint32 indexed previousConsentVersion,
        uint32 indexed consentVersion,
        address supersededBy
    );
    event PatientConsentControllerChanged(address indexed controller, bool allowed, address changedBy);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyConsentSubjectOrWriter(address dataSubject) {
        require(msg.sender == dataSubject || authorizedWriters[msg.sender] || msg.sender == owner, "NOT_AUTHORIZED_WRITER");
        _;
    }

    function authorizeWriter(address writer, bool allowed) external {
        require(msg.sender == owner, "ONLY_OWNER");
        require(writer != address(0), "INVALID_WRITER");
        authorizedWriters[writer] = allowed;
    }

    function authorizePatientConsentController(address controller, bool allowed) external {
        require(msg.sender == owner, "ONLY_OWNER");
        require(controller != address(0), "INVALID_CONTROLLER");
        patientConsentControllers[controller] = allowed;
        emit PatientConsentControllerChanged(controller, allowed, msg.sender);
    }

    modifier onlyPatientConsentController() {
        require(patientConsentControllers[msg.sender], "PATIENT_CONSENT_CONTROLLER_ONLY");
        _;
    }

    function registerConsent(RegisterConsentInput calldata input) external {
        _registerConsent(input, msg.sender);
    }

    function registerConsentFor(RegisterConsentInput calldata input, address dataSubject) external {
        require(authorizedWriters[msg.sender] || msg.sender == owner, "NOT_AUTHORIZED_WRITER");
        require(dataSubject != address(0), "INVALID_DATA_SUBJECT");
        _registerConsent(input, dataSubject);
    }

    function registerDirectedConsentFor(RegisterDirectedConsentInput calldata input, address dataSubject) external {
        require(authorizedWriters[msg.sender] || msg.sender == owner, "NOT_AUTHORIZED_WRITER");
        require(dataSubject != address(0), "INVALID_DATA_SUBJECT");
        require(input.consentIdHash != bytes32(0), "INVALID_CONSENT_HASH");
        require(input.consentProjectionHash != bytes32(0), "INVALID_CONSENT_PROJECTION_HASH");
        require(input.patientHash != bytes32(0), "INVALID_PATIENT_HASH");
        require(input.granteeOrganizationHash != bytes32(0), "INVALID_ORGANIZATION_HASH");
        require(input.resourceIdHash != bytes32(0), "INVALID_RESOURCE_ID_HASH");
        require(input.validUntil > input.validFrom, "INVALID_CONSENT_PERIOD");
        require(input.policyMask != 0, "INVALID_POLICY_MASK");
        require(!directedConsents[input.consentIdHash].active, "CONSENT_ALREADY_ACTIVE");
        directedConsents[input.consentIdHash] = DirectedConsentRecord({
            consentIdHash: input.consentIdHash,
            consentProjectionHash: input.consentProjectionHash,
            patientHash: input.patientHash,
            granteeOrganizationHash: input.granteeOrganizationHash,
            actorConstraintHash: input.actorConstraintHash,
            resourceIdHash: input.resourceIdHash,
            resourceTypeCode: input.resourceTypeCode,
            actionCode: input.actionCode,
            purposeCode: input.purposeCode,
            validFrom: input.validFrom,
            validUntil: input.validUntil,
            active: true,
            policyMask: input.policyMask,
            dataSubject: dataSubject
        });
        activePatientConsentProjections[input.consentIdHash] = PatientConsentProjection({
            policyIdHash: bytes32(0),
            policyVersion: 0,
            consentVersion: 1,
            consentProjectionHash: input.consentProjectionHash,
            active: true,
            status: CONSENT_STATUS_ACTIVE
        });
    }

    function getDirectedConsent(bytes32 consentIdHash) external view returns (DirectedConsentRecord memory) {
        return directedConsents[consentIdHash];
    }

    function getPatientConsent(bytes32 consentIdHash, uint32 consentVersion)
        external
        view
        returns (DirectedConsentRecord memory)
    {
        return patientConsents[consentIdHash][consentVersion];
    }

    function getActivePatientConsentProjection(bytes32 consentIdHash)
        external
        view
        returns (PatientConsentProjection memory)
    {
        return activePatientConsentProjections[consentIdHash];
    }

    function registerPatientConsent(RegisterPatientConsentInput calldata) external pure {
        revert("PATIENT_CONSENT_CONTROLLER_ONLY");
    }

    function registerPatientConsentFor(
        RegisterPatientConsentInput calldata input,
        address dataSubject
    ) external onlyPatientConsentController {
        require(dataSubject != address(0), "INVALID_DATA_SUBJECT");
        _registerPatientConsent(input, dataSubject, msg.sender);
    }

    function supersedePatientConsent(
        RegisterPatientConsentInput calldata,
        uint32
    ) external pure {
        revert("PATIENT_CONSENT_CONTROLLER_ONLY");
    }

    function supersedePatientConsentFor(
        RegisterPatientConsentInput calldata input,
        uint32 previousConsentVersion,
        address dataSubject
    ) external onlyPatientConsentController {
        require(dataSubject != address(0), "INVALID_DATA_SUBJECT");
        _supersedePatientConsent(input, previousConsentVersion, dataSubject, msg.sender);
    }

    function revokePatientConsent(bytes32, uint32) external pure {
        revert("PATIENT_CONSENT_CONTROLLER_ONLY");
    }

    function revokePatientConsentFor(
        bytes32 consentIdHash,
        uint32 consentVersion,
        address revokedBy
    ) external onlyPatientConsentController {
        require(revokedBy != address(0), "INVALID_REVOKER");
        _revokePatientConsent(consentIdHash, consentVersion, revokedBy, msg.sender);
    }

    function _registerConsent(RegisterConsentInput calldata input, address dataSubject) private {
        require(input.consentHash != bytes32(0), "INVALID_CONSENT_HASH");
        require(input.patientHash != bytes32(0), "INVALID_PATIENT_HASH");
        require(input.actorHash != bytes32(0), "INVALID_ACTOR_HASH");
        require(input.organizationHash != bytes32(0), "INVALID_ORGANIZATION_HASH");
        require(input.resourceIdHash != bytes32(0), "INVALID_RESOURCE_ID_HASH");
        require(input.validUntil > input.validFrom, "INVALID_CONSENT_PERIOD");
        require(input.policyMask != 0, "INVALID_POLICY_MASK");

        bytes32 scope = _consentScope(input.patientHash, input.actorHash, input.organizationHash, input.resourceIdHash);
        bytes32 currentScopeConsentHash = consentHashByScope[scope];
        require(!consents[input.consentHash].active, "CONSENT_ALREADY_ACTIVE");
        require(currentScopeConsentHash == bytes32(0) || !consents[currentScopeConsentHash].active, "CONSENT_SCOPE_ALREADY_ACTIVE");

        consents[input.consentHash] = ConsentRecord({
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
            active: true,
            policyMask: input.policyMask,
            dataSubject: dataSubject
        });
        consentHashByScope[scope] = input.consentHash;

        emit ConsentRegistered(input.consentHash, input.patientHash, input.actorHash);
    }

    function _registerPatientConsent(
        RegisterPatientConsentInput calldata input,
        address dataSubject,
        address registeredBy
    ) private {
        require(input.consentIdHash != bytes32(0), "INVALID_CONSENT_HASH");
        require(input.consentProjectionHash != bytes32(0), "INVALID_CONSENT_PROJECTION_HASH");
        require(input.patientHash != bytes32(0), "INVALID_PATIENT_HASH");
        require(input.granteeOrganizationHash != bytes32(0), "INVALID_ORGANIZATION_HASH");
        require(input.resourceIdHash != bytes32(0), "INVALID_RESOURCE_ID_HASH");
        require(input.policyIdHash != bytes32(0), "INVALID_POLICY_ID_HASH");
        require(input.policyVersion != 0, "INVALID_POLICY_VERSION");
        require(input.consentVersion != 0, "INVALID_CONSENT_VERSION");
        require(input.validUntil > input.validFrom, "INVALID_CONSENT_PERIOD");
        require(input.policyMask != 0, "INVALID_POLICY_MASK");
        require(
            patientConsents[input.consentIdHash][input.consentVersion].consentIdHash == bytes32(0),
            "CONSENT_VERSION_ALREADY_EXISTS"
        );
        require(activePatientConsentVersion[input.consentIdHash] == 0, "CONSENT_ALREADY_ACTIVE");

        _writePatientConsent(patientConsents[input.consentIdHash][input.consentVersion], input, dataSubject);
        _writePatientConsent(directedConsents[input.consentIdHash], input, dataSubject);
        _writePatientConsentProjection(patientConsentProjections[input.consentIdHash][input.consentVersion], input);
        _writePatientConsentProjection(activePatientConsentProjections[input.consentIdHash], input);
        activePatientConsentVersion[input.consentIdHash] = input.consentVersion;

        emit PatientConsentRegistered(
            input.consentIdHash,
            input.patientHash,
            input.consentVersion,
            input.policyIdHash,
            registeredBy
        );
    }

    function _supersedePatientConsent(
        RegisterPatientConsentInput calldata input,
        uint32 previousConsentVersion,
        address dataSubject,
        address supersededBy
    ) private {
        DirectedConsentRecord storage previous = patientConsents[input.consentIdHash][previousConsentVersion];
        require(previous.consentIdHash != bytes32(0), "CONSENT_NOT_FOUND");
        require(
            previous.active && activePatientConsentVersion[input.consentIdHash] == previousConsentVersion,
            "CONSENT_NOT_ACTIVE"
        );
        require(previous.dataSubject == dataSubject, "NOT_CONSENT_SUBJECT");
        require(input.consentVersion == previousConsentVersion + 1, "INVALID_CONSENT_VERSION");
        require(
            patientConsents[input.consentIdHash][input.consentVersion].consentIdHash == bytes32(0),
            "CONSENT_VERSION_ALREADY_EXISTS"
        );

        previous.active = false;
        patientConsentProjections[input.consentIdHash][previousConsentVersion].active = false;
        patientConsentProjections[input.consentIdHash][previousConsentVersion].status = CONSENT_STATUS_SUPERSEDED;
        _writePatientConsent(patientConsents[input.consentIdHash][input.consentVersion], input, dataSubject);
        _writePatientConsent(directedConsents[input.consentIdHash], input, dataSubject);
        _writePatientConsentProjection(patientConsentProjections[input.consentIdHash][input.consentVersion], input);
        _writePatientConsentProjection(activePatientConsentProjections[input.consentIdHash], input);
        activePatientConsentVersion[input.consentIdHash] = input.consentVersion;

        emit PatientConsentSuperseded(
            input.consentIdHash,
            previousConsentVersion,
            input.consentVersion,
            supersededBy
        );
        emit PatientConsentRegistered(
            input.consentIdHash,
            input.patientHash,
            input.consentVersion,
            input.policyIdHash,
            supersededBy
        );
    }

    function _revokePatientConsent(
        bytes32 consentIdHash,
        uint32 consentVersion,
        address revokedBy,
        address caller
    ) private {
        DirectedConsentRecord storage consent = patientConsents[consentIdHash][consentVersion];
        require(consent.consentIdHash != bytes32(0), "CONSENT_NOT_FOUND");
        require(consent.active, "CONSENT_NOT_ACTIVE");
        require(
            consent.dataSubject == revokedBy || authorizedWriters[caller] || caller == owner,
            "NOT_AUTHORIZED_WRITER"
        );

        consent.active = false;
        patientConsentProjections[consentIdHash][consentVersion].active = false;
        patientConsentProjections[consentIdHash][consentVersion].status = CONSENT_STATUS_REVOKED;
        if (activePatientConsentVersion[consentIdHash] == consentVersion) {
            activePatientConsentVersion[consentIdHash] = 0;
            directedConsents[consentIdHash].active = false;
            activePatientConsentProjections[consentIdHash].active = false;
            activePatientConsentProjections[consentIdHash].status = CONSENT_STATUS_REVOKED;
        }
        emit PatientConsentRevoked(consentIdHash, consentVersion, consent.patientHash, revokedBy);
    }

    function _writePatientConsent(
        DirectedConsentRecord storage record,
        RegisterPatientConsentInput calldata input,
        address dataSubject
    ) private {
        record.consentIdHash = input.consentIdHash;
        record.consentProjectionHash = input.consentProjectionHash;
        record.patientHash = input.patientHash;
        record.granteeOrganizationHash = input.granteeOrganizationHash;
        record.actorConstraintHash = input.actorConstraintHash;
        record.resourceIdHash = input.resourceIdHash;
        record.resourceTypeCode = input.resourceTypeCode;
        record.actionCode = input.actionCode;
        record.purposeCode = input.purposeCode;
        record.validFrom = input.validFrom;
        record.validUntil = input.validUntil;
        record.active = true;
        record.policyMask = input.policyMask;
        record.dataSubject = dataSubject;
    }

    function _writePatientConsentProjection(
        PatientConsentProjection storage projection,
        RegisterPatientConsentInput calldata input
    ) private {
        projection.policyIdHash = input.policyIdHash;
        projection.policyVersion = input.policyVersion;
        projection.consentVersion = input.consentVersion;
        projection.consentProjectionHash = input.consentProjectionHash;
        projection.active = true;
        projection.status = CONSENT_STATUS_ACTIVE;
    }

    function revokeConsent(bytes32 consentHash) external onlyConsentSubjectOrWriter(consents[consentHash].dataSubject) {
        ConsentRecord storage consent = consents[consentHash];
        require(consent.consentHash != bytes32(0), "CONSENT_NOT_FOUND");

        consent.active = false;

        emit ConsentRevoked(consentHash, consent.patientHash, msg.sender);
    }

    function getConsent(bytes32 consentHash) external view returns (ConsentRecord memory) {
        return consents[consentHash];
    }

    function findConsentHash(
        bytes32 patientHash,
        bytes32 actorHash,
        bytes32 organizationHash,
        bytes32 resourceIdHash
    ) external view returns (bytes32) {
        return consentHashByScope[_consentScope(patientHash, actorHash, organizationHash, resourceIdHash)];
    }

    function isConsentValid(
        bytes32 patientHash,
        bytes32 actorHash,
        bytes32 organizationHash,
        bytes32 resourceIdHash,
        uint16 resourceTypeCode,
        uint16 actionCode,
        uint16 purposeCode,
        uint64 requestTime
    ) external view returns (bool) {
        bytes32 consentHash = consentHashByScope[_consentScope(patientHash, actorHash, organizationHash, resourceIdHash)];
        ConsentRecord memory consent = consents[consentHash];

        if (consent.consentHash == bytes32(0) || !consent.active) {
            return false;
        }

        if (requestTime < consent.validFrom || requestTime > consent.validUntil) {
            return false;
        }

        return consent.resourceTypeCode == resourceTypeCode
            && consent.actionCode == actionCode
            && consent.purposeCode == purposeCode;
    }

    function _consentScope(
        bytes32 patientHash,
        bytes32 actorHash,
        bytes32 organizationHash,
        bytes32 resourceIdHash
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(patientHash, actorHash, organizationHash, resourceIdHash));
    }
}
