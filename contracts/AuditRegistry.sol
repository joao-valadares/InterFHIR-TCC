// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuditRegistry {
    struct AccessDecision {
        address requester;
        bytes32 patientHash;
        bytes32 actorHash;
        bytes32 resourceIdHash;
        bytes32 resourceHash;
        bytes32 policyId;
        bool granted;
        uint8 reasonCode;
        uint256 timestamp;
    }

    struct ConsentRevocation {
        bytes32 consentHash;
        bytes32 patientHash;
        address revokedBy;
        uint8 reasonCode;
        uint256 timestamp;
    }

    uint256 public nextDecisionId = 1;
    uint256 public nextRevocationId = 1;
    address public immutable owner;

    mapping(uint256 => AccessDecision) public decisions;
    mapping(uint256 => ConsentRevocation) public revocations;
    mapping(address => bool) public authorizedWriters;

    event AccessDecisionRecorded(
        uint256 indexed decisionId,
        address indexed requester,
        bytes32 indexed patientHash,
        bytes32 actorHash,
        bytes32 resourceIdHash,
        bytes32 resourceHash,
        bytes32 policyId,
        bool granted,
        uint8 reasonCode
    );
    event ConsentRevocationRecorded(
        uint256 indexed revocationId,
        bytes32 indexed consentHash,
        bytes32 indexed patientHash,
        address revokedBy,
        uint8 reasonCode
    );

    constructor() {
        owner = msg.sender;
        authorizedWriters[msg.sender] = true;
    }

    function authorizeWriter(address writer, bool allowed) external {
        require(msg.sender == owner, "ONLY_OWNER");
        require(writer != address(0), "INVALID_WRITER");
        authorizedWriters[writer] = allowed;
    }

    function recordDecision(
        address requester,
        bytes32 patientHash,
        bytes32 actorHash,
        bytes32 resourceIdHash,
        bytes32 resourceHash,
        bytes32 policyId,
        bool granted,
        uint8 reasonCode
    ) external returns (uint256 decisionId) {
        require(authorizedWriters[msg.sender], "NOT_AUTHORIZED_WRITER");
        require(requester != address(0), "INVALID_REQUESTER");

        decisionId = nextDecisionId;
        nextDecisionId += 1;

        decisions[decisionId] = AccessDecision({
            requester: requester,
            patientHash: patientHash,
            actorHash: actorHash,
            resourceIdHash: resourceIdHash,
            resourceHash: resourceHash,
            policyId: policyId,
            granted: granted,
            reasonCode: reasonCode,
            timestamp: block.timestamp
        });

        emit AccessDecisionRecorded(
            decisionId,
            requester,
            patientHash,
            actorHash,
            resourceIdHash,
            resourceHash,
            policyId,
            granted,
            reasonCode
        );
    }

    function recordConsentRevocation(
        bytes32 consentHash,
        bytes32 patientHash,
        address revokedBy,
        uint8 reasonCode
    ) external returns (uint256 revocationId) {
        require(authorizedWriters[msg.sender], "NOT_AUTHORIZED_WRITER");
        require(consentHash != bytes32(0), "INVALID_CONSENT_HASH");
        require(revokedBy != address(0), "INVALID_REVOKER");

        revocationId = nextRevocationId;
        nextRevocationId += 1;

        revocations[revocationId] = ConsentRevocation({
            consentHash: consentHash,
            patientHash: patientHash,
            revokedBy: revokedBy,
            reasonCode: reasonCode,
            timestamp: block.timestamp
        });

        emit ConsentRevocationRecorded(revocationId, consentHash, patientHash, revokedBy, reasonCode);
    }
}
