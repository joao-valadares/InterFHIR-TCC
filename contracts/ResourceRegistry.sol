// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ResourceRegistry {
    uint8 public constant MANIFEST_STATUS_ACTIVE = 1;
    uint8 public constant MANIFEST_STATUS_SUPERSEDED = 2;
    uint8 public constant MANIFEST_STATUS_REVOKED = 3;

    struct ResourceRecord {
        uint16 resourceTypeCode;
        bytes32 resourceHash;
        bool active;
    }

    struct ManifestRecord {
        bytes32 commitment;
        uint8 status;
        bool exists;
    }

    address public immutable owner;
    address public registryOwner;

    mapping(bytes32 => ResourceRecord) public resources;
    mapping(bytes32 => mapping(uint64 => ManifestRecord)) public manifests;
    mapping(bytes32 => uint64) public latestManifestVersion;

    event ResourceHashRegistered(
        bytes32 indexed resourceIdHash,
        uint16 indexed resourceTypeCode,
        bytes32 indexed resourceHash,
        address registeredBy
    );

    event ManifestVersionAnchored(
        bytes32 indexed manifestIdHash,
        uint64 indexed version,
        bytes32 indexed commitment,
        uint8 status,
        address registeredBy
    );

    event ManifestStatusChanged(
        bytes32 indexed manifestIdHash,
        uint64 indexed version,
        bytes32 previousCommitment,
        bytes32 indexed commitment,
        uint8 status,
        address changedBy
    );

    modifier onlyOwner() {
        require(msg.sender == registryOwner, "ONLY_OWNER");
        _;
    }

    constructor() {
        owner = msg.sender;
        registryOwner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "INVALID_OWNER");
        registryOwner = newOwner;
    }

    function registerResourceHash(bytes32 resourceIdHash, uint16 resourceTypeCode, bytes32 resourceHash) external onlyOwner {
        require(resourceIdHash != bytes32(0), "INVALID_RESOURCE_ID_HASH");
        require(resourceHash != bytes32(0), "INVALID_RESOURCE_HASH");

        resources[resourceIdHash] =
            ResourceRecord({resourceTypeCode: resourceTypeCode, resourceHash: resourceHash, active: true});

        emit ResourceHashRegistered(resourceIdHash, resourceTypeCode, resourceHash, msg.sender);
    }

    function isResourceHashValid(
        bytes32 resourceIdHash,
        uint16 resourceTypeCode,
        bytes32 resourceHash
    ) external view returns (bool) {
        ResourceRecord memory record = resources[resourceIdHash];

        return record.active && record.resourceTypeCode == resourceTypeCode && record.resourceHash == resourceHash;
    }

    function anchorManifestVersion(
        bytes32 manifestIdHash,
        uint64 version,
        bytes32 commitment,
        bytes32 previousVersionCommitment
    ) external onlyOwner {
        require(manifestIdHash != bytes32(0), "INVALID_MANIFEST_ID_HASH");
        require(commitment != bytes32(0), "INVALID_MANIFEST_COMMITMENT");
        require(version == 1 && latestManifestVersion[manifestIdHash] == 0, "INVALID_MANIFEST_VERSION");
        require(previousVersionCommitment == bytes32(0), "INVALID_PREVIOUS_COMMITMENT");

        manifests[manifestIdHash][version] =
            ManifestRecord({commitment: commitment, status: MANIFEST_STATUS_ACTIVE, exists: true});
        latestManifestVersion[manifestIdHash] = version;

        emit ManifestVersionAnchored(
            manifestIdHash,
            version,
            commitment,
            MANIFEST_STATUS_ACTIVE,
            msg.sender
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
        require(manifestIdHash != bytes32(0), "INVALID_MANIFEST_ID_HASH");
        require(supersededCommitment != bytes32(0), "INVALID_MANIFEST_COMMITMENT");
        require(nextCommitment != bytes32(0), "INVALID_MANIFEST_COMMITMENT");
        require(currentVersion == latestManifestVersion[manifestIdHash], "INVALID_MANIFEST_VERSION");
        require(nextVersion == currentVersion + 1, "INVALID_MANIFEST_VERSION");

        ManifestRecord storage current = manifests[manifestIdHash][currentVersion];
        require(current.exists && current.status == MANIFEST_STATUS_ACTIVE, "MANIFEST_NOT_ACTIVE");
        require(current.commitment == expectedCurrentCommitment, "MANIFEST_COMMITMENT_MISMATCH");

        bytes32 previousCommitment = current.commitment;
        current.commitment = supersededCommitment;
        current.status = MANIFEST_STATUS_SUPERSEDED;

        manifests[manifestIdHash][nextVersion] =
            ManifestRecord({commitment: nextCommitment, status: MANIFEST_STATUS_ACTIVE, exists: true});
        latestManifestVersion[manifestIdHash] = nextVersion;

        emit ManifestStatusChanged(
            manifestIdHash,
            currentVersion,
            previousCommitment,
            supersededCommitment,
            MANIFEST_STATUS_SUPERSEDED,
            msg.sender
        );
        emit ManifestVersionAnchored(
            manifestIdHash,
            nextVersion,
            nextCommitment,
            MANIFEST_STATUS_ACTIVE,
            msg.sender
        );
    }

    function revokeManifestVersion(
        bytes32 manifestIdHash,
        uint64 version,
        bytes32 expectedCurrentCommitment,
        bytes32 revokedCommitment
    ) external onlyOwner {
        require(manifestIdHash != bytes32(0), "INVALID_MANIFEST_ID_HASH");
        require(revokedCommitment != bytes32(0), "INVALID_MANIFEST_COMMITMENT");
        require(version == latestManifestVersion[manifestIdHash], "INVALID_MANIFEST_VERSION");

        ManifestRecord storage current = manifests[manifestIdHash][version];
        require(current.exists && current.status == MANIFEST_STATUS_ACTIVE, "MANIFEST_NOT_ACTIVE");
        require(current.commitment == expectedCurrentCommitment, "MANIFEST_COMMITMENT_MISMATCH");

        bytes32 previousCommitment = current.commitment;
        current.commitment = revokedCommitment;
        current.status = MANIFEST_STATUS_REVOKED;

        emit ManifestStatusChanged(
            manifestIdHash,
            version,
            previousCommitment,
            revokedCommitment,
            MANIFEST_STATUS_REVOKED,
            msg.sender
        );
    }
}
