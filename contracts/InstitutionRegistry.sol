// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract InstitutionRegistry {
    struct Institution {
        address gatewayAccount;
        bytes32 metadataCommitment;
        bool active;
    }

    address public immutable owner;
    mapping(bytes32 => Institution) private institutions;

    event InstitutionRegistered(
        bytes32 indexed organizationHash,
        address indexed gatewayAccount,
        bytes32 indexed metadataCommitment,
        address registeredBy
    );
    event InstitutionActiveChanged(bytes32 indexed organizationHash, bool active, address changedBy);
    event InstitutionGatewayChanged(
        bytes32 indexed organizationHash,
        address indexed previousGateway,
        address indexed gatewayAccount,
        address changedBy
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerInstitution(
        bytes32 organizationHash,
        address gatewayAccount,
        bytes32 metadataCommitment
    ) external onlyOwner {
        require(organizationHash != bytes32(0), "INVALID_ORGANIZATION_HASH");
        require(gatewayAccount != address(0), "INVALID_GATEWAY_ACCOUNT");
        require(metadataCommitment != bytes32(0), "INVALID_METADATA_COMMITMENT");
        institutions[organizationHash] = Institution({
            gatewayAccount: gatewayAccount,
            metadataCommitment: metadataCommitment,
            active: true
        });
        emit InstitutionRegistered(organizationHash, gatewayAccount, metadataCommitment, msg.sender);
    }

    function setInstitutionActive(bytes32 organizationHash, bool active) external onlyOwner {
        require(institutions[organizationHash].gatewayAccount != address(0), "INSTITUTION_NOT_FOUND");
        institutions[organizationHash].active = active;
        emit InstitutionActiveChanged(organizationHash, active, msg.sender);
    }

    function setInstitutionGateway(bytes32 organizationHash, address gatewayAccount) external onlyOwner {
        require(gatewayAccount != address(0), "INVALID_GATEWAY_ACCOUNT");
        Institution storage institution = institutions[organizationHash];
        require(institution.gatewayAccount != address(0), "INSTITUTION_NOT_FOUND");
        address previousGateway = institution.gatewayAccount;
        institution.gatewayAccount = gatewayAccount;
        emit InstitutionGatewayChanged(organizationHash, previousGateway, gatewayAccount, msg.sender);
    }

    function isGatewayAuthorized(bytes32 organizationHash, address gatewayAccount) external view returns (bool) {
        Institution memory institution = institutions[organizationHash];
        return institution.active && institution.gatewayAccount == gatewayAccount;
    }

    function getInstitution(bytes32 organizationHash) external view returns (Institution memory) {
        return institutions[organizationHash];
    }
}
