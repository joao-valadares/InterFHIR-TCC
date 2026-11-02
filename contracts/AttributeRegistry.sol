// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AttributeRegistry {
    struct Organization {
        address account;
        bool active;
    }

    struct Practitioner {
        address account;
        bytes32 organizationHash;
        uint16 roleCode;
        uint16 specialtyCode;
        bool licenseActive;
        bool active;
    }

    address public immutable owner;
    address public registryOwner;

    mapping(bytes32 => Organization) public organizations;
    mapping(bytes32 => Practitioner) public practitioners;
    mapping(address => bytes32) public practitionerHashByAccount;

    event OrganizationRegistered(address indexed account, bytes32 indexed organizationHash, address indexed registeredBy);
    event PractitionerRegistered(
        address indexed account,
        bytes32 indexed practitionerHash,
        bytes32 indexed organizationHash,
        bool licenseActive,
        address registeredBy
    );
    event OrganizationActiveChanged(bytes32 indexed organizationHash, bool active, address indexed changedBy);
    event PractitionerActiveChanged(bytes32 indexed practitionerHash, bool active, address indexed changedBy);
    event PractitionerLicenseChanged(bytes32 indexed practitionerHash, bool active, address indexed changedBy);

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

    function registerOrganization(address account, bytes32 organizationHash) external onlyOwner {
        require(account != address(0), "INVALID_ORGANIZATION_ACCOUNT");
        require(organizationHash != bytes32(0), "INVALID_ORGANIZATION_HASH");

        organizations[organizationHash] = Organization({account: account, active: true});

        emit OrganizationRegistered(account, organizationHash, msg.sender);
    }

    function registerPractitioner(
        address account,
        bytes32 practitionerHash,
        bytes32 organizationHash,
        uint16 roleCode,
        uint16 specialtyCode,
        bool licenseActive
    ) external onlyOwner {
        require(account != address(0), "INVALID_PRACTITIONER_ACCOUNT");
        require(practitionerHash != bytes32(0), "INVALID_PRACTITIONER_HASH");
        require(organizations[organizationHash].active, "ORGANIZATION_NOT_ACTIVE");

        practitioners[practitionerHash] = Practitioner({
            account: account,
            organizationHash: organizationHash,
            roleCode: roleCode,
            specialtyCode: specialtyCode,
            licenseActive: licenseActive,
            active: true
        });
        practitionerHashByAccount[account] = practitionerHash;

        emit PractitionerRegistered(account, practitionerHash, organizationHash, licenseActive, msg.sender);
    }

    function setOrganizationActive(bytes32 organizationHash, bool active) external onlyOwner {
        require(organizations[organizationHash].account != address(0), "ORGANIZATION_NOT_FOUND");
        organizations[organizationHash].active = active;
        emit OrganizationActiveChanged(organizationHash, active, msg.sender);
    }

    function setPractitionerActive(bytes32 practitionerHash, bool active) external onlyOwner {
        require(practitioners[practitionerHash].account != address(0), "PRACTITIONER_NOT_FOUND");
        practitioners[practitionerHash].active = active;
        emit PractitionerActiveChanged(practitionerHash, active, msg.sender);
    }

    function setPractitionerLicenseActive(bytes32 practitionerHash, bool active) external onlyOwner {
        require(practitioners[practitionerHash].account != address(0), "PRACTITIONER_NOT_FOUND");
        practitioners[practitionerHash].licenseActive = active;
        emit PractitionerLicenseChanged(practitionerHash, active, msg.sender);
    }

    function getOrganization(bytes32 organizationHash) external view returns (Organization memory) {
        return organizations[organizationHash];
    }

    function getPractitioner(bytes32 practitionerHash) external view returns (Practitioner memory) {
        return practitioners[practitionerHash];
    }
}
