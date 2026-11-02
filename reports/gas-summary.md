# Health Access Control Gas Metrics

Generated from `hardhat test --gas-stats-json reports/gas-stats.json`.

| Contract | Operation | Min | Avg | Median | Max | Count | Runtime size |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AttributeRegistry | deploy | 808849 | 808849 | 808849 | 808849 | 28 | 3395 |
| AttributeRegistry | setOrganizationActive | 31348 | 31348 | 31348 | 31348 | 1 |  |
| AttributeRegistry | setPractitionerActive | 33368 | 33368 | 33368 | 33368 | 1 |  |
| AttributeRegistry | setPractitionerLicenseActive | 33434 | 33434 | 33434 | 33434 | 1 |  |
| AuditRegistry | deploy | 633117 | 633117 | 633117 | 633117 | 28 | 2374 |
| AuditRegistry | recordDecision | 213692 | 213692 | 213692 | 213692 | 1 |  |
| ConsentRegistry | deploy | 2885834 | 2885834 | 2885834 | 2885834 | 32 | 13111 |
| ConsentRegistry | authorizePatientConsentController | 45991 | 45999 | 46003 | 46003 | 26 |  |
| ConsentRegistry | registerConsent | 194018 | 205944 | 208925 | 208925 | 5 |  |
| ConsentRegistry | registerConsentFor | 211596 | 211596 | 211596 | 211596 | 1 |  |
| ConsentRegistry | registerPatientConsentFor | 553387 | 553387 | 553387 | 553387 | 1 |  |
| ConsentRegistry | revokeConsent | 35331 | 35331 | 35331 | 35331 | 3 |  |
| ConsentRegistry | revokePatientConsentFor | 54627 | 54627 | 54627 | 54627 | 1 |  |
| ConsentRegistry | supersedePatientConsentFor | 342418 | 342418 | 342418 | 342418 | 1 |  |
| HealthAccessControl | deploy | 5332558 | 5332578 | 5332582 | 5332582 | 24 | 22431 |
| HealthAccessControl | createPolicyVersion | 128176 | 162509 | 165176 | 165176 | 14 |  |
| HealthAccessControl | deactivatePolicy | 31562 | 31562 | 31562 | 31562 | 2 |  |
| HealthAccessControl | finalizeEnforcement | 47755 | 47755 | 47755 | 47755 | 1 |  |
| HealthAccessControl | registerConsent | 218210 | 218210 | 218210 | 218210 | 3 |  |
| HealthAccessControl | registerPatientConsent | 568542 | 572557 | 568542 | 608690 | 10 |  |
| HealthAccessControl | registerResourceHash | 96846 | 96857 | 96858 | 96858 | 13 |  |
| HealthAccessControl | requestAccess | 255183 | 255183 | 255183 | 255183 | 1 |  |
| HealthAccessControl | requestInstitutionalAccess | 90692 | 316722 | 426361 | 426361 | 12 |  |
| HealthAccessControl | revokePatientConsent | 172309 | 172309 | 172309 | 172309 | 1 |  |
| HealthAccessControl | setInstitutionActive | 29666 | 29666 | 29666 | 29666 | 1 |  |
| HealthAccessControl | setOrganizationActive | 34677 | 34677 | 34677 | 34677 | 1 |  |
| HealthAccessControl | setPractitionerActive | 36698 | 36698 | 36698 | 36698 | 1 |  |
| HealthAccessControl | setPractitionerLicenseActive | 36754 | 36754 | 36754 | 36754 | 1 |  |
| HealthAccessControl | verifyAccess | 29810 | 29810 | 29810 | 29810 | 2 |  |
| HealthAccessControl | verifyInstitutionalAccess | 54134 | 91050 | 80249 | 130366 | 8 |  |
| InstitutionRegistry | deploy | 454537 | 454537 | 454537 | 454537 | 4 | 1860 |
| InstitutionRegistry | setInstitutionActive | 26270 | 26270 | 26270 | 26270 | 1 |  |
| ResourceRegistry | deploy | 869770 | 869770 | 869770 | 869770 | 29 | 3675 |
| ResourceRegistry | registerResourceHash | 93497 | 93497 | 93497 | 93497 | 1 |  |

## TCC Reading Notes

- `registerConsent` and `revokeConsent` represent patient sovereignty operations.
- `requestAccess` and `verifyAccess` remain explicit disabled compatibility ABIs; canonical reads use versioned institutional authorization.
- `runtime size` helps compare deploy/storage footprint across contract architecture changes.
- Keep sensitive FHIR payloads off-chain; gas should grow with metadata, not clinical record size.
