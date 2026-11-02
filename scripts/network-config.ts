export interface PublicNetworkConfiguration {
  schemaVersion: number;
  chainId: number;
  validators: Array<{ name: string; address: string }>;
  wallets: Array<{ name: string; address: string; reference?: string }>;
  institutions: Record<string, {
    organizationReference: string;
    practitionerReference: string;
    walletAddresses: Record<string, string>;
  }>;
}

export const INSTITUTION_NAMES = ["hospital-a", "clinic-b"] as const;

export function readPatientAnaAddress(network: PublicNetworkConfiguration): string {
  const patient = network.wallets.find((wallet) => wallet.name === "patient");
  if (!patient || patient.reference !== "Patient/pat-ana") {
    throw new Error("NETWORK_PATIENT_ANA_INVALID");
  }
  for (const institution of INSTITUTION_NAMES) {
    if (network.institutions[institution].walletAddresses.patient.toLowerCase() !== patient.address.toLowerCase()) {
      throw new Error(`NETWORK_PATIENT_ANA_MISMATCH:${institution}`);
    }
  }
  return patient.address;
}
