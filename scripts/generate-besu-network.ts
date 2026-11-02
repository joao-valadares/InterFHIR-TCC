import { runtimeEnvironment } from "./runtime-environment.js";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { SigningKey, computeAddress } from "ethers";

const root = path.resolve(process.cwd(), ".local", "besu");
const networkFile = path.join(root, "network.json");
const validatorNames = ["hospital-a", "clinic-b", "auditor", "consortium"] as const;
const walletNames = ["deployer", "patient", "practitioner", "organization", "pep"] as const;
const validatorIps: Record<(typeof validatorNames)[number], string> = {
  "hospital-a": `${runtimeEnvironment().subnet.split(".").slice(0,3).join(".")}.10`,
  "clinic-b": `${runtimeEnvironment().subnet.split(".").slice(0,3).join(".")}.11`,
  auditor: `${runtimeEnvironment().subnet.split(".").slice(0,3).join(".")}.12`,
  consortium: `${runtimeEnvironment().subnet.split(".").slice(0,3).join(".")}.13`
};

type WalletName = (typeof walletNames)[number];
type KeyedWallet = { name: string; privateKey: string; address: string };

const institutionRoles = {
  "hospital-a": {
    organizationReference: "Organization/hospital-a",
    practitionerReference: "Practitioner/ana"
  },
  "clinic-b": {
    organizationReference: "Organization/clinic-b",
    practitionerReference: "Practitioner/bruno"
  }
} as const;

await main();

async function main(): Promise<void> {
  await mkdir(root, { recursive: true });
  const existed = existsSync(networkFile);
  const validators = await ensureValidators();
  const rootWallets = await ensureRootWallets();
  const institutionWallets = await ensureInstitutionWallets(rootWallets);
  const allWallets = uniqueWallets([...rootWallets, ...Object.values(institutionWallets).flat()]);

  await writeFile(
    path.join(root, "genesis.json"),
    `${JSON.stringify(buildGenesis(validators.map((node) => node.address), allWallets.map((wallet) => wallet.address)), null, 2)}\n`,
    "utf8"
  );
  await writeNodeConfigs(validators);

  const publicNetwork = {
    schemaVersion: 2,
    chainId: 1337,
    validators: validators.map(({ name, address }) => ({ name, address })),
    wallets: rootWallets.map(({ name, address }) => ({
      name,
      address,
      ...(name === "patient" ? { reference: "Patient/pat-ana" } : {})
    })),
    institutions: Object.fromEntries(
      Object.entries(institutionWallets).map(([name, wallets]) => [
        name,
        {
          ...institutionRoles[name as keyof typeof institutionRoles],
          walletAddresses: Object.fromEntries(wallets.map(({ name: role, address }) => [role, address]))
        }
      ])
    )
  };
  await writeFile(networkFile, `${JSON.stringify(publicNetwork, null, 2)}\n`, "utf8");

  console.log(JSON.stringify({
    status: existed ? "refreshed" : "generated",
    root,
    chainId: publicNetwork.chainId,
    validators: publicNetwork.validators,
    wallets: publicNetwork.wallets,
    institutions: Object.fromEntries(
      Object.entries(publicNetwork.institutions).map(([name, entry]) => [name, entry.walletAddresses])
    )
  }, null, 2));
}

async function ensureValidators(): Promise<Array<{ name: (typeof validatorNames)[number]; publicKey: string; address: string }>> {
  const validators: Array<{ name: (typeof validatorNames)[number]; publicKey: string; address: string }> = [];
  for (const name of validatorNames) {
    const directory = path.join(root, "validators", name);
    await mkdir(directory, { recursive: true });
    const storedKey = await ensureKey(path.join(directory, "key"), false);
    const privateKey = storedKey.startsWith("0x") ? storedKey : `0x${storedKey}`;
    const publicKey = SigningKey.computePublicKey(privateKey, false).slice(4);
    const publicKeyPath = path.join(directory, "key.pub");
    if (existsSync(publicKeyPath) && (await readFile(publicKeyPath, "utf8")).trim() !== publicKey) {
      throw new Error(`BESU_VALIDATOR_PUBLIC_KEY_MISMATCH:${name}`);
    }
    await writeFile(publicKeyPath, `${publicKey}\n`, "utf8");
    validators.push({ name, publicKey, address: computeAddress(privateKey) });
  }
  return validators;
}

async function ensureRootWallets(): Promise<KeyedWallet[]> {
  const directory = path.join(root, "wallets");
  await mkdir(directory, { recursive: true });
  const wallets: KeyedWallet[] = [];
  for (const name of walletNames) {
    const privateKey = await ensureKey(path.join(directory, `${name}.key`), true);
    wallets.push({ name, privateKey, address: computeAddress(privateKey) });
  }
  return wallets;
}

async function ensureInstitutionWallets(rootWallets: KeyedWallet[]): Promise<Record<keyof typeof institutionRoles, KeyedWallet[]>> {
  const rootByName = new Map(rootWallets.map((wallet) => [wallet.name, wallet]));
  const result = {} as Record<keyof typeof institutionRoles, KeyedWallet[]>;
  for (const name of Object.keys(institutionRoles) as Array<keyof typeof institutionRoles>) {
    const directory = path.join(root, "institutions", name);
    await mkdir(directory, { recursive: true });
    const wallets: KeyedWallet[] = [];
    for (const role of walletNames) {
      const rootWallet = rootByName.get(role);
      if (!rootWallet) throw new Error(`BESU_ROOT_WALLET_MISSING:${role}`);
      const privateKey = name === "hospital-a" && ["deployer", "patient", "practitioner", "organization", "pep"].includes(role)
        ? rootWallet.privateKey
        : role === "deployer" || role === "patient"
          ? rootWallet.privateKey
          : await ensureKey(path.join(directory, `${role}.key`), true);
      await ensureKeyValue(path.join(directory, `${role}.key`), privateKey);
      wallets.push({ name: role, privateKey, address: computeAddress(privateKey) });
    }
    result[name] = wallets;
  }
  return result;
}

async function ensureKey(filePath: string, withPrefix: boolean): Promise<string> {
  if (existsSync(filePath)) {
    const stored = (await readFile(filePath, "utf8")).trim();
    validatePrivateKey(stored, filePath, withPrefix);
    return withPrefix ? stored : stored.replace(/^0x/, "");
  }
  const generated = newPrivateKey();
  const value = withPrefix ? generated : generated.slice(2);
  await writeFile(filePath, `${value}\n`, { encoding: "utf8", flag: "wx" });
  return withPrefix ? generated : generated.slice(2);
}

async function ensureKeyValue(filePath: string, privateKey: string): Promise<void> {
  if (existsSync(filePath)) {
    const stored = (await readFile(filePath, "utf8")).trim();
    validatePrivateKey(stored, filePath, true);
    if (stored.toLowerCase() !== privateKey.toLowerCase()) throw new Error(`BESU_INSTITUTION_KEY_MISMATCH:${filePath}`);
    return;
  }
  await writeFile(filePath, `${privateKey}\n`, { encoding: "utf8", flag: "wx" });
}

function validatePrivateKey(value: string, filePath: string, withPrefix: boolean): void {
  const expression = withPrefix ? /^0x[0-9a-fA-F]{64}$/ : /^[0-9a-fA-F]{64}$/;
  if (!expression.test(value)) throw new Error(`BESU_PRIVATE_KEY_INVALID:${filePath}`);
}

function newPrivateKey(): string {
  return `0x${randomBytes(32).toString("hex")}`;
}

function uniqueWallets(wallets: KeyedWallet[]): KeyedWallet[] {
  const seen = new Set<string>();
  return wallets.filter((wallet) => {
    if (seen.has(wallet.address.toLowerCase())) return false;
    seen.add(wallet.address.toLowerCase());
    return true;
  });
}

function qbftExtraData(addresses: string[]): string {
  const vanity = rlpBytes("00".repeat(32));
  const validators = rlpList(addresses.map((address) => rlpBytes(address.slice(2))));
  return `0x${rlpList([vanity, validators, "c0", "80", "c0"])}`;
}

function buildGenesis(validatorAddresses: string[], walletAddresses: string[]) {
  return {
    config: {
      chainId: 1337,
      berlinBlock: 0,
      shanghaiTime: 0,
      qbft: { blockperiodseconds: 2, epochlength: 30000, requesttimeoutseconds: 4 }
    },
    nonce: "0x0",
    timestamp: "0x0",
    gasLimit: "0x1c9c380",
    difficulty: "0x1",
    mixHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    coinbase: "0x0000000000000000000000000000000000000000",
    number: "0x0",
    gasUsed: "0x0",
    parentHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    extraData: qbftExtraData(validatorAddresses),
    alloc: Object.fromEntries(walletAddresses.map((address) => [address.slice(2).toLowerCase(), { balance: "0x3635C9ADC5DEA00000" }]))
  };
}

function rlpList(items: string[]): string { return rlpEncode(items.join(""), 0xc0); }
function rlpBytes(hex: string): string { return hex.length === 2 && Number.parseInt(hex, 16) < 0x80 ? hex : rlpEncode(hex, 0x80); }
function rlpEncode(hex: string, offset: number): string {
  const length = hex.length / 2;
  if (length < 56) return (offset + length).toString(16).padStart(2, "0") + hex;
  const size = length.toString(16);
  const normalized = size.length % 2 === 0 ? size : `0${size}`;
  return (offset + 55 + normalized.length / 2).toString(16).padStart(2, "0") + normalized + hex;
}

async function writeNodeConfigs(validators: Array<{ name: (typeof validatorNames)[number]; publicKey: string }>): Promise<void> {
  const enodes = validators.map((node) => `enode://${node.publicKey}@${validatorIps[node.name]}:30303`);
  for (const validator of validators) {
    const directory = path.join(root, "validators", validator.name);
    const bootnodes = enodes.filter((enode) => !enode.includes(`@${validatorIps[validator.name]}:`));
    const rpc = validator.name === "hospital-a"
      ? `rpc-http-enabled=true\nrpc-http-host=\"0.0.0.0\"\nrpc-http-api=[\"ETH\",\"NET\",\"QBFT\",\"WEB3\"]\nhost-allowlist=[\"besu-hospital-a-validator\",\"localhost\",\"127.0.0.1\"]\n`
      : "";
    await writeFile(
      path.join(directory, "permissions.toml"),
      `nodes-allowlist=[${enodes.map((node) => `\"${node}\"`).join(",")}]\n`,
      "utf8"
    );
    await writeFile(
      path.join(directory, "config.toml"),
      `data-path=\"/data\"\ngenesis-file=\"/config/genesis.json\"\np2p-port=30303\nbootnodes=[${bootnodes.map((node) => `\"${node}\"`).join(",")}]\npermissions-nodes-config-file-enabled=true\npermissions-nodes-config-file=\"/config/permissions.toml\"\n${rpc}`,
      "utf8"
    );
  }
}
