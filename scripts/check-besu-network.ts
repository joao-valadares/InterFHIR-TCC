import { readFile } from "node:fs/promises";
import path from "node:path";
import { Contract, JsonRpcProvider, type InterfaceAbi } from "ethers";

const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546";
const provider = new JsonRpcProvider(rpcUrl);
const chain = await provider.getNetwork();
if (chain.chainId !== 1337n) throw new Error(`BESU_CHAIN_ID_INVALID:${chain.chainId}`);
const peers = await provider.send("net_peerCount", []) as string;
if (Number.parseInt(peers, 16) < 3) throw new Error(`BESU_PEER_COUNT_INSUFFICIENT:${peers}`);
const before = await provider.getBlockNumber();
await new Promise((resolve) => setTimeout(resolve, 4500));
const after = await provider.getBlockNumber();
if (after <= before) throw new Error(`BESU_BLOCK_NOT_ADVANCING:${before}:${after}`);
const address = process.env.HEALTH_ACCESS_CONTROL_ADDRESS;
if (address) {
  const code = await provider.getCode(address);
  if (code === "0x") throw new Error("BESU_CONTRACT_CODE_MISSING");
  const artifact = JSON.parse(await readFile(path.resolve(process.cwd(), "artifacts/contracts/HealthAccessControl.sol/HealthAccessControl.json"), "utf8")) as { abi: InterfaceAbi };
  const owner = await new Contract(address, artifact.abi, provider).owner();
  if (typeof owner !== "string" || !owner.startsWith("0x")) throw new Error("BESU_CONTRACT_UNREADABLE");
}
console.log(JSON.stringify({ chainId: Number(chain.chainId), peerCount: Number.parseInt(peers, 16), blockBefore: before, blockAfter: after, contractChecked: Boolean(address) }, null, 2));
provider.destroy();
