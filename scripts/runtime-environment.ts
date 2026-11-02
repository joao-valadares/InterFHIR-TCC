import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { realpathSync, existsSync } from "node:fs";
import path from "node:path";
import net from "node:net";

export const COMPOSE_FILES = ["docker-compose.yml","docker-compose.dev.yml","docker-compose.identity.yml","docker-compose.blockchain.yml"];
export function normalizeRoot(root: string) { const resolved = path.resolve(root).replaceAll("\\","/").replace(/\/$/,""); return process.platform === "win32" ? resolved.toLowerCase() : resolved; }
export function validateProjectRoot(root = process.cwd()) {
  const resolved = realpathSync(root);
  const gitRoot = execFileSync("git",["rev-parse","--show-toplevel"],{cwd:resolved,encoding:"utf8",windowsHide:true}).trim();
  if (normalizeRoot(gitRoot) !== normalizeRoot(resolved)) throw new Error("E2E_PROJECT_ROOT_INVALID:GIT_ROOT");
  for (const file of [...COMPOSE_FILES,"package.json","scripts","middleware"]) if (!existsSync(path.join(resolved,file))) throw new Error(`E2E_PROJECT_ROOT_INVALID:${file}`);
  return resolved;
}
export const PORT_DEFAULTS = { HOSPITAL_A_FHIR:8081, CLINIC_B_FHIR:8082, HOSPITAL_A_METADATA:5433, CLINIC_B_METADATA:5435, HOSPITAL_A_GATEWAY:3001, CLINIC_B_GATEWAY:3002, HOSPITAL_A_PEER:4001, CLINIC_B_PEER:4002, KEYCLOAK:8180, KEYCLOAK_MANAGEMENT:8190, BESU_RPC:8546 } as const;
export function runtimeEnvironment(root = process.cwd(), env: NodeJS.ProcessEnv = process.env) {
  const projectName = env.INTERFHIR_PROJECT_NAME ?? `interfhir-${createHash("sha256").update(normalizeRoot(realpathSync(root))).digest("hex").slice(0,10)}`;
  if (!/^[a-z0-9][a-z0-9_-]{2,62}$/.test(projectName)) throw new Error("INTERFHIR_PROJECT_NAME_INVALID");
  const ports = Object.fromEntries(Object.entries(PORT_DEFAULTS).map(([name,value]) => [name,Number(env[`INTERFHIR_${name}_HOST_PORT`] ?? value)])) as Record<keyof typeof PORT_DEFAULTS,number>;
  if (Object.values(ports).some(p=> !Number.isSafeInteger(p)||p<1024||p>65535) || new Set(Object.values(ports)).size !== Object.values(ports).length) throw new Error("INTERFHIR_PORTS_INVALID_OR_DUPLICATED");
  const subnet = env.INTERFHIR_BESU_SUBNET ?? "172.30.0.0/24";
  if (!/^(10|172|192)\.(\d{1,3})\.(\d{1,3})\.0\/24$/.test(subnet) || subnet.split(/[./]/).slice(0,4).some(x=>Number(x)>255)) throw new Error("INTERFHIR_BESU_SUBNET_INVALID");
  const prefix = subnet.slice(0,subnet.lastIndexOf(".")+1);
  return {projectName,root:normalizeRoot(root),ports,subnet,environment:{INTERFHIR_PROJECT_NAME:projectName,INTERFHIR_ROOT:normalizeRoot(root),COMPOSE_PROJECT_NAME:projectName,INTERFHIR_BESU_SUBNET:subnet,...Object.fromEntries(Object.entries(ports).map(([key,value])=>[`INTERFHIR_${key}_HOST_PORT`,String(value)])),...Object.fromEntries(["HOSPITAL_A","CLINIC_B","AUDITOR","CONSORTIUM"].map((key,i)=>[`INTERFHIR_BESU_${key}_IP`,`${prefix}${10+i}`]))}};
}
export function applyRuntimeEnvironment(root = process.cwd()) {
  const config = runtimeEnvironment(root);
  Object.assign(process.env,config.environment);
  const p = config.ports;
  const pairs: Record<string,string> = {
    KEYCLOAK_HOST_URL:`http://127.0.0.1:${p.KEYCLOAK}`,KEYCLOAK_MANAGEMENT_HOST_URL:`http://127.0.0.1:${p.KEYCLOAK_MANAGEMENT}`,
    BLOCKCHAIN_RPC_URL:`http://127.0.0.1:${p.BESU_RPC}`,E2E_BLOCKCHAIN_RPC_URL:`http://127.0.0.1:${p.BESU_RPC}`,RUNTIME_BLOCKCHAIN_RPC_URL:`http://127.0.0.1:${p.BESU_RPC}`,
    RUNTIME_INSTITUTIONAL_IDENTITY_NETWORK:`${config.projectName}-institutional-identity`,RUNTIME_INSTITUTIONAL_BLOCKCHAIN_NETWORK:`${config.projectName}-institutional-blockchain`
  };
  for(const institution of ["HOSPITAL_A","CLINIC_B"] as const) {
    const lower=institution.toLowerCase();
    const fhir=`http://127.0.0.1:${p[`${institution}_FHIR`]}/fhir`;
    const gateway=`https://localhost:${p[`${institution}_GATEWAY`]}`;
    const database=`postgresql://${lower}_metadata:${lower}_metadata@127.0.0.1:${p[`${institution}_METADATA`]}/interfhir_${lower}_metadata`;
    Object.assign(pairs,{[`E2E_${institution}_FHIR_URL`]:fhir,[`FHIR_${institution}_BASE_URL`]:fhir,[`RUNTIME_${institution}_FHIR_BASE_URL`]:fhir,[`E2E_${institution}_GATEWAY_URL`]:gateway,[`RUNTIME_${institution}_GATEWAY_URL`]:gateway,[`E2E_${institution}_METADATA_DATABASE_URL`]:database,[`RUNTIME_${institution}_METADATA_DATABASE_URL`]:database,[`${institution}_METADATA_TEST_DATABASE_URL`]:database});
  }
  pairs.MANIFEST_TEST_DATABASE_URL=pairs.HOSPITAL_A_METADATA_TEST_DATABASE_URL;
  pairs.E2E_UDAP_DISCOVERY_URL=`${pairs.E2E_HOSPITAL_A_GATEWAY_URL}/fhir/.well-known/udap`;
  pairs.UDAP_BASE_URL=pairs.E2E_HOSPITAL_A_GATEWAY_URL;
  pairs.UDAP_DISCOVERY_URL=pairs.E2E_UDAP_DISCOVERY_URL;
  pairs.UDAP_CLINIC_B_DISCOVERY_URL=pairs.E2E_UDAP_DISCOVERY_URL;
  for(const [key,value] of Object.entries(pairs)) process.env[key] ??= value;
  return config;
}
export function composeArguments(root=process.cwd()) { const c=runtimeEnvironment(root); return ["compose","--profile","gateways","--project-name",c.projectName,"--project-directory",root,...COMPOSE_FILES.flatMap(file=>["--file",path.join(root,file)])]; }
export function dockerJson(args:string[]) { return JSON.parse(execFileSync("docker",args,{encoding:"utf8",windowsHide:true,stdio:["ignore","pipe","pipe"]})); }
export function assertRuntimeResourceIdentity(resources: Array<{ Name?: string; name?: string; Config?: { Labels?: Record<string,string> }; Labels?: Record<string,string> }>, root=process.cwd()) {
  const config = runtimeEnvironment(root);
  for (const resource of resources) {
    const labels = resource.Config?.Labels ?? resource.Labels ?? {};
    if (labels["org.interfhir.root"] !== config.root || labels["com.docker.compose.project"] !== config.projectName) throw new Error("RESOURCE_OWNERSHIP_MISMATCH");
    const name = (resource.Name ?? resource.name ?? "").replace(/^\//, "");
    if (name && !name.startsWith(config.projectName + "-")) throw new Error("RESOURCE_NAME_MISMATCH");
  }
}
export function assertOwnedResources(root=process.cwd()) {
  const c=runtimeEnvironment(root);
  for(const kind of ["container","network","volume"]) {
    const args=kind==="container"?["ps","-aq","--filter",`label=com.docker.compose.project=${c.projectName}`]:[kind,"ls","-q","--filter",`label=com.docker.compose.project=${c.projectName}`];
    const ids=execFileSync("docker",args,{encoding:"utf8",windowsHide:true}).trim().split(/\r?\n/).filter(Boolean);
    for(const id of ids) { const object=dockerJson([kind,"inspect",id])[0]; assertRuntimeResourceIdentity([object],root); }
  }
}
export async function runtimePreflight(root=process.cwd()) {
  validateProjectRoot(root); assertOwnedResources(root);
  const c=runtimeEnvironment(root);
  const own=execFileSync("docker",["ps","-q","--filter",`label=com.docker.compose.project=${c.projectName}`],{encoding:"utf8",windowsHide:true}).trim().split(/\r?\n/).filter(Boolean);
  const ownPorts=new Set<string>();
  for(const id of own) for(const binds of Object.values(dockerJson(["inspect",id])[0].NetworkSettings.Ports??{}) as any[]) for(const bind of binds??[]) ownPorts.add(bind.HostPort);
  for(const port of Object.values(c.ports)) if(!ownPorts.has(String(port))) await new Promise<void>((resolve,reject)=>{const server=net.createServer();server.once("error",()=>reject(new Error(`HOST_PORT_UNAVAILABLE:${port}`)));server.listen(port,"127.0.0.1",()=>server.close(()=>resolve()));});
  const ids=execFileSync("docker",["network","ls","-q"],{encoding:"utf8",windowsHide:true}).trim().split(/\r?\n/).filter(Boolean);
  const number=(ip:string)=>ip.split(".").reduce((n,v)=>n*256+Number(v),0);
  const current=number(c.subnet.split("/")[0]);
  for(const id of ids){const n=dockerJson(["network","inspect",id])[0];if(n.Labels?.["org.interfhir.root"]===c.root)continue;for(const ipam of n.IPAM?.Config??[]){if(!ipam.Subnet||ipam.Subnet.includes(":"))continue;const [ip,bits]=ipam.Subnet.split("/");const low=number(ip),high=low+2**(32-Number(bits))-1;if(current<=high&&current+255>=low)throw new Error("BESU_SUBNET_CONFLICT");}}
}
