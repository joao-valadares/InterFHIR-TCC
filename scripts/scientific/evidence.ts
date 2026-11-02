import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export type TestCategory = "unit" | "contracts" | "postgres" | "https";
export function classifyTestFile(file: string): TestCategory {
  const name = path.basename(file);
  if (["health-access-control.test.ts", "registries.test.ts", "institution-registry.test.ts"].includes(name)) return "contracts";
  if (["postgres-manifest-repository.test.ts", "postgres-share-repository.test.ts"].includes(name)) return "postgres";
  if (["http-authentication.test.ts", "udap-interinstitutional-scenario-report.test.ts", "certificate-identity.test.ts"].includes(name)) return "https";
  return "unit";
}

export function observeDelivery(body: unknown, authorized: boolean): "authorized" | "none" | "unexpected" | "unknown" {
  if (body === undefined) return "unknown";
  function clinical(value: unknown): boolean {
    if (Array.isArray(value)) return value.some(clinical);
    if (!value || typeof value !== "object") return false;
    return Object.entries(value).some(([key, child]) => /^(resource|resourceType|entry|patientReference|consentReference|fhirLocator|resourceReference|content|pointer)$/i.test(key) || clinical(child));
  }
  return clinical(body) ? (authorized ? "authorized" : "unexpected") : "none";
}

export function summarizeSamples(samples: Array<{durationMs: number; success: boolean}>) {
  const values = samples.filter(s => s.success).map(s => s.durationMs).sort((a,b) => a-b);
  if (samples.some(s => !Number.isFinite(s.durationMs) || s.durationMs < 0)) throw new Error("INVALID_DURATION");
  const n = values.length;
  const mean = n ? values.reduce((a,b) => a+b,0)/n : null;
  return { count: samples.length, succeeded: n, failed: samples.length-n, mean,
    median: n ? (values[Math.floor((n-1)/2)] + values[Math.floor(n/2)])/2 : null,
    p95: n ? values[Math.ceil(n*.95)-1] : null, min: n ? values[0] : null, max: n ? values[n-1] : null,
    sampleStandardDeviation: n > 1 ? Math.sqrt(values.reduce((sum,x) => sum+(x-mean!)**2,0)/(n-1)) : null };
}

export async function sourceIdentity(root = process.cwd()) {
  const git = (args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8", windowsHide: true }).trim();
  // A local rename leaves the old path in the index and the new path untracked.
  // Hash the current working tree without trying to read the removed path.
  const deleted = new Set(git(["ls-files", "--deleted"]).split(/\r?\n/));
  const files = git(["ls-files", "--cached", "--others", "--exclude-standard"]).split(/\r?\n/)
    .filter(f => !deleted.has(f))
    .filter(f => /^(contracts\/|middleware\/|scripts\/|test\/|types\/|fixtures\/|infra\/|package.*json$|hardhat.config.ts$|tsconfig.json$|docker.*)/.test(f)).sort();
  const hash = createHash("sha256");
  for (const file of files) { hash.update(file); hash.update(await readFile(path.join(root,file))); }
  return { revision: git(["rev-parse", "HEAD"]), dirty: git(["status", "--porcelain"]).length > 0, sourceHash: hash.digest("hex"), sourceHashScope: "repository-execution-v2", nodeVersion: process.version, platform: process.platform };
}

export async function writeRunArtifact(kind: string, report: unknown, root = process.cwd()) {
  if (!/^[a-z][a-z0-9-]+$/.test(kind)) throw new Error("INVALID_ARTIFACT_KIND");
  const runId = `${new Date().toISOString().replace(/[:.]/g,"-")}-${randomUUID().slice(0,8)}`;
  const directory = path.join(root,"reports","runs",runId);
  await mkdir(directory,{recursive:true});
  const output = { schemaVersion: 2, runId, recordedAt: new Date().toISOString(), source: await sourceIdentity(root), report };
  const serialized = `${JSON.stringify(output,null,2)}\n`;
  await writeFile(path.join(directory,`${kind}.json`),serialized,{flag:"wx"});
  await writeFile(path.join(root,"reports",`${kind}-latest.json`),serialized);
  return output;
}
