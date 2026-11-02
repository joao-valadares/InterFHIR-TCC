import { applyRuntimeEnvironment } from "./runtime-environment.js";
import { readdir, mkdir, readFile, access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { classifyTestFile, sourceIdentity, writeRunArtifact } from "./scientific/evidence.js";

applyRuntimeEnvironment();
const category = process.argv[2] ?? "all";
if (!["all","unit","contracts","postgres","https","middleware"].includes(category)) throw new Error("TEST_CATEGORY_INVALID");
const files = (await Promise.all(["test","middleware/test"].map(async dir => (await readdir(dir)).filter(f => f.endsWith(".test.ts")).map(f => `${dir}/${f}`)))).flat().sort();
const selected = files.filter(file => category === "all" || (category === "middleware" ? file.startsWith("middleware/") : classifyTestFile(file) === category));
if (!selected.length) throw new Error("NO_TESTS_SELECTED");
await mkdir(".local/test-results",{recursive:true});
const resultPath = path.resolve(`.local/test-results/${category}-${Date.now()}.json`);
if (selected.some(file => classifyTestFile(file) === "https")) {
  try { await access(".local/pki/ca/ca.crt"); }
  catch {
    const prepared = spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/generate-local-pki.ps1"], { stdio: "inherit", windowsHide: true });
    if (prepared.status !== 0) throw new Error("HTTPS_PKI_PREPARATION_BLOCKED");
  }
}
const before = await sourceIdentity();
const started = Date.now();
const result = spawnSync(process.execPath,["scripts/run-hardhat.cjs","test","--no-compile",...selected],{stdio:"inherit",windowsHide:true,env:{...process.env,INTERFHIR_TEST_EVIDENCE:resultPath}});
let evidence: { cases: Array<{file:string;title:string;status:string;durationMs:number|null}>; stats: {passes:number;failures:number;pending:number}};
try { evidence = JSON.parse(await readFile(resultPath,"utf8")); }
catch { evidence = {cases:[],stats:{passes:0,failures:0,pending:0}}; }
const after = await sourceIdentity();
const represented = new Set(evidence.cases.map(test => test.file));
const complete = selected.every(file => represented.has(file));
const status = result.status === 0 && complete && evidence.stats.pending === 0 && evidence.stats.failures === 0 && before.sourceHash === after.sourceHash ? "passed" : "failed";
await writeRunArtifact(`tests-${category}`,{status,category,command:["node","scripts/run-hardhat.cjs","test","--no-compile",...selected],durationMs:Date.now()-started,files:selected,sourceBefore:before.sourceHash,sourceAfter:after.sourceHash,...evidence});
process.exitCode = status === "passed" ? 0 : 1;
