import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { assertRuntimeResourceIdentity, composeArguments } from "../runtime-environment.js";

export interface HistoricalSnapshot { pid: number; version: number; latest: number; encoding: string; text: string }
export interface HistoricalStore {
  load(version: number): HistoricalSnapshot;
  replace(pid: number, expected: string, replacement: string): boolean;
  backup?(snapshot: HistoricalSnapshot): void;
}

export async function withHistoricalObservationMutation<T>(store: HistoricalStore, version: number, operation: () => Promise<T>): Promise<T> {
  if (!Number.isSafeInteger(version) || version < 1) throw new Error("E2E_HISTORICAL_VERSION_INVALID");
  const original = store.load(version);
  if (!Number.isSafeInteger(original.pid) || original.pid < 1 || original.version !== version || original.latest <= version || original.encoding !== "JSON") throw new Error("E2E_HISTORICAL_STORAGE_UNSUPPORTED");
  const resource = JSON.parse(original.text);
  if (resource.resourceType !== "Observation" || resource.valueQuantity?.value !== 82) throw new Error("E2E_HISTORICAL_FIXTURE_MISMATCH");
  resource.valueQuantity.value = 999;
  const modified = JSON.stringify(resource);
  store.backup?.(original);
  if (!store.replace(original.pid, original.text, modified)) throw new Error("E2E_HISTORICAL_MUTATION_NOT_APPLIED");
  try { return await operation(); }
  finally {
    if (!store.replace(original.pid, modified, original.text) || store.load(version).text !== original.text) throw new Error("E2E_HISTORICAL_RESTORE_FAILED");
  }
}

/** Restricted to one synthetic Observation in this project's clinical store. */
export function createHistoricalObservationStore(root: string): HistoricalStore {
  const docker = (...args: string[]) => execFileSync("docker", args, { cwd: root, encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }).trim();
  const container = docker(...composeArguments(root), "ps", "-q", "hospital-a-postgres");
  if (!/^[a-f0-9]{12,64}$/.test(container)) throw new Error("E2E_HISTORICAL_CONTAINER_INVALID");
  assertRuntimeResourceIdentity(JSON.parse(docker("inspect", container)), root);
  const sql = (query: string) => docker("exec", container, "psql", "-U", "hapi", "-d", "hapi", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-c", query);
  const encodedText = (text: string) => `convert_from(decode('${Buffer.from(text, "utf8").toString("base64")}','base64'),'UTF8')`;
  return {
    load(version) {
      if (!Number.isSafeInteger(version) || version < 1) throw new Error("E2E_HISTORICAL_VERSION_INVALID");
      const raw = sql(`SELECT json_build_object('pid',v.pid,'version',v.res_ver,'latest',r.res_ver,'encoding',v.res_encoding,'text',v.res_text_vc) FROM hfj_res_ver v JOIN hfj_resource r ON r.res_id=v.res_id WHERE r.fhir_id='obs-ana-specialist' AND r.res_type='Observation' AND v.res_type='Observation' AND v.res_ver=${version};`);
      if (!raw) throw new Error("E2E_HISTORICAL_ROW_NOT_FOUND");
      return JSON.parse(raw) as HistoricalSnapshot;
    },
    replace(pid, expected, replacement) {
      if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("E2E_HISTORICAL_PID_INVALID");
      return sql(`UPDATE hfj_res_ver v SET res_text_vc=${encodedText(replacement)} FROM hfj_resource r WHERE v.pid=${pid} AND r.res_id=v.res_id AND r.fhir_id='obs-ana-specialist' AND r.res_type='Observation' AND v.res_ver<r.res_ver AND v.res_text_vc=${encodedText(expected)} RETURNING v.pid;`) === String(pid);
    },
    backup(snapshot) {
      const directory = path.join(root, ".local/e2e/historical-backups");
      mkdirSync(directory, { recursive: true });
      writeFileSync(path.join(directory, `${snapshot.pid}-${snapshot.version}.json`), JSON.stringify(snapshot), { flag: "wx" });
    }
  };
}
