import {
  buildRuntimeTargets,
  checkRuntimeDependency
} from "./wait-for-services.js";

export async function main() {
  const checks = [];
  for (const target of buildRuntimeTargets()) {
    const check = await checkRuntimeDependency(target);
    checks.push(check);
    if (check.status === "failed") break;
  }
  const firstFailure = checks.find((check) => check.status === "failed");
  console.log(JSON.stringify({
    status: firstFailure ? "blocked" : "ready",
    checks,
    firstFailure: firstFailure ?? null
  }, null, 2));
  if (firstFailure) process.exitCode = 1;
}

if (process.argv.some((argument) => /[\\/]check-runtime\.(?:ts|js)$/.test(argument))) {
  await main();
}
