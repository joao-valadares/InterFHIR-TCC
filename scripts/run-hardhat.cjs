const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const hardhatGlobal = path.join(root, ".hardhat-global");
fs.mkdirSync(hardhatGlobal, { recursive: true });

const hardhatPackage = require(path.join(root, "node_modules", "hardhat", "package.json"));
const hardhatCli = path.join(root, "node_modules", "hardhat", hardhatPackage.bin.hardhat);
const result = spawnSync(process.execPath, [hardhatCli, ...process.argv.slice(2)], {
  cwd: root,
  stdio: "inherit",
  shell: false,
  env: {
    ...process.env,
    APPDATA: hardhatGlobal,
    LOCALAPPDATA: hardhatGlobal,
    XDG_CONFIG_HOME: hardhatGlobal,
    XDG_CACHE_HOME: path.join(hardhatGlobal, "cache"),
    XDG_DATA_HOME: path.join(hardhatGlobal, "data"),
    HARDHAT_TELEMETRY_DISABLED: "true"
  }
});

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
