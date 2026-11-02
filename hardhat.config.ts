import { createRequire } from "node:module";

import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { defineConfig } from "hardhat/config";
import localRemappingsPlugin from "./scripts/hardhat-local-remappings-plugin.js";

const require = createRequire(import.meta.url);
const solcPath = require.resolve("solc/soljson.js");

export default defineConfig({
  test: { mocha: process.env.INTERFHIR_TEST_EVIDENCE ? { reporter: require.resolve("./scripts/scientific/mocha-evidence-reporter.cjs") } : {} },
  plugins: [hardhatToolboxMochaEthersPlugin, localRemappingsPlugin],
  solidity: {
    profiles: {
      default: {
        version: "0.8.28",
        path: solcPath,
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        },
        preferWasm: true
      },
      production: {
        version: "0.8.28",
        path: solcPath,
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        },
        preferWasm: true
      }
    }
  },
  paths: {
    sources: "./contracts",
    tests: {
      mocha: "./test"
    },
    cache: "./cache",
    artifacts: "./artifacts"
  },
  typechain: {
    outDir: "./typechain-types"
  }
});
