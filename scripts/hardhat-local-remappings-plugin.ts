import type { HardhatPlugin } from "hardhat/types/plugins";
import { definePlugin } from "hardhat/plugins";

const plugin: HardhatPlugin = definePlugin({
  id: "interfhir:local-remappings",
  hookHandlers: {
    solidity: () => import("./hardhat-local-remappings.js")
  }
});

export default plugin;
