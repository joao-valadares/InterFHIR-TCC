import path from "node:path";

import type { SolidityHooks } from "hardhat/types/hooks";

const projectRoot = path.resolve(process.cwd());

export default async (): Promise<Partial<SolidityHooks>> => ({
  readNpmPackageRemappings: async (
    context,
    packageName,
    packageVersion,
    packagePath,
    next
  ) => {
    if (
      packageName === "interfhir" &&
      path.resolve(packagePath) === projectRoot
    ) {
      return [];
    }
    return next(context, packageName, packageVersion, packagePath);
  }
});
