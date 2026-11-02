import { expect } from "chai";

import { absorbIdlePostgresClientErrors } from "../src/persistence/postgres-pool.js";

describe("PostgreSQL pool lifecycle", function () {
  it("absorbs an idle-client transport error without throwing", function () {
    let listener: ((error: Error) => void) | undefined;
    absorbIdlePostgresClientErrors({
      on: (_event: string, registered: (error: Error) => void) => { listener = registered; }
    });

    expect(() => listener?.(new Error("terminating connection due to administrator command"))).not.to.throw();
  });
});
