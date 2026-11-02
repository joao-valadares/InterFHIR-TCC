// Load extra definitions only in this E2E process, then run the unchanged gateway.
import "./policy-variation-fixtures.js";
await import("../start-institution-gateway.js");
