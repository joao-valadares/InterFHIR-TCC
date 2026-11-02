import { requireExplicitInstitutionGatewayBinding } from "../middleware/src/config.js";

/** Starts one gateway with an explicit institutional vault selection. */
requireExplicitInstitutionGatewayBinding(process.env);
await import("./start-api.js");
