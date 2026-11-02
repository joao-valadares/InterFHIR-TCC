import { expect } from "chai";
import { withHistoricalObservationMutation, type HistoricalStore } from "../../scripts/e2e/historical-fhir-mutation.js";

function fixture(latest = 3, encoding = "JSON") {
  const original = JSON.stringify({ resourceType: "Observation", valueQuantity: { value: 82 } });
  let text = original;
  let writes = 0;
  const store: HistoricalStore = {
    load: version => ({ pid: 10, version, latest, encoding, text }),
    replace: (_pid, expected, replacement) => { if (text !== expected) return false; text = replacement; writes++; return true; }
  };
  return { store, original, read: () => text, writes: () => writes };
}

describe("historical FHIR mutation fixture", function () {
  it("alters only the clinical value during the probe and restores the original bytes", async function () {
    const f = fixture();
    await withHistoricalObservationMutation(f.store, 2, async () => {
      expect(JSON.parse(f.read()).valueQuantity.value).to.equal(999);
    });
    expect(f.read()).to.equal(f.original);
    expect(f.writes()).to.equal(2);
  });
  it("restores the original bytes even if the E2E probe throws", async function () {
    const f = fixture();
    let message = "";
    try { await withHistoricalObservationMutation(f.store, 2, async () => { throw new Error("PROBE_FAILED"); }); }
    catch (error) { message = (error as Error).message; }
    expect(message).to.equal("PROBE_FAILED");
    expect(f.read()).to.equal(f.original);
    expect(f.writes()).to.equal(2);
  });
  it("refuses to mutate the current version or an unsupported encoding", async function () {
    for (const f of [fixture(2), fixture(3, "JSONC")]) {
      let rejected = false;
      try { await withHistoricalObservationMutation(f.store, 2, async () => undefined); } catch { rejected = true; }
      expect(rejected).to.equal(true);
      expect(f.writes()).to.equal(0);
    }
  });
  it("reports a failed conditional restoration instead of overwriting another change", async function () {
    const f = fixture();
    const replace = f.store.replace;
    let calls = 0;
    f.store.replace = (pid, expected, replacement) => ++calls === 2 ? false : replace(pid, expected, replacement);
    let message = "";
    try { await withHistoricalObservationMutation(f.store, 2, async () => undefined); }
    catch (error) { message = (error as Error).message; }
    expect(message).to.equal("E2E_HISTORICAL_RESTORE_FAILED");
  });
});
