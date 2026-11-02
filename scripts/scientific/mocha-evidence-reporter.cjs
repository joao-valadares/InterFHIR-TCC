const fs = require('node:fs');
const path = require('node:path');
const Mocha = require('mocha');
class EvidenceReporter extends Mocha.reporters.Spec {
  constructor(runner, options) {
    super(runner, options);
    const cases = [];
    const record = (test, status) => cases.push({file: path.relative(process.cwd(),test.file || '').replaceAll('\\','/'), title: test.fullTitle(), status, durationMs: test.duration ?? null});
    runner.on('pass', test => record(test,'passed'));
    runner.on('fail', test => record(test,'failed'));
    runner.on('pending', test => record(test,'skipped'));
    runner.once('end', () => {
      const output = process.env.INTERFHIR_TEST_EVIDENCE;
      if (output) fs.writeFileSync(output, JSON.stringify({cases,stats:{passes:runner.stats.passes,failures:runner.stats.failures,pending:runner.stats.pending}}, null,2));
    });
  }
}
module.exports = EvidenceReporter;
