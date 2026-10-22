// Stands in for `@tinfoilsh/verifier` inside the server child process of the
// PII integration tests (loaded through fakeVerifierRegister.mjs; never part of
// src/ or the enclave image). It keeps the one rule the tests exercise, the
// real verifier's measurement comparison: the release's code measurement (here
// the bundle digest, signed for `configRepo`) must equal the measurement in the
// enclave's report. Everything else about the bundle is taken as given.
export class Verifier {
  constructor({ configRepo }) {
    this.configRepo = configRepo;
  }

  async verifyBundle(bundle) {
    const report = JSON.parse(bundle.enclaveAttestationReport.body);
    if (report.repo !== this.configRepo) throw new Error('provenance is for another repo');
    if (report.measurement !== bundle.digest) throw new Error('measurement mismatch');
    return { hpkePublicKey: report.hpkePublicKey, measurement: { type: 'fake', registers: [report.measurement] } };
  }
}
