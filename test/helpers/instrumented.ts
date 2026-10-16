import { globalOptions } from "hardhat";

/**
 * Skips the running test (or every test under the hook that calls it) under `hardhat test --coverage`.
 *
 * Coverage recompiles every contract with probes injected and the optimizer off, so a ZKMLDSAVerifier deployed there
 * runs code that is no recorded wrapper build (evidence/zk/sp1/wrapper-builds/), and the binding gate rightly refuses
 * it as not genuine. A test that needs a genuine (recorded) wrapper, or that compares the compiled wrapper or the
 * receipt with what a plain compile derives, cannot hold under instrumentation; it is skipped there rather than made
 * to pass. The plain `npm test` run checks it, and so do the CI validators, which run after a plain compile and before
 * the coverage step (test/CIValidatorCoverage.test.ts).
 */
export function skipWhenInstrumented(ctx: Mocha.Context): void {
  if (globalOptions.coverage) ctx.skip();
}
