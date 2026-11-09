// GEN2-PQ-CONFORMANCE-1 — attempt to run the UPSTREAM ZKNOX Foundry test suite for ML-DSA-65 on Hardhat 3's
// Solidity test runner (EDR), because `forge` could not be installed in this environment. Outside the repository.
// forge-std (8ba9031f, the commit pinned by the vendor's submodule), sstore2 and InterfaceVerifier are exposed as
// local npm-style packages under ./node_modules (copies of the pinned sources) since Hardhat 3 has no user remappings.
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  paths: {
    sources: "src",
    tests: { solidity: "test", mocha: "mocha-none" },
  },
  solidity: {
    version: "0.8.30",
    settings: {
      evmVersion: "osaka",
      viaIR: true,
      optimizer: { enabled: true, runs: 1_000_000 },
    },
  },
  test: {
    solidity: {
      ffi: true,
      fsPermissions: { readFile: ["test/KAT/ACVP_ML-DSA-65_keyGen-FIPS204.json","test/KAT/ACVP_ML-DSA-65_sigGen-FIPS204.json","test/KAT/ACVP_ML-DSA-65_sigVer-FIPS204.json","test/KAT/PQCsignKAT_Dilithium3.rsp","test/KAT/mldsa65_kat0.json","test/KAT/mldsa65_vectors.json"], readDirectory: ["test/KAT"] },
      transactionGasCap: false,
      blockGasLimit: false,
      gasLimit: 1_000_000_000n,
    },
  },
});
