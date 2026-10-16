/**
 * SP1 implementation lane: reading revert data from a failed eth_call (scripts/lib/rpc-answer.ts), which the per-chain
 * execution check turns into a verdict. EDR, ethers and plain JSON-RPC put the data in `data`; ethers can also carry
 * the node's own error in `info.error`. Anything that is not hex is no revert data. Whether a failure is the chain's
 * answer at all is SP1-TD2's isExecutionFailure, tested in test/Sp1Td2VerifierBinding.test.ts.
 */
import { expect } from "chai";

import { revertDataOf } from "../scripts/lib/rpc-answer";
import { verdictOf } from "../scripts/lib/sp1-chain-execution";

describe("SP1 implementation lane — revert data from a failed call", function () {
  it("reads it where each provider puts it, lowercased, and nothing else", function () {
    const cases: [string, unknown, string | null][] = [
      ["EDR (SolidityError, code 3)", { code: 3, data: "0x7fcdd1f4" }, "0x7fcdd1f4"],
      ["ethers CALL_EXCEPTION", { code: "CALL_EXCEPTION", data: "0x7FCDD1F4" }, "0x7fcdd1f4"],
      [
        "the node's error inside ethers' info",
        { code: "CALL_EXCEPTION", data: null, info: { error: { data: "0xAB" } } },
        "0xab",
      ],
      ["top-level data wins over the nested one", { data: "0x01", info: { error: { data: "0x02" } } }, "0x01"],
      ["text is not revert data", { data: "execution reverted" }, null],
      ["nested text is not either", { info: { error: { data: "reverted" } } }, null],
      ["no data", { code: 3 }, null],
      ["null", null, null],
      ["a string", "0x7fcdd1f4", null],
    ];
    for (const [label, error, data] of cases) expect(revertDataOf(error), label).to.equal(data);
  });

  it("a revert without data is the verdict 'revert 0x'; a returned value is not a plain success", async function () {
    const provider = (outcome: () => Promise<string>) => ({ call: outcome }) as any;
    const call = { to: "0x0000000000000000000000000000000000000001", data: "0x41493c60" };
    expect(
      await verdictOf(
        provider(() => Promise.reject({ code: 3 })),
        call,
      ),
    ).to.equal("revert 0x");
    expect(
      await verdictOf(
        provider(() => Promise.resolve("0x")),
        call,
      ),
    ).to.equal("success");
    expect(
      await verdictOf(
        provider(() => Promise.resolve("0x01")),
        call,
      ),
    ).to.equal("success 0x01");
  });
});
