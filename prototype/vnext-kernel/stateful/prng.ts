/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * A deterministic, dependency-free pseudo-random generator for the stateful
 * authority campaign.
 *
 * WHY NOT `fast-check`, and why not `Math.random()`
 * ------------------------------------------------
 * `Math.random()` is disqualified outright: a campaign whose failures cannot be
 * replayed is not evidence, it is an anecdote. Every failure this lane can
 * produce must come back from a seed alone.
 *
 * `fast-check` is the obvious model-based-testing library and it was the first
 * candidate. It is NOT used, for one repository-specific reason: adding it is a
 * production `package.json` / `package-lock.json` change, which drags this
 * ASSURANCE-ONLY lane through the repository's dependency-freeze and lockfile
 * guard chain and makes a zero-Solidity-change PR touch the production
 * dependency graph. The generator this lane actually needs is ~60 lines
 * (uniform ints, weighted choice, shuffle) and shrinking is a list-level
 * delta-debug over recorded actions, not a type-directed one. The cost of
 * owning that is far below the cost of the dependency.
 *
 * `mulberry32` is used because it is a well-known, exactly specified 32-bit
 * generator: the same seed yields the same stream on every platform and every
 * Node version, which is the only property that matters here. It is NOT
 * cryptographic and nothing in this lane treats it as such.
 */

export interface Prng {
  /** Uniform integer in [0, boundExclusive). */
  int(boundExclusive: number): number;
  /** Uniform integer in [lo, hi], inclusive both ends. */
  between(lo: number, hi: number): number;
  /** Uniform element of a non-empty array. */
  pick<T>(xs: readonly T[]): T;
  /** Weighted element. `weights` must be the same length as `xs` and sum > 0. */
  weighted<T>(xs: readonly T[], weights: readonly number[]): T;
  /** True with probability `p` in [0, 1]. */
  chance(p: number): boolean;
  /** A fresh shuffled copy (Fisher-Yates). */
  shuffled<T>(xs: readonly T[]): T[];
  /** The seed this generator was constructed from — carried into every artifact. */
  readonly seed: number;
}

/**
 * mulberry32. `seed` is coerced to a uint32, so a seed of 0 is legal and the
 * stream is identical everywhere.
 */
export function makePrng(seed: number): Prng {
  let s = seed >>> 0;
  const next = (): number => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  const int = (boundExclusive: number): number => {
    if (!Number.isInteger(boundExclusive) || boundExclusive <= 0) {
      throw new Error(`prng.int bound must be a positive integer, got ${boundExclusive}`);
    }
    return Math.floor(next() * boundExclusive);
  };

  return {
    seed: seed >>> 0,
    int,
    between: (lo, hi) => {
      if (hi < lo) throw new Error(`prng.between: hi ${hi} < lo ${lo}`);
      return lo + int(hi - lo + 1);
    },
    pick: <T,>(xs: readonly T[]): T => {
      if (xs.length === 0) throw new Error("prng.pick on an empty array");
      return xs[int(xs.length)]!;
    },
    weighted: <T,>(xs: readonly T[], weights: readonly number[]): T => {
      if (xs.length === 0) throw new Error("prng.weighted on an empty array");
      if (xs.length !== weights.length) throw new Error("prng.weighted: length mismatch");
      const total = weights.reduce((a, b) => a + b, 0);
      if (total <= 0) throw new Error("prng.weighted: non-positive total weight");
      let r = next() * total;
      for (let i = 0; i < xs.length; i++) {
        r -= weights[i]!;
        if (r < 0) return xs[i]!;
      }
      return xs[xs.length - 1]!;
    },
    chance: (p) => next() < p,
    shuffled: <T,>(xs: readonly T[]): T[] => {
      const out = xs.slice();
      for (let i = out.length - 1; i > 0; i--) {
        const j = int(i + 1);
        const tmp = out[i]!;
        out[i] = out[j]!;
        out[j] = tmp;
      }
      return out;
    },
  };
}
