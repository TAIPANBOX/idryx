# CLAUDE.md

**Read [`AGENTS.md`](./AGENTS.md). It is the single instruction file for this
repo, and it applies to Claude exactly as written.**

This file holds no guidance of its own on purpose. Two instruction files in one
repo are two copies of one thing, and two copies of one thing always diverge:
one gets a new invariant, the other does not, and the next session reads the
stale one. `AGENTS.md` is also the file the other agent tooling reads, so
keeping the content there means one source for everybody.

If you are about to add a rule here, add it to `AGENTS.md` instead.

Start with, in `AGENTS.md`:

- **The non-negotiable gate**, before your first commit.
- **Hard invariants**, before changing a detector, the graph, or anything that
  touches the shared wire types.
- **Decisions that have no gate yet**, so you know which invariants are held by
  prose alone and cannot catch you.

## Coverage floor

Total test coverage measured in CI may not fall below the number in `.coverage-floor`, and that number may only rise: it was set to the first CI measurement minus one point, and is raised when coverage rises. The goal is 90% (the `# target:` line in that file); the floor is raised towards it, and the job summary prints the total, the slack above the floor and the gap to the target. *(gate: `scripts/coverage-floor.sh check` and `ratchet` in CI; teeth cases in `scripts/gates-have-teeth.sh`)*

## Mutation testing

A weekly run (`.github/workflows/mutation.yml`, Sundays, also by hand with `workflow_dispatch`) breaks the product code one fault at a time with gremlins v0.6.0 and puts the count of killed and surviving mutants on the run page. Measured, not gated: no score is required yet.
