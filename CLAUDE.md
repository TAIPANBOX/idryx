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
