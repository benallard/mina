# Contributing to Mina

Read [AGENTS.md](AGENTS.md) first. It is short and governs everything.

## Getting started

```bash
git clone https://github.com/yourorg/mina
cd mina
cargo test --all    # should pass with no system dependencies
cargo clippy        # should produce no warnings
cargo fmt --check   # should produce no diff
```

## Before opening a PR

- All three checks above pass
- New logic has Tier 1 or Tier 2 tests (see AGENTS.md)
- If your change touches PAM, auditd, or transport: add a step to `docs/manual-testing.md`
- No new `unwrap()` in production paths

## Where things go

| What you're adding | Where it goes |
|---|---|
| Core agent logic | `src/` |
| Nest ingest server | `nest/src/` |
| Analysis / query scripts | `tools/` (Python, stdlib-only preferred) |
| Manual test steps | `docs/manual-testing.md` |

## Questions

Open an issue. Describe what you want to change and why before writing code.
