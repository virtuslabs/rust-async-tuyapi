# Embassy lifetimes gating plan

Goal:
- Gate all embassy-specific lifetime usage behind the `embassy` feature.
- Keep non-embassy runtimes (tokio/async-std) lifetime-free for their core types.
- Use futures abstractions to maintain runtime-agnostic core logic.

Proposal:
- In Tuyadevice.rs and Tuyadevice implementation, wrap embassy-specific generic lifetime types with `#[cfg(feature = "embassy")]` and provide non-embassy versions without lifetimes.
- In runtime.rs, provide a embassy path that uses `ReadHalf<'a>`/`WriteHalf<'a>` and a non-embassy path that uses `ReadHalf`/`WriteHalf` without lifetimes. Gate all code accordingly.
- For all cross-cutting traits (spawn, connect, sleep, channels), keep the public API stable via `crate::runtime` re-exports, but have embassy-specific lifetimes only present when `embassy` is enabled.
- Provide a migration checklist and tests to cover all 3 runtimes.

Next steps if you approve:
- Implement the gated changes in code with small, isolated commits.
- Run cargo check for tokio, async-std, and embassy features.
