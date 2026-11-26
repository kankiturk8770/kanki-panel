# MASTER PROTOCOL: GO, RUST, KOTLIN, SHELL & INFRASTRUCTURE

## 1. TOKEN EFFICIENCY & SILENT EXECUTION (HIGHEST PRIORITY)
- **Silent Mode:** NEVER narrate your steps, thoughts, or tool calls. Execute all reads, edits, builds, and tests silently.
- **Minimal Output:** Respond ONLY after all tasks compile and pass tests. Keep final reports under 10 bullet lines.
- **Context Hygiene:** Never read full large files, lockfiles, binaries, or build artifacts. Read targeted line ranges or use `rg`/`grep`. Never re-read unchanged files.
- **Subagent Offloading:** Run heavy codebase searches, log analysis, and test suites in isolated background subagents so raw logs do not pollute the main context.
- **Surgical Edits:** Modify only exact target blocks; never rewrite whole files for small changes.

## 2. ZERO DUMMY CODE & 100% IMPLEMENTATION
- **Strictly Banned:** `TODO`, `FIXME`, `todo!()`, `unimplemented!()`, `pass`, `...`, stub functions, hardcoded mocks, or placeholder logic in production paths.
- **No Swallowed Errors:** Ignoring errors (`_ = err`, empty `catch {}`, or suppressed exit codes) is strictly forbidden.
- If a critical spec, secret, or protocol detail is missing, STOP and ask in 1–2 short sentences before writing partial code.

## 3. LANGUAGE-SPECIFIC HARDENING
- **Go:** Enforce `context.Context` timeouts on all network/DB/exec calls. Close all resources via `defer`. Prevent goroutine leaks (use `errgroup` or bounded worker pools). Protect shared maps/state with mutexes or atomics (`go test -race` clean).
- **Rust:** Zero `.unwrap()` or `.expect()` in production paths (propagate errors via `?` and typed `Result`). Minimize `unsafe` blocks (document invariants if unavoidable). Use bounded channels/buffers to prevent OOM under traffic spikes.
- **Kotlin (Android/Backend):** Zero `GlobalScope` or non-null assertions (`!!`) in production. Explicitly close all sockets, streams, and `ParcelFileDescriptor`s (`VpnService`). Never block the Main thread; manage coroutine lifecycles cleanly.
- **Shell:** Start every script with `set -euo pipefail`. Double-quote every variable (`"$VAR"`). Register `trap` handlers for temp-file/process cleanup. Never pass unvalidated input to `eval` or subshells.

## 4. API, VPN, PANEL & BOT SECURITY (ZERO-TRUST)
- **Boundary Validation:** Validate and sanitize 100% of inputs (API payloads, packets, headers, Telegram updates, webhooks) with strict schemas and size limits.
- **Zero-Trust Auth & Ownership:** Never trust client-provided user IDs, peer keys, or roles. Enforce server-side ownership checks on every query/mutation (prevent IDOR and privilege escalation).
- **Zero Injection:** Use parameterized SQL queries exclusively. When panels/bots execute system or tunnel commands (e.g., `ip`, `iptables`, `wg`, `sysctl`), pass arguments as strict arrays—NEVER concatenate user strings into shell commands.
- **Secrets & Privacy:** Never hardcode tokens, private keys, or credentials. Never log sensitive user data, private keys, or raw stack traces.
- **Resilience:** Enforce rate limits on auth/bot/mutation endpoints, strict timeouts on upstream calls, and atomic DB transactions with rollback on multi-step failures.

## 5. REAL TESTS ONLY (SILENT VERIFICATION)
- **Banned:** Tautological tests (`assert true`), trivial getter/setter tests, or mocking the exact logic under test to fake coverage.
- **Required:** Write focused integration/edge-case tests ONLY for high-risk paths:
  1. Unauthorized access, invalid tokens, and cross-user IDOR attempts (401/403).
  2. Concurrent mutations / race conditions and transaction rollbacks.
  3. Malformed inputs/packets, buffer limits, and upstream timeouts.

## 6. FINAL REPORT FORMAT (POST-COMPLETION ONLY)
- **Files Changed:** (paths)
- **Built & Hardened:** (3–5 short bullets)
- **Verification:** (build, linter & test status)
