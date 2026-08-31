# IntentAuthorityKit

**Your App Intents surface stopped having users and started having an untrusted LLM planner as a caller. `perform()` receives resolved parameters and nothing about where they came from.**

In iOS 27, Siri decides at runtime which registered intent satisfies a request and chains several together. That makes your intent surface a public API invoked by a caller you do not control, do not authenticate, and cannot patch. [NowSecure's August 2026 teardown](https://www.nowsecure.com/blog/2026/08/05/what-appsec-teams-need-to-know-about-app-intents-siri-ai-and-the-new-ios-27-attack-surface/) names the failure modes: *parameter poisoning* (the recipient field of a transfer is rewritten by injected content), *action poisoning* (the planner is steered to fire `openURL` instead of `summarize`), and the one that makes both worse — the **baton pass**, where one agent hands off to another inside a session and the full transcript, injection included, is inherited downstream. Apple's [WWDC26 session 347, *Secure your app: mitigate risks to agentic features*](https://developer.apple.com/videos/play/wwdc2026/347/), concedes indirect prompt injection is unsolved and pushes threat modelling onto the developer.

*(Both sources are linked because the argument rests on them. Nothing below depends on a claim you cannot check.)*

This package is the module that pushes back: an authorization broker that sits between the planner and your intents.

> **Demo app:** **[intent-authority-demo-app](https://github.com/rajatslakhina/intent-authority-demo-app)** — a separate Xcode project that consumes this package as a version-pinned *remote* Swift Package and shows the broker refusing things on one screen.

---

## Why this matters

The obvious defence is a confirmation prompt. It does not work, for a reason that is structural rather than a matter of tuning:

**You cannot confirm your way out of content-tainted data, because the confirmation prompt renders the attacker's string.** Asking *"Send £40 to `ACME Supplies (acct 0099)`?"* — where that account came out of an email the planner read — delegates the security decision to a user reading attacker-controlled copy. There is no wording that fixes this. The only sound answer is refusal.

The second reason is subtler and is what most of this library is about:

**Provenance answers "can I trust these bytes?" It does not answer "can I trust that this value was selected for the right reason?"** Those are different questions, and the obvious implementation conflates them. A contact pulled from your own address book has authentic content no matter what — but if the planner chose *that* contact after reading an attacker's email, the selection is the poisoned bit. A single-axis model sees "value came from our own database" and waves the commit through.

So every value carries **two** trust axes:

| | comes from | degraded by |
|---|---|---|
| **content trust** | the value's provenance | what produced the bytes |
| **selection trust** | the session's taint floor | what the session has read |

`.userConfirmed` values are exempt from the session floor — a value the user typed themselves was not selected by the planner and cannot be retroactively poisoned. `.appDerived` values are deliberately **not** exempt. That asymmetry is the design.

---

## What's in it

Two library products. `IntentAuthority` imports nothing but the standard library, so the entire decision layer is testable on Linux; `IntentAuthorityUI` is the SwiftUI console the demo app renders.

**The taint model** — `Provenance` is a join-semilattice (`userConfirmed` › `appDerived` › `plannerAuthored` › `contentDerived`), so interpolating an attacker substring into a user-typed template yields a tainted value without any call site having to remember that. `TaintedValue.derived(...)` is the only supported way to build a composite, which makes the safe path the easy one. Commutativity, associativity and idempotence are checked exhaustively, not assumed.

**`TaintFloor`** — a monotone high-water mark of what the *session* has been exposed to, inherited across a baton pass. There is no way to lower it. Taint that lived only on individual values would be laundered by the handoff: the downstream agent authors a "fresh" value and it looks clean, because it never touched the poisoned bytes itself.

**`DefaultAuthorizationPolicy`** — one **tier gate**, then **four independent pure checks** (content, selection, blast radius, budget) joined **worst-wins**. `ConfirmationRequirement` is `Comparable` and combined with `max`, so the join's evaluation order provably cannot change the answer — and that property is itself a shipped, runnable check. The gate is deliberately *not* part of that proof: it short-circuits ahead of the join and is order-dependent by construction, because an empty read is a fact about the world while an empty commit is a planner error.

**`ConfirmationReceipt`** — a digest over the exact resolved parameters, *not* a boolean. (Replay protection lives one layer down in the ledger, not in the receipt's `nonce`, which nothing reads — the header comment says so rather than implying a defence that isn't there.) App Intents re-resolves parameters and planners retry, so between the moment the user approved and the moment the commit runs, the values can legitimately change. A flag cannot tell; a digest can. Blast radius is inside the digest, so a receipt granted for "archive this 1 message" does not satisfy a re-resolution to 400.

**`StableDigest`** — FNV-1a/64, hand-rolled, because Swift seeds `Hasher` per process. A receipt keyed on `hashValue` stops matching the moment the app relaunches, which is exactly the window a retry aims at — and **a test suite cannot catch it, because a test suite runs in one process.** Every field is length-prefixed, so `{"ab": "c"}` and `{"a": "bc"}` cannot collide.

**`CommitBudget`** — reserved at *admission*, not decremented on success. A budget spent only by successes does nothing against a probing planner, whose calls mostly fail. Only a refusal that provably did nothing refunds.

**`IdempotencyLedger`** — bounded, with eviction permitted only past the retry horizon. Dropping a record inside the horizon re-admits a retry as a fresh commit and double-commits, so the ledger **refuses** rather than evicting under pressure, and refuses to overwrite a record that is still inside the horizon (that overwrite would reset the clock and could clobber a settled outcome back to `.inFlight`). Past the horizon a record *is* replaced — past the horizon a repeat is a new request, not a retry — and `settle` updates in place while preserving the original timestamp.

**`AuthorityAudit`** — nine invariants shipped as runnable code, checkable against *any* policy. `BrokerSession` records every decision, including allowed tainted reads, with parameter **names** and never values.

---

## Design decisions, and what they cost

**Content-tainted commits are refused, not confirmed.** *Cost:* some legitimate flows get refused — the user really did mean to pay the invoice in that email. *Escape hatch:* re-entry through a system-mediated picker, which mints a `.userConfirmed` value. *Rejected alternative:* a "high-risk confirmation" sheet with extra friction, rejected because friction does not change who authored the string on screen.

**The taint floor is monotone and unrecoverable within a session.** *Cost:* one tainted read poisons the rest of the session, and the only reset is a new session. *Rejected alternative:* per-value taint with decay, rejected because it is precisely what the baton pass launders.

**Reads and proposals are always inert.** A proposal is how a planner in a fully-tainted session is still allowed to be useful: it surfaces a draft, and the user's action mints a fresh authentic value. *Scoping stated plainly:* a read can still exfiltrate, because its result leaves through the planner. Containing that is an egress-policy problem and is **out of scope here** — what this package does is record every tainted read so the exposure is reconstructable.

**Limits are compiled in, never remotely settable.** *Cost:* changing a ceiling needs a release. *Reason:* one mis-published config field should not lift every commit ceiling in the fleet at once.

**`StableDigest` is FNV-1a, not SHA-256.** It is a *binding* digest, defending a receipt against accidental drift — not a security primitive, and not collision-resistant against an adversary who can grind inputs. The honest upgrade is CryptoKit; it is deliberately not taken so the package stays dependency-free and Linux-testable. **Stated as a limitation, not sold as a guarantee.**

**Two things are claimed before the confirmation `await`: the budget *and* the idempotency key.** Actor isolation gives mutual exclusion *between* suspension points and nothing across them, and `await presenter.confirm(...)` sits in the middle of a check-then-act sequence.

Claiming the budget is proved necessary by a barrier-driven test: with a budget of 1 and four concurrent invocations, `CommitAdmissionOrder.reserveAfterConfirmation` (shipped so it can be proved wrong) raises **four** prompts the session can never honour where the correct order raises **one**. It does not over-admit — `reserve()` re-checks — but prompt amplification is the point: confirmation fatigue is what makes per-action approval stop being a control, so an attacker who can manufacture prompts is attacking the control directly.

Claiming the key is the symmetric half, and it was missing until an independent review pointed at the asymmetry. Two invocations of the *same* commit could both find the ledger empty, both raise a prompt, and one be discarded. Both regression tests were verified by **reverting each fix and watching the test fail** with the exact predicted symptom, then restoring it.

---

## Running it

```bash
swift build -Xswiftc -warnings-as-errors
swift test
```

Add it to a project:

```swift
.package(url: "https://github.com/rajatslakhina/intent-authority-kit.git", from: "1.0.0")
```

```swift
let session = BrokerSession(id: SessionID(conversationID), presenter: myPresenter, clock: clock)
await session.noteContentIngested(from: SourceID("inbox/message-4821"))

let result = await session.authorize(invocation)
switch result.decision {
case let .allowedCommit(key):  try await perform(); await session.settle(key, outcome: .executed)
case let .replayed(outcome):   return outcome          // a retry — do not re-execute
case let .refused(reason):     throw IntentError(reason)
case .declined, .allowedInert: break
}
```

---

## Verification status (honest)

**What was actually run**, on a Linux container with Swift 6.0.3:

- `swift build -Xswiftc -warnings-as-errors` from a clean `.build` — succeeds, zero warnings.
- `swift test` — **89 tests, 0 failures.** The concurrency tests were re-run five times to check for scheduling flakiness; stable.
- The concurrency regression test was verified to be non-vacuous by **reverting the fix and watching it fail** with the exact predicted symptom (`the same key was admitted twice`), then restoring it.
- The digest golden vectors were produced by an **independent** FNV-1a implementation (a Python script following the same encoding), not by freezing this package's own output. A swap to `Hasher` fails them in any process.
- Both invariant-checker directions are asserted: the real policy passes all nine, `PermissiveAuthorizationPolicy` fails the content-taint invariant, and `SingleAxisAuthorizationPolicy` **passes monotonicity and still fails** the selection-trust invariant — which is why that invariant exists.

**What was not run:** this package has no app target, so nothing here was launched on a Simulator. See the companion demo repo for what did and did not happen there — stated separately, because "builds for a Simulator" and "ran on a Simulator" are different claims.

CI runs both jobs on every push: [Actions](https://github.com/rajatslakhina/intent-authority-kit/actions). The Linux job re-runs the warnings-as-errors build and the full suite; the macOS job compiles the package for a generic iOS Simulator destination.

---

## Changelog

**1.1.0** — an independent review of 1.0.0 found a genuine concurrency defect and several doc claims that outran the code. Fixed:

- **The idempotency key is now claimed before the confirmation `await`, not after.** Two concurrent invocations of the same commit could previously both find the ledger empty, both raise a prompt, and — before a second fix landed — both be admitted. Regression tests for both halves were verified by reverting each fix and watching them fail.
- `IdempotencyLedger.record` refuses to overwrite a record inside the retry horizon; `settle` refuses a second settle; `rollback` refuses once a commit has settled.
- `noteContentIngested(from:)` retains the source (it previously discarded it), bounded and with a truncation flag.
- `SourceSet` is capped; its equality was aligned with what the parameter digest actually encodes.
- Removed the unused `RefusalReason.confirmationMissing` and a dead nonce counter.
- Corrected doc comments that were factually wrong: which invariant `SingleAxisAuthorizationPolicy` fails, "five joined checks" (it is one gate plus four), a `CommitBudget` audit that does not exist, and `nonce` described as a replay defence it never was.

**1.0.0** — initial release.

## License

MIT. See [LICENSE](LICENSE).
