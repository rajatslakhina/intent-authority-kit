import XCTest
@testable import IntentAuthority

final class BrokerSessionTests: XCTestCase {

    private func makeInvocation(
        intent: String = "mail.archive",
        tier: EffectTier = .commit,
        provenance: Provenance = .userConfirmed,
        value: String = "Thread #1",
        radius: Int = 1
    ) -> IntentInvocation {
        IntentInvocation(
            descriptor: IntentDescriptor(
                id: IntentID(intent), tier: tier, effectSummary: "Archive a conversation"
            ),
            parameters: ParameterSet([
                TaintedValue(name: "thread", canonicalValue: value, provenance: provenance)
            ]),
            blastRadius: BlastRadius(resolvedCount: radius)
        )
    }

    private func makeSession(
        clock: ManualClock,
        presenter: any ConfirmationPresenter,
        limits: AuthorityLimits = .standard,
        floor: TaintFloor = .clean,
        order: CommitAdmissionOrder = .reserveBeforeConfirmation,
        policy: any AuthorizationPolicy = DefaultAuthorizationPolicy()
    ) -> BrokerSession {
        BrokerSession(
            id: SessionID("s-1"),
            policy: policy,
            presenter: presenter,
            clock: clock,
            limits: limits,
            initialFloor: floor,
            admissionOrder: order
        )
    }

    // MARK: - Happy path

    func testCleanCommitIsAdmittedWithoutAPrompt() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysDeclinePresenter())
        let result = await session.authorize(makeInvocation())

        XCTAssertEqual(result.requirement, .none)
        guard case .allowedCommit = result.decision else {
            return XCTFail("expected admission, got \(result.decision)")
        }
        // A declining presenter proves the prompt was never raised.
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget - 1)
    }

    func testDeclinedConfirmationRefundsTheBudget() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysDeclinePresenter())
        let result = await session.authorize(makeInvocation(provenance: .plannerAuthored))

        XCTAssertEqual(result.requirement, .verifyValue)
        XCTAssertEqual(result.decision, .declined)
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(
            remaining, AuthorityLimits.standard.commitBudget,
            "a refusal that did nothing must not spend the allowance"
        )
    }

    func testContentTaintedCommitIsRefusedWithoutAskingTheUser() async {
        let clock = ManualClock()
        let presenter = AlwaysApprovePresenter(clock: clock)
        let session = makeSession(clock: clock, presenter: presenter, floor: .contentExposed)
        let result = await session.authorize(
            makeInvocation(provenance: .contentDerived(SourceID("m-1")), value: "ATTACKER TEXT")
        )
        XCTAssertEqual(result.decision, .refused(.contentTaintedCommit))
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget)
    }

    // MARK: - Session taint

    func testBatonPassInheritanceEscalatesAnAppDerivedCommit() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysApprovePresenter(clock: clock))

        let before = await session.authorize(makeInvocation(provenance: .appDerived))
        XCTAssertEqual(before.requirement, .none)

        // Agent A read an email, then handed off to agent B.
        await session.inherit(from: .contentExposed)

        let after = await session.authorize(
            makeInvocation(provenance: .appDerived, value: "Thread #2")
        )
        XCTAssertEqual(
            after.requirement, .verifyValue,
            "the same app-derived value must be treated differently after handoff"
        )
    }

    func testFloorCannotBeLowered() async {
        let clock = ManualClock()
        let session = makeSession(
            clock: clock, presenter: AlwaysApprovePresenter(clock: clock), floor: .contentExposed
        )
        await session.note(exposure: .clean)
        let floor = await session.currentFloor
        XCTAssertEqual(floor, .contentExposed)
    }

    // MARK: - Receipt binding

    /// The test that a boolean `confirmed` flag would fail: the user approved
    /// values V, and by execution time the parameters resolved to V'.
    func testReceiptDoesNotTransferToDifferentValues() async {
        let clock = ManualClock()
        let approved = makeInvocation(provenance: .plannerAuthored, value: "Thread #1")
        let reResolved = makeInvocation(provenance: .plannerAuthored, value: "Thread #999")

        let receipt = ReceiptIssuer(clock: clock).issue(
            sessionID: SessionID("s-1"), invocation: approved, granted: .verifyValue, nonce: 1
        )

        XCTAssertNil(
            receipt.validate(
                against: approved, sessionID: SessionID("s-1"), required: .verifyValue,
                now: clock.now, validitySeconds: 120
            )
        )
        XCTAssertEqual(
            receipt.validate(
                against: reResolved, sessionID: SessionID("s-1"), required: .verifyValue,
                now: clock.now, validitySeconds: 120
            ),
            .receiptValueMismatch
        )
    }

    /// "Are you sure?" is not an answer to "which one?".
    func testWeakerReceiptDoesNotSatisfyStrongerRequirement() {
        let clock = ManualClock()
        let invocation = makeInvocation(provenance: .plannerAuthored)
        let receipt = ReceiptIssuer(clock: clock).issue(
            sessionID: SessionID("s-1"), invocation: invocation, granted: .verifyEffect, nonce: 1
        )
        XCTAssertEqual(
            receipt.validate(
                against: invocation, sessionID: SessionID("s-1"), required: .verifyValue,
                now: clock.now, validitySeconds: 120
            ),
            .receiptInsufficient
        )
    }

    func testReceiptExpires() {
        let clock = ManualClock()
        let invocation = makeInvocation(provenance: .plannerAuthored)
        let receipt = ReceiptIssuer(clock: clock).issue(
            sessionID: SessionID("s-1"), invocation: invocation, granted: .verifyValue, nonce: 1
        )
        clock.advance(bySeconds: 121)
        XCTAssertEqual(
            receipt.validate(
                against: invocation, sessionID: SessionID("s-1"), required: .verifyValue,
                now: clock.now, validitySeconds: 120
            ),
            .receiptExpired
        )
    }

    /// A receipt from the future means the clock moved under us; treat it as
    /// suspect rather than as maximally fresh.
    func testReceiptFromTheFutureIsRejected() {
        let clock = ManualClock(start: Timestamp(secondsSinceEpoch: 1000)!)
        let invocation = makeInvocation(provenance: .plannerAuthored)
        let receipt = ReceiptIssuer(clock: clock).issue(
            sessionID: SessionID("s-1"), invocation: invocation, granted: .verifyValue, nonce: 1
        )
        XCTAssertEqual(
            receipt.validate(
                against: invocation, sessionID: SessionID("s-1"), required: .verifyValue,
                now: Timestamp(secondsSinceEpoch: 500)!, validitySeconds: 120
            ),
            .receiptExpired
        )
    }

    func testReceiptIsBoundToItsSession() {
        let clock = ManualClock()
        let invocation = makeInvocation(provenance: .plannerAuthored)
        let receipt = ReceiptIssuer(clock: clock).issue(
            sessionID: SessionID("s-1"), invocation: invocation, granted: .verifyValue, nonce: 1
        )
        XCTAssertEqual(
            receipt.validate(
                against: invocation, sessionID: SessionID("other"), required: .verifyValue,
                now: clock.now, validitySeconds: 120
            ),
            .receiptSessionMismatch
        )
    }

    // MARK: - Budget and idempotency

    func testBudgetIsSpentByRefusedWorkNotOnlyBySuccess() async {
        let clock = ManualClock()
        let limits = AuthorityLimits(commitBudget: 3)
        let session = makeSession(
            clock: clock, presenter: AlwaysApprovePresenter(clock: clock), limits: limits
        )
        for index in 0..<3 {
            let result = await session.authorize(makeInvocation(value: "Thread #\(index)"))
            guard case .allowedCommit = result.decision else {
                return XCTFail("expected admission at \(index)")
            }
        }
        let exhausted = await session.authorize(makeInvocation(value: "Thread #overflow"))
        XCTAssertEqual(exhausted.decision, .refused(.commitBudgetExhausted))
    }

    func testRetryIsAnsweredFromTheLedgerRatherThanReExecuting() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysApprovePresenter(clock: clock))
        let invocation = makeInvocation()

        let first = await session.authorize(invocation)
        guard case let .allowedCommit(key) = first.decision else {
            return XCTFail("expected admission")
        }
        await session.settle(key, outcome: .executed)

        let retry = await session.authorize(invocation)
        XCTAssertEqual(retry.decision, .replayed(.executed))

        // And the retry did not cost a second unit of budget.
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget - 1)
    }

    func testRetryDuringFlightIsNotReExecuted() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysApprovePresenter(clock: clock))
        let invocation = makeInvocation()
        _ = await session.authorize(invocation)
        let retry = await session.authorize(invocation)
        XCTAssertEqual(retry.decision, .replayed(.inFlight))
    }

    func testRetryPastTheHorizonIsANewRequest() async {
        let clock = ManualClock()
        let limits = AuthorityLimits(idempotencyHorizonSeconds: 60)
        let session = makeSession(
            clock: clock, presenter: AlwaysApprovePresenter(clock: clock), limits: limits
        )
        let invocation = makeInvocation()
        let first = await session.authorize(invocation)
        guard case let .allowedCommit(key) = first.decision else { return XCTFail("expected admission") }
        await session.settle(key, outcome: .executed)

        clock.advance(bySeconds: 61)
        let later = await session.authorize(invocation)
        guard case .allowedCommit = later.decision else {
            return XCTFail("past the horizon a repeat is a new request, got \(later.decision)")
        }
    }

    func testSettlingAnUnknownKeyIsRejectedRatherThanInvented() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysApprovePresenter(clock: clock))
        let bogus = IdempotencyKey(sessionID: SessionID("s-1"), invocation: makeInvocation())
        let settled = await session.settle(bogus, outcome: .executed)
        XCTAssertFalse(settled)
    }

    func testRollbackDiscardsTheRecordSoALaterRetryIsNotAPhantomReplay() async {
        let clock = ManualClock()
        let session = makeSession(clock: clock, presenter: AlwaysApprovePresenter(clock: clock))
        let invocation = makeInvocation()
        let first = await session.authorize(invocation)
        guard case let .allowedCommit(key) = first.decision else { return XCTFail("expected admission") }

        let rolledBack = await session.rollback(key)
        XCTAssertTrue(rolledBack)
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget)

        let again = await session.authorize(invocation)
        guard case .allowedCommit = again.decision else {
            return XCTFail("expected a fresh admission, got \(again.decision)")
        }
    }

    // MARK: - Audit

    func testTaintedReadsAreAllowedButRecorded() async {
        let clock = ManualClock()
        let session = makeSession(
            clock: clock, presenter: AlwaysApprovePresenter(clock: clock), floor: .contentExposed
        )
        let result = await session.authorize(
            makeInvocation(
                intent: "mail.summarise", tier: .read,
                provenance: .contentDerived(SourceID("m-1")), value: "ATTACKER TEXT"
            )
        )
        XCTAssertEqual(result.decision, .allowedInert)

        let records = await session.auditRecords
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].untrustedParameterNames, ["thread"])
    }

    /// The audit trail must never copy attacker bytes into a support tool.
    ///
    /// Weak on its own — `AuditRecord` has no field that could hold a
    /// `canonicalValue`, so the absence is structural. Its job is to fail if
    /// someone later adds one "just for debugging"; the positive half of the
    /// contract is `testAuditRecordsNameTheUntrustedParameters` below.
    func testAuditRecordsCarryNamesNeverValues() async {
        let clock = ManualClock()
        let session = makeSession(
            clock: clock, presenter: AlwaysApprovePresenter(clock: clock), floor: .contentExposed
        )
        _ = await session.authorize(
            makeInvocation(provenance: .contentDerived(SourceID("m-1")), value: "ATTACKER TEXT")
        )
        let records = await session.auditRecords
        let dump = records.map { "\($0)" }.joined()
        XCTAssertFalse(dump.contains("ATTACKER TEXT"))
    }

    func testAuditLedgerIsBoundedAndCountsWhatItDropped() {
        var ledger = AuditLedger(capacity: 2)
        let invocation = makeInvocation()
        for _ in 0..<5 {
            ledger.append(
                at: .zero, sessionID: SessionID("s"), invocation: invocation,
                floor: .clean, trust: EffectiveTrust(content: .authentic, selection: .authentic),
                requirement: .none, decision: .allowedInert, parameterDigest: StableDigest(value: 0)
            )
        }
        XCTAssertEqual(ledger.records.count, 2)
        XCTAssertEqual(ledger.droppedCount, 3)
        XCTAssertTrue(ledger.hasGap)
        // Sequence numbers survive the drop, so the gap is visible to a reader.
        XCTAssertEqual(ledger.records.map(\.sequence), [3, 4])
    }
}

// MARK: - Coverage added after an independent review

/// Free function: a task-group closure that touches `self` captures the
/// non-`Sendable` `XCTestCase`, which Swift 6 correctly rejects.
private func sameKeyCommit() -> IntentInvocation {
    IntentInvocation(
        descriptor: IntentDescriptor(
            id: IntentID("payments.send"), tier: .commit, effectSummary: "Send a payment"
        ),
        parameters: ParameterSet([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .plannerAuthored)
        ]),
        blastRadius: .single
    )
}

final class ConcurrentReplayTests: XCTestCase {

    /// **Regression test for a real double-commit bug.**
    ///
    /// The replay check runs before `await presenter.confirm(...)`. Actor
    /// isolation guarantees nothing across that suspension, so two invocations
    /// with the *same* idempotency key can both find the ledger empty, both sit
    /// in their own confirmation, and — without a re-check after the suspension —
    /// both be admitted. Both callers then `perform()`, which is exactly the
    /// double-commit the ledger exists to prevent.
    ///
    /// The barrier makes the interleaving deterministic rather than hoping for it:
    /// both invocations are held inside the suspension point at the same time,
    /// which `testBarrierHoldsBothInvocationsInside` asserts directly.
    func testConcurrentIdenticalCommitsAdmitExactlyOnce() async {
        let clock = ManualClock()
        let presenter = BarrierConfirmationPresenter(clock: clock)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: presenter,
            clock: clock,
            // Budget of 4 so the *budget* cannot be what stops the second one —
            // this test is about the ledger, and a budget-limited pass would be
            // a false negative.
            limits: AuthorityLimits(commitBudget: 4)
        )

        let first = sameKeyCommit()
        let second = sameKeyCommit()
        async let a = session.authorize(first).decision
        async let b = session.authorize(second).decision

        // Exactly ONE invocation may reach the user. The other must be answered
        // from the ledger without a prompt — the key is claimed before the
        // suspension point, symmetrically with the budget.
        await presenter.waitForArrivals(1)
        await presenter.release()

        let decisions = [await a, await b]
        let admitted = decisions.filter { if case .allowedCommit = $0 { return true }; return false }
        let replayed = decisions.filter { if case .replayed = $0 { return true }; return false }
        let prompts = await presenter.arrivalCount

        XCTAssertEqual(admitted.count, 1, "the same key was admitted twice: \(decisions)")
        XCTAssertEqual(replayed.count, 1, "the loser must be answered from the ledger, not refused")
        XCTAssertEqual(replayed.first, .replayed(.inFlight))
        XCTAssertEqual(prompts, 1, "a duplicate commit must not manufacture a second confirmation")

        // And the loser's budget was given back, since it did nothing.
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, 3)
    }

    /// A declined confirmation must release BOTH claims — the budget and the
    /// idempotency key — or the key stays `.inFlight` forever and a later
    /// genuine attempt is answered from a phantom record that will never settle.
    func testDeclinedConfirmationReleasesTheLedgerClaimAsWellAsTheBudget() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysDeclinePresenter(),
            clock: clock,
            limits: AuthorityLimits(commitBudget: 2)
        )
        let invocation = sameKeyCommit()
        let firstDecision = await session.authorize(invocation).decision
        XCTAssertEqual(firstDecision, .declined)

        let budgetLeft = await session.remainingCommitBudget
        XCTAssertEqual(budgetLeft, 2, "a decline did nothing, so it refunds")

        // The key must be free again, not stuck at .inFlight.
        let second = await session.authorize(invocation)
        XCTAssertEqual(second.decision, .declined,
                       "got \(second.decision) — the ledger claim leaked from the first decline")
    }

    /// The ledger must refuse to overwrite an existing record: an overwrite resets
    /// `recordedAt` (silently extending the retry horizon) and can clobber a
    /// settled outcome back to `.inFlight`, so a later genuine retry is told the
    /// wrong thing.
    func testLedgerRefusesToOverwriteAndPreservesSettledOutcome() {
        var ledger = IdempotencyLedger(capacity: 8, horizonSeconds: 100)
        let key = IdempotencyKey(sessionID: SessionID("s"), invocation: sameKeyCommit())
        let t0 = Timestamp.zero
        let t50 = Timestamp(secondsSinceEpoch: 50)!

        XCTAssertTrue(ledger.record(key, outcome: .inFlight, now: t0))
        XCTAssertTrue(ledger.settle(key, outcome: .executed))
        XCTAssertFalse(ledger.record(key, outcome: .inFlight, now: t50),
                       "a second record must be refused, not applied")
        XCTAssertEqual(ledger.replay(of: key, now: t50)?.outcome, .executed,
                       "the settled outcome must survive")

        // The horizon still runs from the ORIGINAL timestamp, not the retry.
        let t101 = Timestamp(secondsSinceEpoch: 101)!
        XCTAssertNil(ledger.replay(of: key, now: t101))
    }
}

final class LedgerAndBudgetTests: XCTestCase {

    func testSaturatedLedgerRefusesRatherThanEvictingInsideTheHorizon() async {
        let clock = ManualClock()
        // Capacity 1, budget 4: the ledger runs out before the budget does, which
        // is the inverted ordering the library documents as defence-in-depth.
        let limits = AuthorityLimits(commitBudget: 4, idempotencyCapacity: 1, auditCapacity: 32)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock,
            limits: limits
        )
        func commit(_ n: Int) -> IntentInvocation {
            IntentInvocation(
                descriptor: IntentDescriptor(id: IntentID("mail.archive"), tier: .commit, effectSummary: "Archive"),
                parameters: ParameterSet([
                    TaintedValue(name: "thread", canonicalValue: "Thread #\(n)", provenance: .userConfirmed)
                ]),
                blastRadius: .single
            )
        }
        guard case .allowedCommit = await session.authorize(commit(1)).decision else {
            return XCTFail("first commit should be admitted")
        }
        let second = await session.authorize(commit(2))
        XCTAssertEqual(second.decision, .refused(.ledgerSaturated),
                       "a full ledger inside the horizon must refuse, never evict")

        // Budget spent by the admitted one only; the refusal refunded.
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, 3)
    }

    func testPruneDropsOnlyRecordsPastTheHorizon() {
        var ledger = IdempotencyLedger(capacity: 8, horizonSeconds: 60)
        let key = IdempotencyKey(sessionID: SessionID("s"), invocation: sameKeyCommit())
        ledger.record(key, outcome: .executed, now: .zero)
        XCTAssertEqual(ledger.count, 1)
        ledger.prune(now: Timestamp(secondsSinceEpoch: 59)!)
        XCTAssertEqual(ledger.count, 1)
        ledger.prune(now: Timestamp(secondsSinceEpoch: 61)!)
        XCTAssertEqual(ledger.count, 0)
    }

    func testRollbackRefusesOnceTheCommitHasSettled() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock
        )
        let result = await session.authorize(sameKeyCommit())
        guard case let .allowedCommit(key) = result.decision else { return XCTFail("expected admission") }

        await session.settle(key, outcome: .executed)
        let rolledBack = await session.rollback(key)
        XCTAssertFalse(rolledBack, "refunding budget for a commit that ran breaks the refund rule")

        let snapshot = await session.budgetSnapshot
        XCTAssertEqual(snapshot.settled, 1)
        XCTAssertEqual(snapshot.outstanding, 0)
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget - 1)
    }

    func testOutstandingCountsAdmittedCommitsWhoseOutcomeIsUnknown() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock
        )
        _ = await session.authorize(sameKeyCommit())
        let snapshot = await session.budgetSnapshot
        XCTAssertEqual(snapshot.outstanding, 1, "admitted but never settled")
        XCTAssertEqual(snapshot.settled, 0)
    }

    func testFailedOutcomeIsReplayedRatherThanReExecuted() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock
        )
        let invocation = sameKeyCommit()
        guard case let .allowedCommit(key) = await session.authorize(invocation).decision else {
            return XCTFail("expected admission")
        }
        await session.settle(key, outcome: .failed("backend 503"))
        let retry = await session.authorize(invocation)
        XCTAssertEqual(retry.decision, .replayed(.failed("backend 503")),
                       "a failure is still an outcome; the caller decides, the broker does not silently retry")
    }
}

final class SessionTaintTests: XCTestCase {

    /// The ingested source used to be discarded (`_ = source`), which left the
    /// event that raised the floor with no trace at all.
    func testIngestedSourcesAreRetainedAndBounded() async {
        let clock = ManualClock()
        let limits = AuthorityLimits(ingestedSourceCapacity: 2)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock,
            limits: limits
        )
        await session.noteContentIngested(from: SourceID("inbox/1"))
        await session.noteContentIngested(from: SourceID("inbox/1"))  // duplicate
        let afterOne = await session.ingestedSources
        XCTAssertEqual(afterOne.map(\.rawValue), ["inbox/1"])
        let floor = await session.currentFloor
        XCTAssertEqual(floor, .contentExposed)
        var truncated = await session.ingestedSourcesTruncated
        XCTAssertFalse(truncated)

        await session.noteContentIngested(from: SourceID("web/2"))
        await session.noteContentIngested(from: SourceID("web/3"))
        let all = await session.ingestedSources
        XCTAssertEqual(all.count, 2, "bounded like every other collection here")
        truncated = await session.ingestedSourcesTruncated
        XCTAssertTrue(truncated, "a partial attribution must say it is partial")
    }

    /// A proposal is how a planner in a fully-tainted session is still allowed to
    /// be useful. It must be inert end-to-end, not merely inert in the policy.
    func testProposeTierIsInertThroughTheBroker() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysDeclinePresenter(),
            clock: clock,
            initialFloor: .contentExposed
        )
        let proposal = IntentInvocation(
            descriptor: IntentDescriptor(id: IntentID("mail.draft"), tier: .propose, effectSummary: "Draft a reply"),
            parameters: ParameterSet([
                TaintedValue(
                    name: "body", canonicalValue: "ATTACKER TEXT",
                    provenance: .contentDerived(SourceID("m-1"))
                )
            ]),
            blastRadius: BlastRadius(resolvedCount: 400)
        )
        let result = await session.authorize(proposal)
        XCTAssertEqual(result.decision, .allowedInert)
        let remaining = await session.remainingCommitBudget
        XCTAssertEqual(remaining, AuthorityLimits.standard.commitBudget, "a proposal must not spend commit budget")
    }

    func testAuditRecordsNameTheUntrustedParameters() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock,
            initialFloor: .contentExposed
        )
        let invocation = IntentInvocation(
            descriptor: IntentDescriptor(id: IntentID("mail.summarise"), tier: .read, effectSummary: "Summarise"),
            parameters: ParameterSet([
                TaintedValue(name: "clean", canonicalValue: "ok", provenance: .userConfirmed),
                TaintedValue(name: "poisoned", canonicalValue: "ATTACKER", provenance: .contentDerived(SourceID("m"))),
                TaintedValue(name: "alsoPoisoned", canonicalValue: "ATTACKER2", provenance: .contentDerived(SourceID("m")))
            ]),
            blastRadius: .single
        )
        _ = await session.authorize(invocation)
        let records = await session.auditRecords
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].untrustedParameterNames.sorted(), ["alsoPoisoned", "poisoned"])
    }

    func testDroppedAuditRecordsAreCountedOnTheSession() async {
        let clock = ManualClock()
        let limits = AuthorityLimits(commitBudget: 8, auditCapacity: 2)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock,
            limits: limits
        )
        for index in 0..<5 {
            let read = IntentInvocation(
                descriptor: IntentDescriptor(id: IntentID("mail.read"), tier: .read, effectSummary: "Read"),
                parameters: ParameterSet([
                    TaintedValue(name: "id", canonicalValue: "\(index)", provenance: .appDerived)
                ]),
                blastRadius: .single
            )
            _ = await session.authorize(read)
        }
        let records = await session.auditRecords
        let dropped = await session.auditDroppedCount
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(dropped, 3, "a lossy ledger must admit the gap rather than read as 'nothing happened'")
    }

    func testAggregateProvenanceIsTheJoinOfEveryParameter() {
        let set = ParameterSet([
            TaintedValue(name: "a", canonicalValue: "1", provenance: .userConfirmed),
            TaintedValue(name: "b", canonicalValue: "2", provenance: .appDerived),
            TaintedValue(name: "c", canonicalValue: "3", provenance: .contentDerived(SourceID("m")))
        ])
        // Assert the joined Provenance itself, not just its trust projection:
        // the worst parameter is also last in name order, so asserting only the
        // projection would let a "last one wins" implementation pass.
        XCTAssertEqual(set.aggregateProvenance, .contentDerived(SourceID("m")))
        XCTAssertEqual(ParameterSet([]).aggregateProvenance, .userConfirmed)

        // Reordering the names must not change the join.
        let reordered = ParameterSet([
            TaintedValue(name: "z", canonicalValue: "3", provenance: .contentDerived(SourceID("m"))),
            TaintedValue(name: "a", canonicalValue: "1", provenance: .userConfirmed)
        ])
        XCTAssertEqual(reordered.aggregateProvenance, .contentDerived(SourceID("m")))
    }
}

final class SettleIdempotenceTests: XCTestCase {

    /// `record` was hardened against clobbering a settled outcome; `settle` needs
    /// the symmetric guard, or calling it twice inflates `budget.settled` past
    /// what was ever reserved and `outstanding` goes negative-by-clamping.
    func testSettleIsRejectedTheSecondTime() async {
        let clock = ManualClock()
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: AlwaysApprovePresenter(clock: clock),
            clock: clock
        )
        guard case let .allowedCommit(key) = await session.authorize(sameKeyCommit()).decision else {
            return XCTFail("expected admission")
        }
        let first = await session.settle(key, outcome: .executed)
        let second = await session.settle(key, outcome: .failed("late"))
        XCTAssertTrue(first)
        XCTAssertFalse(second, "a second settle must be refused, not applied")

        let snapshot = await session.budgetSnapshot
        XCTAssertEqual(snapshot.settled, 1, "settled must never exceed reserved")
        XCTAssertEqual(snapshot.reserved, 1)

        // And the first outcome stands.
        let retry = await session.authorize(sameKeyCommit())
        XCTAssertEqual(retry.decision, .replayed(.executed))
    }
}
