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
