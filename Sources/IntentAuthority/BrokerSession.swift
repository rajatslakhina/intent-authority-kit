//
//  BrokerSession.swift
//  IntentAuthority
//

/// What the broker decided.
public enum BrokerDecision: Sendable, Hashable {
    /// Inert tier. Nothing was reserved, nothing needs settling.
    case allowedInert
    /// Commit admitted. The caller must report the outcome via `settle`.
    case allowedCommit(IdempotencyKey)
    /// A commit with this exact key was already admitted inside the retry
    /// horizon; here is what happened to it. The caller must not re-execute.
    case replayed(CommitOutcome)
    /// Policy refused.
    case refused(RefusalReason)
    /// The user was asked and said no.
    case declined
}

/// The full result, including the reasoning, so a caller can surface *why*.
public struct AuthorizationResult: Sendable, Hashable {
    public let decision: BrokerDecision
    public let requirement: ConfirmationRequirement
    public let trust: EffectiveTrust
    public let floor: TaintFloor

    public init(
        decision: BrokerDecision,
        requirement: ConfirmationRequirement,
        trust: EffectiveTrust,
        floor: TaintFloor
    ) {
        self.decision = decision
        self.requirement = requirement
        self.trust = trust
        self.floor = floor
    }
}

/// Controls when the commit budget is taken relative to the confirmation
/// suspension point.
///
/// This exists as a switch for exactly one reason: the wrong order is a real,
/// subtle, actor-reentrancy bug, and shipping both orders lets the test suite
/// drive the *same* actor through the *same* interleaving and show the
/// difference is caused by this decision alone rather than by two separately
/// written implementations that might differ elsewhere.
public enum CommitAdmissionOrder: Sendable, Hashable {
    /// Correct. The budget is taken before `await`ing the user, so a second
    /// invocation arriving during that suspension sees the reduced budget.
    case reserveBeforeConfirmation
    /// Incorrect, and shipped only to be proved wrong. Reads the budget, awaits
    /// the user, then reserves — so N concurrent invocations all observe the
    /// same pre-award balance and the session over-admits.
    case reserveAfterConfirmation
}

/// The authorization broker for one agent session.
///
/// An actor because the state it guards (taint floor, commit budget,
/// idempotency ledger, audit ledger) is mutated from concurrent intent
/// invocations. Actor isolation gives mutual exclusion *between* suspension
/// points and nothing across them, which is exactly the hazard
/// `CommitAdmissionOrder` is about: `await presenter.confirm(...)` is a
/// suspension point in the middle of a check-then-act sequence.
public actor BrokerSession {

    public let id: SessionID
    private let policy: any AuthorizationPolicy
    private let presenter: any ConfirmationPresenter
    private let clock: AuthorityClock
    private let limits: AuthorityLimits
    private let admissionOrder: CommitAdmissionOrder

    private var floor: TaintFloor
    private var budget: CommitBudget
    private var idempotency: IdempotencyLedger
    private var audit: AuditLedger
    private var nonceCounter: UInt64 = 0

    public init(
        id: SessionID,
        policy: any AuthorizationPolicy = DefaultAuthorizationPolicy(),
        presenter: any ConfirmationPresenter,
        clock: AuthorityClock,
        limits: AuthorityLimits = .standard,
        initialFloor: TaintFloor = .clean,
        admissionOrder: CommitAdmissionOrder = .reserveBeforeConfirmation
    ) {
        self.id = id
        self.policy = policy
        self.presenter = presenter
        self.clock = clock
        self.limits = limits
        self.admissionOrder = admissionOrder
        self.floor = initialFloor
        self.budget = CommitBudget(granted: limits.commitBudget)
        self.idempotency = IdempotencyLedger(
            capacity: limits.idempotencyCapacity,
            horizonSeconds: limits.idempotencyHorizonSeconds
        )
        self.audit = AuditLedger(capacity: limits.auditCapacity)
    }

    // MARK: - Session taint

    public var currentFloor: TaintFloor { floor }
    public var remainingCommitBudget: Int { budget.remaining }
    public var budgetSnapshot: CommitBudget { budget }
    public var auditRecords: [AuditRecord] { audit.records }
    public var auditDroppedCount: Int { audit.droppedCount }

    /// Raises the session floor. Monotone: a lower value is ignored, never
    /// applied. There is no way to lower it, by design.
    public func note(exposure: TaintFloor) {
        floor = floor.raised(to: exposure)
    }

    /// Records that untrusted content entered the session.
    public func noteContentIngested(from source: SourceID) {
        _ = source
        floor = floor.raised(to: .contentExposed)
    }

    /// Inherits another agent's session floor on a baton pass.
    ///
    /// The handoff is the taint-propagating event, not the values that cross it:
    /// the downstream agent inherits the full transcript, so it inherits the
    /// exposure that produced it.
    public func inherit(from upstreamFloor: TaintFloor) {
        floor = floor.raised(to: upstreamFloor)
    }

    // MARK: - Authorization

    public func authorize(_ invocation: IntentInvocation) async -> AuthorizationResult {
        let now = clock.now
        let trust = invocation.parameters.effectiveTrust(under: floor)
        let digest = ReceiptBinding.digest(sessionID: id, invocation: invocation)

        // Inert tiers never reserve, never confirm, but are still recorded — a
        // tainted read is the exfiltration path, and the audit trail is the only
        // place it becomes reconstructable.
        guard invocation.descriptor.tier == .commit else {
            let requirement = policy.requirement(
                for: invocation,
                floor: floor,
                remainingCommitBudget: budget.remaining,
                limits: limits
            )
            let decision: BrokerDecision = requirement.isRefusal
                ? .refused(refusalReason(requirement) ?? .contentTaintedCommit)
                : .allowedInert
            record(now, invocation, requirement, decision, trust, digest)
            return AuthorizationResult(
                decision: decision, requirement: requirement, trust: trust, floor: floor
            )
        }

        // Replay check first: a retry must be answered from the ledger before
        // any budget is spent, or a retrying planner drains the allowance.
        let key = IdempotencyKey(sessionID: id, invocation: invocation)
        if let replayed = idempotency.replay(of: key, now: now) {
            let requirement = ConfirmationRequirement.none
            let decision = BrokerDecision.replayed(replayed.outcome)
            record(now, invocation, requirement, decision, trust, digest)
            return AuthorizationResult(
                decision: decision, requirement: requirement, trust: trust, floor: floor
            )
        }

        let requirement = policy.requirement(
            for: invocation,
            floor: floor,
            remainingCommitBudget: budget.remaining,
            limits: limits
        )

        if let reason = refusalReason(requirement) {
            let decision = BrokerDecision.refused(reason)
            record(now, invocation, requirement, decision, trust, digest)
            return AuthorizationResult(
                decision: decision, requirement: requirement, trust: trust, floor: floor
            )
        }

        // ---- The reentrancy-critical region ----
        var didReserve = false
        if admissionOrder == .reserveBeforeConfirmation {
            guard budget.reserve() else {
                return refuse(.commitBudgetExhausted, now, invocation, requirement, trust, digest)
            }
            didReserve = true
        }

        var receipt: ConfirmationReceipt?
        if requirement != .none {
            nonceCounter = Saturating.addingUInt64(nonceCounter, 1)
            // SUSPENSION POINT. Everything read before this line may be stale
            // after it; nothing is re-read from `self` below without being
            // re-validated.
            receipt = await presenter.confirm(
                invocation: invocation, requirement: requirement, sessionID: id
            )
            guard let presented = receipt else {
                if didReserve { budget.refund() }
                let decision = BrokerDecision.declined
                record(clock.now, invocation, requirement, decision, trust, digest)
                return AuthorizationResult(
                    decision: decision, requirement: requirement, trust: trust, floor: floor
                )
            }
            // Re-validated against the invocation about to run, not against what
            // was true when the prompt was raised.
            if let reason = presented.validate(
                against: invocation,
                sessionID: id,
                required: requirement,
                now: clock.now,
                validitySeconds: limits.receiptValiditySeconds
            ) {
                if didReserve { budget.refund() }
                return refuse(reason, clock.now, invocation, requirement, trust, digest)
            }
        }

        if admissionOrder == .reserveAfterConfirmation {
            guard budget.reserve() else {
                return refuse(.commitBudgetExhausted, clock.now, invocation, requirement, trust, digest)
            }
            didReserve = true
        }

        let settleTime = clock.now
        guard idempotency.record(key, outcome: .inFlight, now: settleTime) else {
            if didReserve { budget.refund() }
            return refuse(.ledgerSaturated, settleTime, invocation, requirement, trust, digest)
        }

        let decision = BrokerDecision.allowedCommit(key)
        record(settleTime, invocation, requirement, decision, trust, digest)
        return AuthorizationResult(
            decision: decision, requirement: requirement, trust: trust, floor: floor
        )
    }

    /// Reports the outcome of an admitted commit.
    ///
    /// Returns `false` if the key was never admitted, which is a caller bug the
    /// broker refuses to paper over.
    @discardableResult
    public func settle(_ key: IdempotencyKey, outcome: CommitOutcome) -> Bool {
        guard idempotency.settle(key, outcome: outcome) else { return false }
        budget.settle()
        return true
    }

    /// Rolls back an admission that provably did nothing — for example, the app
    /// discovered the entity had already been deleted before issuing any call.
    ///
    /// Discards the ledger record so a genuine later retry is not answered from
    /// a phantom `inFlight` entry that will never settle, and refunds the budget.
    @discardableResult
    public func rollback(_ key: IdempotencyKey) -> Bool {
        guard idempotency.replay(of: key, now: clock.now) != nil else { return false }
        idempotency.discard(key)
        budget.refund()
        return true
    }

    // MARK: - Helpers

    private func refusalReason(_ requirement: ConfirmationRequirement) -> RefusalReason? {
        if case let .refuse(reason) = requirement { return reason }
        return nil
    }

    private func refuse(
        _ reason: RefusalReason,
        _ now: Timestamp,
        _ invocation: IntentInvocation,
        _ requirement: ConfirmationRequirement,
        _ trust: EffectiveTrust,
        _ digest: StableDigest
    ) -> AuthorizationResult {
        let decision = BrokerDecision.refused(reason)
        record(now, invocation, requirement, decision, trust, digest)
        return AuthorizationResult(
            decision: decision, requirement: requirement, trust: trust, floor: floor
        )
    }

    private func record(
        _ now: Timestamp,
        _ invocation: IntentInvocation,
        _ requirement: ConfirmationRequirement,
        _ decision: BrokerDecision,
        _ trust: EffectiveTrust,
        _ digest: StableDigest
    ) {
        audit.append(
            at: now,
            sessionID: id,
            invocation: invocation,
            floor: floor,
            trust: trust,
            requirement: requirement,
            decision: decision,
            parameterDigest: digest
        )
    }
}

extension Saturating {
    /// Unsigned saturating increment for the receipt nonce counter.
    static func addingUInt64(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let (result, overflow) = a.addingReportingOverflow(b)
        return overflow ? UInt64.max : result
    }
}
