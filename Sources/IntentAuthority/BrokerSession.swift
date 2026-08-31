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
    /// the user, then reserves — so N concurrent invocations all evaluate policy
    /// against the same pre-award balance.
    ///
    /// **It does not over-admit**, because `CommitBudget.reserve()` re-checks
    /// `remaining` and nothing suspends between that check and the record. The
    /// harm is prompt amplification: with a budget of 1 and four concurrent
    /// invocations it raises four confirmations the session can never honour,
    /// where the correct order raises one. Confirmation fatigue is what makes
    /// per-action approval stop working, so an attacker who can manufacture
    /// prompts is attacking the control directly.
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
    private var ingested: Set<SourceID> = []
    private var ingestedTruncated = false

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
    ///
    /// The source is retained, not discarded: the event that raised the floor is
    /// the one a reviewer most wants to see, and a floor with no provenance is a
    /// verdict with no explanation. Bounded like everything else here — past the
    /// cap the set stops growing and `ingestedSourcesTruncated` says so, rather
    /// than letting a planner grow it without limit.
    public func noteContentIngested(from source: SourceID) {
        if ingested.count < limits.ingestedSourceCapacity {
            ingested.insert(source)
        } else if !ingested.contains(source) {
            ingestedTruncated = true
        }
        floor = floor.raised(to: .contentExposed)
    }

    /// Sources whose content entered this session, in canonical order.
    public var ingestedSources: [SourceID] { ingested.sorted() }

    /// True when at least one ingested source was dropped for capacity.
    public var ingestedSourcesTruncated: Bool { ingestedTruncated }

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
            // A policy may refuse an inert tier; the default one never does.
            let decision: BrokerDecision = refusalReason(requirement).map(BrokerDecision.refused)
                ?? .allowedInert
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
        //
        // Three things read before the suspension point can go stale across it,
        // because a prompt is an `await` and this actor accepts other work while
        // one is parked. Two are handled by *claiming* them here; the third
        // cannot be claimed, so it is snapshotted and re-checked afterwards.
        //
        //   1. the commit budget — claimed, or N concurrent invocations all
        //      price themselves against the same pre-award balance;
        //   2. the idempotency key — claimed, or N invocations of the *same*
        //      commit each raise their own prompt for one admission; and
        //   3. the session taint floor — NOT claimable, because raising it is
        //      exactly what a concurrent `noteContentIngested` is entitled to
        //      do while this prompt is up. `requirement` was computed against
        //      the floor as it was at entry; if the floor rises during the
        //      prompt, that requirement is now too weak and the receipt the
        //      user is about to hand back was granted for the wrong question.
        //      See `floorAtEntry` below.
        //
        // Claiming only the budget — which is what this code did until an
        // independent review pointed at the asymmetry — closes the first and
        // leaves the second open, and prompt amplification is precisely the
        // fatigue vector that makes per-action approval stop being a control.
        // A second review pointed at the third: the floor was read, never
        // re-read, and the baton-pass scenario the README leads with could be
        // defeated by winning a race against the prompt.
        var didReserve = false
        if admissionOrder == .reserveBeforeConfirmation {
            guard budget.reserve() else {
                return refuse(.commitBudgetExhausted, now, invocation, requirement, trust, digest)
            }
            didReserve = true
        }

        // Claim the key. A concurrent duplicate now takes the replay path above
        // and is answered from the ledger without ever reaching the user.
        guard idempotency.record(key, outcome: .inFlight, now: now) else {
            if didReserve { budget.refund() }
            return refuse(.ledgerSaturated, now, invocation, requirement, trust, digest)
        }

        // From here on, every failure must release BOTH claims.
        func releaseClaims() {
            if didReserve { budget.refund() }
            idempotency.discard(key)
        }

        // Snapshot the floor the requirement was computed against. Compared, not
        // trusted, once the prompt returns.
        let floorAtEntry = floor

        var receipt: ConfirmationReceipt?
        if requirement != .none {
            // SUSPENSION POINT. Everything read before this line may be stale
            // after it: the budget and the key are claimed above, and the floor
            // is compared against `floorAtEntry` below.
            receipt = await presenter.confirm(
                invocation: invocation, requirement: requirement, sessionID: id
            )
            guard let presented = receipt else {
                releaseClaims()
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
                releaseClaims()
                return refuse(reason, clock.now, invocation, requirement, trust, digest)
            }

            // The floor is monotone, so `floor != floorAtEntry` means it rose.
            // The receipt in hand was granted against a requirement computed
            // under a *lower* floor and cannot be upgraded after the fact — the
            // user answered a weaker question than the one now being asked. The
            // honest move is to refuse and let the caller re-ask under the new
            // floor, which is what a retry will do.
            //
            // Recomputing the requirement here instead would be worse: it would
            // admit on a receipt bound to the old requirement, which is the exact
            // stale-authority bug `ConfirmationReceipt` exists to prevent.
            if floor != floorAtEntry {
                releaseClaims()
                return refuse(
                    .sessionFloorRaisedDuringConfirmation,
                    clock.now, invocation, requirement,
                    // Report the trust as it is *now*, so the audit record is
                    // internally consistent with the floor it also carries.
                    invocation.parameters.effectiveTrust(under: floor),
                    digest
                )
            }
        }

        if admissionOrder == .reserveAfterConfirmation {
            guard budget.reserve() else {
                idempotency.discard(key)
                return refuse(.commitBudgetExhausted, clock.now, invocation, requirement, trust, digest)
            }
            // Deliberately not `didReserve = true`: nothing below this line
            // releases claims, so the flag would be a dead store.
        }

        let admittedAt = clock.now
        let decision = BrokerDecision.allowedCommit(key)
        record(admittedAt, invocation, requirement, decision, trust, digest)
        return AuthorizationResult(
            decision: decision, requirement: requirement, trust: trust, floor: floor
        )
    }

    /// Reports the outcome of an admitted commit.
    ///
    /// Returns `false` if the key was never admitted, which is a caller bug the
    /// broker refuses to paper over — and also if it has already settled, so a
    /// double `settle` cannot inflate `budget.settled` past what was reserved.
    @discardableResult
    public func settle(_ key: IdempotencyKey, outcome: CommitOutcome) -> Bool {
        guard idempotency.recordedOutcome(of: key) == .inFlight else { return false }
        guard idempotency.settle(key, outcome: outcome) else { return false }
        budget.settle()
        return true
    }

    /// Rolls back an admission that provably did nothing — for example, the app
    /// discovered the entity had already been deleted before issuing any call.
    ///
    /// Refuses once the commit has settled, at any age. Refunding budget for a
    /// commit that ran would break the rule `CommitBudget` documents: only a
    /// refusal with no side effect refunds.
    @discardableResult
    public func rollback(_ key: IdempotencyKey) -> Bool {
        guard idempotency.recordedOutcome(of: key) == .inFlight else { return false }
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

