//
//  AuditLedger.swift
//  IntentAuthority
//

/// One decision, recorded.
///
/// Carries everything needed to recompute the decision offline: the policy is a
/// pure function of exactly these inputs, so a reviewer investigating a
/// suspicious commit can replay the verdict rather than trusting the log's
/// summary of it.
public struct AuditRecord: Sendable, Hashable {
    public let sequence: Int
    public let at: Timestamp
    public let sessionID: SessionID
    public let intentID: IntentID
    public let tier: EffectTier
    public let floor: TaintFloor
    public let trust: EffectiveTrust
    public let blastRadius: BlastRadius
    public let requirement: ConfirmationRequirement
    public let decision: BrokerDecision
    public let parameterDigest: StableDigest
    /// Names — never values — of parameters whose content was untrusted. Logging
    /// the values would copy attacker-controlled bytes into the audit trail,
    /// which is then rendered in a support tool by someone who trusts it.
    public let untrustedParameterNames: [String]

    public init(
        sequence: Int,
        at: Timestamp,
        sessionID: SessionID,
        intentID: IntentID,
        tier: EffectTier,
        floor: TaintFloor,
        trust: EffectiveTrust,
        blastRadius: BlastRadius,
        requirement: ConfirmationRequirement,
        decision: BrokerDecision,
        parameterDigest: StableDigest,
        untrustedParameterNames: [String]
    ) {
        self.sequence = sequence
        self.at = at
        self.sessionID = sessionID
        self.intentID = intentID
        self.tier = tier
        self.floor = floor
        self.trust = trust
        self.blastRadius = blastRadius
        self.requirement = requirement
        self.decision = decision
        self.parameterDigest = parameterDigest
        self.untrustedParameterNames = untrustedParameterNames
    }
}

/// Bounded, append-only record of broker decisions.
///
/// When full it drops the oldest record and *counts the drop*. A ledger that
/// silently discards is worse than one that admits a gap, because a gap the
/// reader cannot see reads as "nothing happened" — and an attacker who can
/// generate traffic can use that to push their own entry off the end.
public struct AuditLedger: Sendable {
    public private(set) var records: [AuditRecord] = []
    public private(set) var droppedCount: Int = 0
    private var nextSequence: Int = 0
    private let capacity: Int

    public init(capacity: Int) {
        self.capacity = max(1, Saturating.nonNegative(capacity))
    }

    public mutating func append(
        at: Timestamp,
        sessionID: SessionID,
        invocation: IntentInvocation,
        floor: TaintFloor,
        trust: EffectiveTrust,
        requirement: ConfirmationRequirement,
        decision: BrokerDecision,
        parameterDigest: StableDigest
    ) {
        let record = AuditRecord(
            sequence: nextSequence,
            at: at,
            sessionID: sessionID,
            intentID: invocation.descriptor.id,
            tier: invocation.descriptor.tier,
            floor: floor,
            trust: trust,
            blastRadius: invocation.blastRadius,
            requirement: requirement,
            decision: decision,
            parameterDigest: parameterDigest,
            untrustedParameterNames: invocation.parameters.untrustedNames
        )
        nextSequence = Saturating.adding(nextSequence, 1)
        records.append(record)
        while records.count > capacity {
            records.removeFirst()
            droppedCount = Saturating.adding(droppedCount, 1)
        }
    }

    /// Records whose sequence numbers are missing from the retained window.
    /// Non-zero means the ledger is lossy and the reader must say so.
    public var hasGap: Bool { droppedCount > 0 }
}
