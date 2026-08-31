//
//  AuthorizationPolicy.swift
//  IntentAuthority
//

/// Why the broker refused.
public enum RefusalReason: String, Sendable, Hashable, CaseIterable {
    /// A commit whose parameters carry attacker-authored bytes.
    case contentTaintedCommit
    /// A commit that would affect nothing. Silently succeeding teaches the
    /// planner the call worked and invites it to escalate.
    case emptyEffect
    /// More entities than the app is willing to change in one invocation.
    case blastRadiusExceeded
    /// The session has spent its commit allowance.
    case commitBudgetExhausted
    /// The idempotency ledger cannot record this commit, so replay-safety
    /// cannot be guaranteed.
    case ledgerSaturated
    /// A receipt was required and none was presented.
    case confirmationMissing
    /// A receipt was presented, but for different values than the ones about to
    /// execute.
    case receiptValueMismatch
    /// A receipt was presented, but it was issued for a weaker confirmation than
    /// the one now required.
    case receiptInsufficient
    /// A receipt was presented after its validity window.
    case receiptExpired
    /// A receipt was presented that belongs to a different session.
    case receiptSessionMismatch
}

/// What the user must be asked before a commit proceeds.
///
/// `Comparable` and combined with `max`, so the order in which independent
/// checks run provably cannot change the answer.
public enum ConfirmationRequirement: Sendable, Hashable, Comparable {
    /// Proceed without asking.
    case none
    /// Ask "are you sure?" — validates the verb.
    case verifyEffect
    /// Ask "which one?" — shows the resolved values and validates the noun.
    case verifyValue
    /// Do not proceed at all.
    case refuse(RefusalReason)

    var severity: Int {
        switch self {
        case .none: return 0
        case .verifyEffect: return 1
        case .verifyValue: return 2
        case .refuse: return 3
        }
    }

    public static func < (lhs: ConfirmationRequirement, rhs: ConfirmationRequirement) -> Bool {
        if lhs.severity != rhs.severity { return lhs.severity < rhs.severity }
        // Two refusals of equal severity are ordered by reason so that `max` is
        // a total, deterministic function rather than order-dependent.
        if case let .refuse(a) = lhs, case let .refuse(b) = rhs {
            return a.rawValue < b.rawValue
        }
        return false
    }

    /// Worst-wins join.
    public func combined(with other: ConfirmationRequirement) -> ConfirmationRequirement {
        Swift.max(self, other)
    }

    public var isRefusal: Bool {
        if case .refuse = self { return true }
        return false
    }
}

/// Tunable limits. Compiled into the app, never remotely settable: a single
/// mis-published config field should not be able to lift every commit ceiling in
/// the fleet at once.
public struct AuthorityLimits: Sendable, Hashable {
    /// Entities above which a commit is refused outright.
    public let blastRadiusCeiling: Int
    /// Entities above which a commit requires at least an effect confirmation.
    public let blastRadiusConfirmThreshold: Int
    /// Commits a single session may be admitted for.
    public let commitBudget: Int
    /// How long a confirmation receipt stays valid, in seconds.
    public let receiptValiditySeconds: Double
    /// How long an idempotency record is retained, in seconds. A replay after
    /// this window is treated as a new request, so it must exceed the planner's
    /// own retry horizon.
    public let idempotencyHorizonSeconds: Double
    /// Maximum idempotency records held at once.
    public let idempotencyCapacity: Int
    /// Maximum audit records retained.
    public let auditCapacity: Int

    public init(
        blastRadiusCeiling: Int = 50,
        blastRadiusConfirmThreshold: Int = 1,
        commitBudget: Int = 8,
        receiptValiditySeconds: Double = 120,
        idempotencyHorizonSeconds: Double = 300,
        idempotencyCapacity: Int = 64,
        auditCapacity: Int = 256
    ) {
        self.blastRadiusCeiling = Saturating.nonNegative(blastRadiusCeiling)
        self.blastRadiusConfirmThreshold = Saturating.nonNegative(blastRadiusConfirmThreshold)
        self.commitBudget = Saturating.nonNegative(commitBudget)
        // Non-finite or negative durations would make every freshness comparison
        // read false; clamp at the boundary.
        self.receiptValiditySeconds = AuthorityLimits.sanitised(receiptValiditySeconds, fallback: 120)
        self.idempotencyHorizonSeconds = AuthorityLimits.sanitised(idempotencyHorizonSeconds, fallback: 300)
        self.idempotencyCapacity = max(1, Saturating.nonNegative(idempotencyCapacity))
        self.auditCapacity = max(1, Saturating.nonNegative(auditCapacity))
    }

    static func sanitised(_ value: Double, fallback: Double) -> Double {
        guard value.isFinite, value >= 0, value <= Timestamp.magnitudeLimit else { return fallback }
        return value
    }

    public static let standard = AuthorityLimits()
}

/// Decides what confirmation an invocation needs.
///
/// Injectable so an app can tighten the defaults for its own surface — and so
/// the audit in `AuthorityAudit` can be pointed at *any* policy, including a
/// deliberately broken one, and still tell the truth about it.
public protocol AuthorizationPolicy: Sendable {
    func requirement(
        for invocation: IntentInvocation,
        floor: TaintFloor,
        remainingCommitBudget: Int,
        limits: AuthorityLimits
    ) -> ConfirmationRequirement
}

/// The default policy.
///
/// Five independent checks, joined worst-wins. Each is a pure function of its
/// inputs, so the whole decision is reproducible from an audit record and the
/// evaluation order is provably irrelevant.
public struct DefaultAuthorizationPolicy: AuthorizationPolicy {

    public init() {}

    public func requirement(
        for invocation: IntentInvocation,
        floor: TaintFloor,
        remainingCommitBudget: Int,
        limits: AuthorityLimits
    ) -> ConfirmationRequirement {
        let tier = invocation.descriptor.tier

        // Reads and proposals are inert. A proposal is specifically how a
        // planner in a fully-tainted session is still allowed to be useful: it
        // surfaces a draft the user acts on, and the user's action mints a fresh
        // `.userConfirmed` value with authentic selection trust.
        //
        // Scoping note, stated rather than hidden: a read can still exfiltrate,
        // because its *result* leaves through the planner. Containing that is an
        // egress-policy problem and is deliberately out of scope here; what this
        // package does is record every tainted read in the audit ledger so the
        // exposure is reconstructable after the fact.
        guard tier == .commit else { return .none }

        var requirement = ConfirmationRequirement.none
        for check in [
            contentCheck(invocation),
            selectionCheck(invocation, floor: floor),
            radiusCheck(invocation, limits: limits),
            budgetCheck(remainingCommitBudget)
        ] {
            requirement = requirement.combined(with: check)
        }
        return requirement
    }

    /// **The load-bearing refusal.** You cannot confirm your way out of
    /// content-tainted data, because the confirmation prompt would render the
    /// attacker's string: asking "Send $500 to `<attacker-authored text>`?"
    /// delegates the security decision to a user reading attacker-controlled
    /// copy. Refusal is the only sound answer.
    ///
    /// The cost is real and is named in the README: some legitimate flows get
    /// refused. The escape hatch is re-entry through a system-mediated picker,
    /// which mints a `.userConfirmed` value with authentic content trust.
    private func contentCheck(_ invocation: IntentInvocation) -> ConfirmationRequirement {
        switch invocation.parameters.contentTrust {
        case .untrusted: return .refuse(.contentTaintedCommit)
        case .unverified: return .verifyValue
        case .authentic: return .none
        }
    }

    /// Authentic bytes, attacker-influenced choice. The user must see *which*
    /// entity, not merely be asked whether they are sure — confirming the verb
    /// says nothing about the noun.
    private func selectionCheck(
        _ invocation: IntentInvocation,
        floor: TaintFloor
    ) -> ConfirmationRequirement {
        switch invocation.parameters.selectionTrust(under: floor) {
        case .untrusted: return .verifyValue
        case .unverified: return .verifyEffect
        case .authentic: return .none
        }
    }

    private func radiusCheck(
        _ invocation: IntentInvocation,
        limits: AuthorityLimits
    ) -> ConfirmationRequirement {
        let count = invocation.blastRadius.resolvedCount
        if count == 0 { return .refuse(.emptyEffect) }
        if count > limits.blastRadiusCeiling { return .refuse(.blastRadiusExceeded) }
        if count > limits.blastRadiusConfirmThreshold { return .verifyEffect }
        return .none
    }

    private func budgetCheck(_ remaining: Int) -> ConfirmationRequirement {
        remaining <= 0 ? .refuse(.commitBudgetExhausted) : .none
    }
}
