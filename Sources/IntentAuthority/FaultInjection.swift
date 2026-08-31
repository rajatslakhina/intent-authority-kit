//
//  FaultInjection.swift
//  IntentAuthority
//
//  Deliberately-wrong implementations, shipped in the library rather than hidden
//  in the test target, for two reasons. First, the demo app can trigger the
//  failure live so a reviewer sees the bug rather than reading a claim about it.
//  Second, `AuthorityAudit` is only meaningful if something can make it fail, and
//  a checker whose counterexample lives in a test target cannot be pointed at by
//  anyone reading the library.
//

/// A policy that waves everything through.
///
/// Not a straw man: this is what a reasonable engineer writes when they believe
/// a confirmation prompt is sufficient protection — "ask the user and let them
/// decide". `AuthorityAudit` reports exactly which invariants it breaks.
public struct PermissiveAuthorizationPolicy: AuthorizationPolicy {
    public init() {}

    public func requirement(
        for invocation: IntentInvocation,
        floor: TaintFloor,
        remainingCommitBudget: Int,
        limits: AuthorityLimits
    ) -> ConfirmationRequirement {
        invocation.descriptor.tier == .commit ? .verifyEffect : .none
    }
}

/// A policy that trusts the app's own storage unconditionally.
///
/// The single-axis mistake in its purest form: it reads provenance, sees
/// `.appDerived`, concludes "our data, therefore safe", and never asks whether
/// the *selection* was the planner's.
///
/// It refuses content-tainted commits correctly, and — because it ignores the
/// floor entirely — it is a *constant* function of the floor, so it **passes**
/// `requirementIsMonotoneInTaintFloor`. A constant function is monotone. The one
/// invariant it fails is `appDerivedCommitEscalatesUnderExposure`, which is
/// exactly why that invariant exists.
public struct SingleAxisAuthorizationPolicy: AuthorizationPolicy {
    public init() {}

    public func requirement(
        for invocation: IntentInvocation,
        floor: TaintFloor,
        remainingCommitBudget: Int,
        limits: AuthorityLimits
    ) -> ConfirmationRequirement {
        guard invocation.descriptor.tier == .commit else { return .none }
        if invocation.blastRadius.resolvedCount == 0 { return .refuse(.emptyEffect) }
        switch invocation.parameters.contentTrust {
        case .untrusted: return .refuse(.contentTaintedCommit)
        case .unverified: return .verifyEffect
        case .authentic: return .none
        }
    }
}

/// Approves everything immediately.
public struct AlwaysApprovePresenter: ConfirmationPresenter {
    private let clock: AuthorityClock
    public init(clock: AuthorityClock) { self.clock = clock }

    public func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt? {
        ReceiptIssuer(clock: clock).issue(
            sessionID: sessionID, invocation: invocation, granted: requirement, nonce: 0
        )
    }
}

/// Declines everything.
public struct AlwaysDeclinePresenter: ConfirmationPresenter {
    public init() {}
    public func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt? { nil }
}

/// Returns a receipt bound to a *different* invocation than the one being
/// authorized.
///
/// This models the attack the parameter digest exists to stop: a confirmation
/// obtained for "send £5 to Alice" being replayed against "send £5000 to Mallory".
/// It exists because without it, `BrokerSession`'s receipt-validation branch was
/// unreachable in the whole test suite — every shipped presenter returned either
/// `nil` or a correctly-bound receipt, so deleting the branch outright left all
/// tests green. A fault injector that can only produce valid output is not a
/// fault injector.
public struct MisboundReceiptPresenter: ConfirmationPresenter {
    private let clock: AuthorityClock
    private let substitute: IntentInvocation

    /// - Parameter substitute: the invocation the receipt will actually be bound
    ///   to, which must differ from the one presented for it to be a fault.
    public init(clock: AuthorityClock, substitute: IntentInvocation) {
        self.clock = clock
        self.substitute = substitute
    }

    public func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt? {
        // Note it grants exactly what was asked for and is issued now, in this
        // session: the *only* thing wrong with it is the digest. Anything else
        // would let the test pass for the wrong reason.
        ReceiptIssuer(clock: clock).issue(
            sessionID: sessionID, invocation: substitute, granted: requirement, nonce: 0
        )
    }
}

/// Returns a receipt that grants strictly less than was required.
///
/// A user who answered "are you sure?" has not answered "which one?", and a
/// receipt cannot be promoted after the fact.
public struct UndergrantingReceiptPresenter: ConfirmationPresenter {
    private let clock: AuthorityClock
    private let grants: ConfirmationRequirement

    public init(clock: AuthorityClock, grants: ConfirmationRequirement) {
        self.clock = clock
        self.grants = grants
    }

    public func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt? {
        ReceiptIssuer(clock: clock).issue(
            sessionID: sessionID, invocation: invocation, granted: grants, nonce: 0
        )
    }
}

/// A presenter whose first `confirm` parks until released.
///
/// This is the concurrent writer that makes the reentrancy test real: without
/// something that genuinely holds the actor's suspension point open while a
/// second invocation enters, a "concurrency test" only proves the code runs
/// twice in sequence.
public actor BarrierConfirmationPresenter: ConfirmationPresenter {

    private let clock: AuthorityClock
    private var parkedContinuations: [CheckedContinuation<Void, Never>] = []
    private var arrivals = 0
    private var released = false
    private var waitersForArrival: [(count: Int, continuation: CheckedContinuation<Void, Never>)] = []

    public init(clock: AuthorityClock) {
        self.clock = clock
    }

    public var arrivalCount: Int { arrivals }

    public func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt? {
        arrivals = Saturating.adding(arrivals, 1)
        signalArrivalWaiters()

        if !released {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                parkedContinuations.append(continuation)
            }
        }

        return ReceiptIssuer(clock: clock).issue(
            sessionID: sessionID, invocation: invocation, granted: requirement, nonce: 0
        )
    }

    /// Suspends until at least `count` invocations have reached the barrier.
    public func waitForArrivals(_ count: Int) async {
        if arrivals >= count { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waitersForArrival.append((count, continuation))
        }
    }

    /// Releases everyone parked, and lets later arrivals through immediately.
    public func release() {
        released = true
        let parked = parkedContinuations
        parkedContinuations.removeAll()
        for continuation in parked {
            continuation.resume()
        }
    }

    private func signalArrivalWaiters() {
        let satisfied = waitersForArrival.filter { arrivals >= $0.count }
        waitersForArrival.removeAll { arrivals >= $0.count }
        for waiter in satisfied {
            waiter.continuation.resume()
        }
    }
}
