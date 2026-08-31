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
/// the *selection* was the planner's. It passes the content-taint check and
/// fails taint-floor monotonicity.
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
