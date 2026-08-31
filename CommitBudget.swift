//
//  CommitBudget.swift
//  IntentAuthority
//

/// A session's allowance of admitted commits.
///
/// **The decision that matters is when the allowance is spent.** The obvious
/// implementation decrements on success, which means a planner firing fifty
/// commits that all fail still has its full budget afterwards — the budget stops
/// working precisely against the caller it exists to stop, since a probing
/// planner's calls mostly fail. So the budget is *reserved at admission*, before
/// any work happens, and refunded only on a refusal that provably changed
/// nothing.
///
/// The refund rule is the whole subtlety: a refusal issued *before* the reserve
/// never took the budget in the first place, and a refusal issued *after* the
/// commit may have partially executed, so it is not refundable. Only the middle
/// band — reserved, then refused with no side effect — refunds.
public struct CommitBudget: Sendable, Hashable {
    public private(set) var granted: Int
    public private(set) var reserved: Int
    public private(set) var settled: Int

    public init(granted: Int) {
        self.granted = Saturating.nonNegative(granted)
        self.reserved = 0
        self.settled = 0
    }

    /// Commits that may still be admitted.
    public var remaining: Int {
        Saturating.subtractingClampedToZero(granted, reserved)
    }

    /// Takes one unit if any is left. Returns `false` when exhausted.
    public mutating func reserve() -> Bool {
        guard remaining > 0 else { return false }
        reserved = Saturating.adding(reserved, 1)
        return true
    }

    /// Returns a previously reserved unit. Only valid for a refusal that did no
    /// work; refunding after a partial commit would let a session exceed its
    /// real effect allowance.
    ///
    /// Refunding more than was reserved is a caller bug. It is clamped rather
    /// than trapped, because trapping would turn a bookkeeping mistake into a
    /// crash — but the clamp is the only defence: nothing in `AuthorityAudit`
    /// checks it, because that checker's subject is the *policy*, not the budget.
    /// `BrokerSession` is what keeps reserve/refund/settle paired, and the tests
    /// covering it are the actual guarantee.
    public mutating func refund() {
        reserved = Saturating.subtractingClampedToZero(reserved, 1)
    }

    /// Marks a reserved unit as having actually executed.
    public mutating func settle() {
        settled = Saturating.adding(settled, 1)
    }

    /// Reserved units that were neither refunded nor settled — commits admitted
    /// whose outcome the broker never learned.
    public var outstanding: Int {
        Saturating.subtractingClampedToZero(reserved, settled)
    }
}
