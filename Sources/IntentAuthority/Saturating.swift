//
//  Saturating.swift
//  IntentAuthority
//
//  Every arithmetic operation in this package that can trap goes through here.
//

/// Clamping integer arithmetic.
///
/// The broker counts things an attacker can influence: how many entities an
/// intent resolved to, how many commits a session has attempted, how many audit
/// records are pending. Swift's `+`, `-` and `*` trap on overflow, so a planner
/// that reports `Int.max` resolved entities would crash the host app rather than
/// be refused by policy. A crash is a worse outcome than a refusal, so every
/// such operation is routed through these helpers and saturates instead.
public enum Saturating {

    /// `a + b`, clamped to the representable range instead of trapping.
    public static func adding(_ a: Int, _ b: Int) -> Int {
        let (result, overflow) = a.addingReportingOverflow(b)
        guard overflow else { return result }
        return b > 0 ? Int.max : Int.min
    }

    /// `a - b`, clamped to the representable range instead of trapping.
    ///
    /// Note the `Int.min` special case: `0 - Int.min` overflows because
    /// `-Int.min` is not representable, which is the same family of bug as
    /// `Int.min / -1`.
    public static func subtracting(_ a: Int, _ b: Int) -> Int {
        let (result, overflow) = a.subtractingReportingOverflow(b)
        guard overflow else { return result }
        return b > 0 ? Int.min : Int.max
    }

    /// `a * b`, clamped to the representable range instead of trapping.
    public static func multiplying(_ a: Int, _ b: Int) -> Int {
        let (result, overflow) = a.multipliedReportingOverflow(by: b)
        guard overflow else { return result }
        // Sign of the true product decides which end we clamp to.
        let negative = (a < 0) != (b < 0)
        return negative ? Int.min : Int.max
    }

    /// `a - b` clamped to zero below, for counters that are meaningless when negative.
    public static func subtractingClampedToZero(_ a: Int, _ b: Int) -> Int {
        max(0, subtracting(a, b))
    }

    /// Clamps an arbitrary integer into a non-negative count.
    public static func nonNegative(_ value: Int) -> Int {
        max(0, value)
    }
}
