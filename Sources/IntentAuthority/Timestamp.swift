//
//  Timestamp.swift
//  IntentAuthority
//

/// A validated point in time, in seconds since an unspecified fixed epoch.
///
/// This is a value type rather than `Date` for two reasons. The obvious one is
/// that the package must build and be fully testable on Linux with nothing but
/// the Swift standard library. The load-bearing one is validation: the broker
/// subtracts timestamps to decide whether a confirmation receipt is still fresh
/// and whether an idempotency record has aged past the retry horizon, and both
/// of those comparisons are silently wrong if a `NaN` reaches them — every
/// comparison against `NaN` is `false`, so a `NaN` receipt age reads as
/// "not expired" and a `NaN` ledger age reads as "not evictable".
///
/// Rejecting non-finite and absurd values *at the type boundary* means no call
/// site downstream has to defend against them.
public struct Timestamp: Sendable, Hashable, Comparable {

    /// Largest magnitude accepted, in seconds. Roughly 31.7 million years, which
    /// is far outside any plausible clock and far inside the range where
    /// `a - b` can round to infinity.
    public static let magnitudeLimit: Double = 1e15

    public let secondsSinceEpoch: Double

    /// Fails for `NaN`, infinities, and values whose magnitude is large enough
    /// that differencing two of them could overflow to infinity.
    public init?(secondsSinceEpoch: Double) {
        guard secondsSinceEpoch.isFinite else { return nil }
        guard abs(secondsSinceEpoch) <= Timestamp.magnitudeLimit else { return nil }
        self.secondsSinceEpoch = secondsSinceEpoch
    }

    /// The origin of the timeline. Always valid.
    public static let zero = Timestamp(secondsSinceEpoch: 0)!

    /// Seconds elapsed from `earlier` to `self`. Negative if `self` precedes it.
    ///
    /// Always finite: both operands are bounded by `magnitudeLimit`, so the
    /// difference is bounded by `2 * magnitudeLimit`.
    public func seconds(since earlier: Timestamp) -> Double {
        secondsSinceEpoch - earlier.secondsSinceEpoch
    }

    /// Returns a timestamp `interval` seconds later, or `nil` if that would
    /// leave the representable range.
    public func advanced(bySeconds interval: Double) -> Timestamp? {
        guard interval.isFinite else { return nil }
        return Timestamp(secondsSinceEpoch: secondsSinceEpoch + interval)
    }

    public static func < (lhs: Timestamp, rhs: Timestamp) -> Bool {
        lhs.secondsSinceEpoch < rhs.secondsSinceEpoch
    }
}

/// Supplies the current time.
///
/// This is a seam, not test scaffolding: a host app running against a mocked
/// clock is how receipt-expiry and retry-horizon behaviour becomes reproducible
/// in its own test suite, so `ManualClock` is shipped as product API.
public protocol AuthorityClock: Sendable {
    var now: Timestamp { get }
}

/// A clock the caller advances by hand. Deterministic; no real time passes.
public final class ManualClock: AuthorityClock, @unchecked Sendable {
    private let lock = Mutex()
    private var current: Timestamp

    public init(start: Timestamp = .zero) {
        self.current = start
    }

    public var now: Timestamp {
        lock.withLock { current }
    }

    /// Advances the clock. A non-finite or out-of-range interval is ignored
    /// rather than trapping, and the clock never moves backwards.
    public func advance(bySeconds interval: Double) {
        guard interval.isFinite, interval >= 0 else { return }
        lock.withLock {
            if let next = current.advanced(bySeconds: interval) {
                current = next
            }
        }
    }
}
