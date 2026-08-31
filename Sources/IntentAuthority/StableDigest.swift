//
//  StableDigest.swift
//  IntentAuthority
//

/// A 64-bit digest that is stable across processes, launches and platforms.
///
/// **Why this is hand-rolled rather than `Hashable`.** Swift seeds `Hasher` with
/// a per-process random value, so `hashValue` for the same input differs between
/// two launches of the same binary. A confirmation receipt keyed on `hashValue`
/// would stop matching the moment the app is relaunched — and relaunch is
/// precisely the window a retry aims at, so the failure lands exactly where the
/// mechanism is needed. Worse, a test suite cannot catch it, because a test
/// suite runs in a single process where `hashValue` *is* self-consistent.
///
/// The algorithm is FNV-1a/64 (offset basis `0xcbf29ce484222325`, prime
/// `0x100000001b3`), chosen because it is short enough to audit by eye and has a
/// specification independent of this package, so the test suite can check the
/// output against a second implementation rather than against itself.
///
/// This is a *binding* digest, not a security primitive. It defends a
/// confirmation receipt against accidental drift between what the user was shown
/// and what is about to execute. It is not collision-resistant and must not be
/// used where an adversary can grind inputs; the honest upgrade is SHA-256 via
/// CryptoKit, which is deliberately not taken here so the package stays
/// dependency-free and Linux-testable.
public struct StableDigest: Sendable, Hashable, CustomStringConvertible {

    public static let offsetBasis: UInt64 = 0xcbf2_9ce4_8422_2325
    public static let prime: UInt64 = 0x0000_0100_0000_01b3

    public let value: UInt64

    public init(value: UInt64) {
        self.value = value
    }

    public var description: String {
        // Zero-padded lowercase hex, stable width for display and logging.
        let hex = String(value, radix: 16)
        // `UInt64` is at most 16 hex digits, so the pad is never negative; the
        // clamp is here so the invariant is enforced rather than assumed.
        let padding = Saturating.subtractingClampedToZero(16, hex.count)
        return String(repeating: "0", count: padding) + hex
    }
}

/// Accumulates bytes into a `StableDigest`.
///
/// Every field is length-prefixed. Without that, `["ab": "c"]` and
/// `["a": "bc"]` serialise to the same byte stream and therefore collide, which
/// would let a planner move a character across a field boundary and still
/// present a receipt that matches.
public struct StableDigestHasher {

    private var state: UInt64 = StableDigest.offsetBasis

    public init(domain: String) {
        // Domain separation: digests computed for different purposes must never
        // be interchangeable, so each starts from a distinct state.
        combine(bytes: Array(domain.utf8))
    }

    /// Wrapping arithmetic is intentional here and is the specified behaviour of
    /// FNV-1a; it is not an overflow bug.
    public mutating func combine(byte: UInt8) {
        state ^= UInt64(byte)
        state = state &* StableDigest.prime
    }

    public mutating func combine(bytes: [UInt8]) {
        // Length prefix, little-endian, fixed 8 bytes.
        combine(rawUInt64: UInt64(bytes.count))
        for byte in bytes {
            combine(byte: byte)
        }
    }

    /// Combines a raw 64-bit value with no length prefix of its own.
    public mutating func combine(rawUInt64 value: UInt64) {
        var remaining = value
        for _ in 0..<8 {
            combine(byte: UInt8(truncatingIfNeeded: remaining))
            remaining >>= 8
        }
    }

    public mutating func combine(string: String) {
        combine(bytes: Array(string.utf8))
    }

    /// Combines a non-negative count. Negative input is clamped to zero rather
    /// than trapping on the `UInt64` conversion.
    public mutating func combine(count: Int) {
        combine(rawUInt64: UInt64(Saturating.nonNegative(count)))
    }

    public func finalized() -> StableDigest {
        StableDigest(value: state)
    }
}

extension Provenance {
    /// A stable tag byte sequence for digest encoding.
    ///
    /// Encoded structurally rather than via `String(describing:)`, which is not
    /// a stable format across compiler versions.
    var digestTag: String {
        switch self {
        case .userConfirmed: return "u"
        case .appDerived: return "a"
        case .plannerAuthored: return "p"
        case .contentDerived: return "c"
        }
    }

    func combine(into hasher: inout StableDigestHasher) {
        hasher.combine(string: digestTag)
        if case let .contentDerived(sources) = self {
            hasher.combine(count: sources.sources.count)
            for source in sources.sources {
                hasher.combine(string: source.rawValue)
            }
        } else {
            hasher.combine(count: 0)
        }
    }
}
