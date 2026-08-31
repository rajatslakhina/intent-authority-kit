//
//  Provenance.swift
//  IntentAuthority
//

/// Identifies a body of untrusted content the planner read.
///
/// Opaque and order-comparable so that `SourceSet` can maintain a canonical
/// ordering — a set whose serialisation depends on insertion order would make
/// the parameter digest unstable, which would break receipt binding.
public struct SourceID: Sendable, Hashable, Comparable, CustomStringConvertible {
    public let rawValue: String

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }

    public static func < (lhs: SourceID, rhs: SourceID) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// A canonically-ordered, duplicate-free set of content sources.
///
/// Deliberately not `Set<SourceID>`: the digest encoder walks this in order, and
/// `Set`'s iteration order is not stable across processes.
public struct SourceSet: Sendable, Hashable {

    /// Upper bound on retained sources.
    ///
    /// A `contentDerived` value can be joined with another on every composition,
    /// and a planner controls how many times that happens — so without a cap this
    /// is the one unbounded collection in a package that bounds everything else.
    /// Past the cap the set stops growing and `isTruncated` records that the
    /// attribution is partial, which is a smaller lie than silently dropping it.
    public static let capacity = 32

    public private(set) var sources: [SourceID]
    /// True when at least one source was dropped for capacity.
    public private(set) var isTruncated: Bool

    public init(_ sources: [SourceID] = []) {
        var seen = Set<SourceID>()
        var unique: [SourceID] = []
        for source in sources where seen.insert(source).inserted {
            unique.append(source)
        }
        unique.sort()
        self.isTruncated = unique.count > SourceSet.capacity
        self.sources = Array(unique.prefix(SourceSet.capacity))
    }

    public init(_ single: SourceID) {
        self.sources = [single]
        self.isTruncated = false
    }

    public var isEmpty: Bool { sources.isEmpty }

    /// Set union. Associative, commutative and idempotent — the three properties
    /// `Provenance.combined` inherits and that `AuthorityAudit` verifies.
    /// Equality and hashing cover `sources` only, deliberately.
    ///
    /// `isTruncated` is metadata about how this set was *derived*, not part of
    /// what it *is* — and the parameter digest encodes exactly the sources. If
    /// the flag participated in equality, two values that compare unequal would
    /// produce an identical digest, and a confirmation receipt could not tell
    /// them apart. Keeping identity and the digest in agreement is worth more
    /// than distinguishing a provenance footnote.
    public static func == (lhs: SourceSet, rhs: SourceSet) -> Bool {
        lhs.sources == rhs.sources
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(sources)
    }

    public func union(_ other: SourceSet) -> SourceSet {
        var joined = SourceSet(sources + other.sources)
        // Truncation is sticky: once attribution is partial it stays partial,
        // or the flag would be cleared by a later join that happened to fit.
        if isTruncated || other.isTruncated { joined.isTruncated = true }
        return joined
    }
}

/// Where a parameter value came from.
///
/// This answers exactly one question — *can I trust these bytes?* — and
/// deliberately does not answer *was this value selected for the right reason?*
/// The two are separate, and conflating them is the mistake this package exists
/// to avoid. See `SelectionTrust`.
public enum Provenance: Sendable, Hashable {
    /// The user supplied or picked this value in a system-mediated interface.
    case userConfirmed
    /// The app computed this value from its own storage. The bytes are the
    /// app's own; the *choice* of which record may still be the planner's.
    case appDerived
    /// The planner produced this value, having ingested no untrusted content.
    case plannerAuthored
    /// The planner produced this value from content it read. The bytes are, in
    /// the worst case, chosen by whoever authored that content.
    case contentDerived(SourceSet)

    /// Convenience for the single-source case.
    public static func contentDerived(_ source: SourceID) -> Provenance {
        .contentDerived(SourceSet(source))
    }
}

extension Provenance {

    /// Ordering used by `combined`: lower is less trusted and therefore wins.
    var trustRank: Int {
        switch self {
        case .contentDerived: return 0
        case .plannerAuthored: return 1
        case .appDerived: return 2
        case .userConfirmed: return 3
        }
    }

    /// The join of two provenances in the taint lattice: the result is no more
    /// trusted than the least-trusted input, and content sources accumulate.
    ///
    /// This is what makes taint structural rather than conventional. A value
    /// built by interpolating an attacker-controlled substring into a
    /// user-typed template is `contentDerived`, not `userConfirmed`, without
    /// any call site having to remember that.
    ///
    /// Associative, commutative and idempotent — proved in `AuthorityAudit` and
    /// exercised exhaustively in the test suite.
    public func combined(with other: Provenance) -> Provenance {
        switch (self, other) {
        case let (.contentDerived(a), .contentDerived(b)):
            return .contentDerived(a.union(b))
        case let (.contentDerived(a), _):
            return .contentDerived(a)
        case let (_, .contentDerived(b)):
            return .contentDerived(b)
        default:
            return trustRank <= other.trustRank ? self : other
        }
    }

    /// Folds a sequence of provenances. Empty input is `userConfirmed`, the
    /// lattice's top element — an empty combination adds no taint.
    public static func combining<S: Sequence>(_ provenances: S) -> Provenance
    where S.Element == Provenance {
        provenances.reduce(Provenance.userConfirmed) { $0.combined(with: $1) }
    }
}

/// How much a value's *content* can be trusted.
public enum ContentTrust: Int, Sendable, Hashable, Comparable, CaseIterable {
    /// Bytes are, in the worst case, authored by whoever wrote the content the
    /// planner read. Rendering them in a confirmation prompt shows the user the
    /// attacker's string, which is why this level cannot be confirmed away.
    case untrusted = 0
    /// Bytes were written by the planner with no untrusted input.
    case unverified = 1
    /// Bytes came from the user or from the app's own storage.
    case authentic = 2

    public static func < (lhs: ContentTrust, rhs: ContentTrust) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// How much the *reason this value was selected* can be trusted.
///
/// The distinction that motivates the whole package: a contact record pulled
/// from the app's own address book has authentic content no matter what, but if
/// the planner chose *that* contact after reading an attacker's email, the
/// selection is the poisoned bit. Provenance cannot see this, because provenance
/// is a property of the value and selection is a property of the session.
public enum SelectionTrust: Int, Sendable, Hashable, Comparable, CaseIterable {
    case untrusted = 0
    case unverified = 1
    case authentic = 2

    public static func < (lhs: SelectionTrust, rhs: SelectionTrust) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

extension Provenance {
    /// The content-trust projection of this provenance.
    public var contentTrust: ContentTrust {
        switch self {
        case .userConfirmed, .appDerived: return .authentic
        case .plannerAuthored: return .unverified
        case .contentDerived: return .untrusted
        }
    }
}

/// The two-axis verdict for a single parameter.
public struct EffectiveTrust: Sendable, Hashable {
    public let content: ContentTrust
    public let selection: SelectionTrust

    public init(content: ContentTrust, selection: SelectionTrust) {
        self.content = content
        self.selection = selection
    }
}
