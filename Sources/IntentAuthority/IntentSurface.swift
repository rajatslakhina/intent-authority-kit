//
//  IntentSurface.swift
//  IntentAuthority
//

/// A single parameter carrying its provenance.
public struct TaintedValue: Sendable, Hashable {
    public let name: String
    /// The canonical string form the digest is computed over and the user is shown.
    public let canonicalValue: String
    public let provenance: Provenance

    public init(name: String, canonicalValue: String, provenance: Provenance) {
        self.name = name
        self.canonicalValue = canonicalValue
        self.provenance = provenance
    }

    /// Derives a new value from this one and others, joining provenance.
    ///
    /// The only supported way to build a composite value. Constructing a
    /// composite by hand and re-declaring its provenance is how taint gets
    /// laundered, so this is the affordance that makes the safe path the easy one.
    public func derived(
        name: String,
        canonicalValue: String,
        combinedWith others: [TaintedValue]
    ) -> TaintedValue {
        let joined = Provenance.combining([provenance] + others.map(\.provenance))
        return TaintedValue(name: name, canonicalValue: canonicalValue, provenance: joined)
    }
}

/// The resolved parameters of one intent invocation.
///
/// Canonicalised on construction: sorted by name, duplicates resolved by joining
/// provenance rather than by last-one-wins, so two orderings of the same
/// parameters always produce the same digest.
public struct ParameterSet: Sendable, Hashable {
    public private(set) var values: [TaintedValue]

    public init(_ values: [TaintedValue]) {
        var merged: [String: TaintedValue] = [:]
        for value in values {
            if let existing = merged[value.name] {
                // A duplicate name is a planner error, but silently dropping one
                // of them would drop its taint with it. Join instead.
                merged[value.name] = TaintedValue(
                    name: value.name,
                    canonicalValue: existing.canonicalValue,
                    provenance: existing.provenance.combined(with: value.provenance)
                )
            } else {
                merged[value.name] = value
            }
        }
        self.values = merged.values.sorted { $0.name < $1.name }
    }

    public var isEmpty: Bool { values.isEmpty }

    /// The join of every parameter's provenance. An empty set joins to
    /// `userConfirmed`, the lattice identity — but note that
    /// `selectionTrust(under:)` does *not* read this: an empty set is still
    /// subject to the session floor. See that method for why.
    public var aggregateProvenance: Provenance {
        Provenance.combining(values.map(\.provenance))
    }

    /// The weakest content trust across all parameters.
    ///
    /// An empty set is `.authentic`, and that default is correct on this axis:
    /// no bytes really does mean no attacker-authored bytes.
    public var contentTrust: ContentTrust {
        values.map(\.provenance.contentTrust).min() ?? .authentic
    }

    /// The weakest selection trust across all parameters, under a session floor.
    ///
    /// **An empty set is not exempt from the floor.** It takes
    /// `floor.selectionCeiling`, the same ceiling every non-`userConfirmed`
    /// parameter takes.
    ///
    /// This is the opposite of the content axis above, and the asymmetry is the
    /// whole point of having two axes. A parameterless intent — "pay my
    /// balance", "clear my inbox", "unlock the door", which is the most common
    /// shape in App Intents — has no bytes to distrust, but it is *pure planner
    /// choice*: nothing about it was decided by a human, and after the session
    /// has read attacker-controlled content, the decision to invoke it at all is
    /// exactly what may have been steered. Returning `.authentic` here would
    /// hand the planner the `.userConfirmed` exemption without anyone having
    /// confirmed anything, and would silently wave through the single case this
    /// library exists to catch.
    ///
    /// An earlier version returned `.authentic` and a test asserted it as
    /// intended; both were wrong.
    public func selectionTrust(under floor: TaintFloor) -> SelectionTrust {
        values.map { IntentAuthority.selectionTrust(for: $0.provenance, under: floor) }.min()
            ?? floor.selectionCeiling
    }

    public func effectiveTrust(under floor: TaintFloor) -> EffectiveTrust {
        EffectiveTrust(content: contentTrust, selection: selectionTrust(under: floor))
    }

    /// Parameters whose content is untrusted — the ones a confirmation prompt
    /// must not render.
    public var untrustedNames: [String] {
        values.filter { $0.provenance.contentTrust == .untrusted }.map(\.name)
    }
}

/// What an intent does to the world.
///
/// The tier belongs to the *effect*, not to the intent's name. Two intents that
/// both "archive" are the same tier; the same intent invoked over one entity and
/// over four hundred is the same tier with a different blast radius.
public enum EffectTier: Int, Sendable, Hashable, Comparable, CaseIterable {
    /// Returns information. Changes nothing.
    case read = 0
    /// Produces a draft or suggestion the user must act on separately. Inert.
    case propose = 1
    /// Changes state the user or a third party can observe. Not undoable by the broker.
    case commit = 2

    public static func < (lhs: EffectTier, rhs: EffectTier) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// How many entities an invocation actually resolved to.
///
/// A separate type because the number arrives from the planner and is therefore
/// attacker-influenced: it is validated here rather than at each call site, and
/// it saturates rather than trapping.
public struct BlastRadius: Sendable, Hashable, Comparable {
    public let resolvedCount: Int

    public init(resolvedCount: Int) {
        self.resolvedCount = Saturating.nonNegative(resolvedCount)
    }

    public static let none = BlastRadius(resolvedCount: 0)
    public static let single = BlastRadius(resolvedCount: 1)

    public static func < (lhs: BlastRadius, rhs: BlastRadius) -> Bool {
        lhs.resolvedCount < rhs.resolvedCount
    }
}

/// Identifies an intent in the app's surface.
public struct IntentID: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public var description: String { rawValue }
}

/// One intent as the broker sees it.
public struct IntentDescriptor: Sendable, Hashable {
    public let id: IntentID
    public let tier: EffectTier
    /// Human-readable effect summary, shown in a confirmation prompt. Authored
    /// by the app, never by the planner — a planner-authored summary would let
    /// the attacker write the confirmation text.
    public let effectSummary: String

    public init(id: IntentID, tier: EffectTier, effectSummary: String) {
        self.id = id
        self.tier = tier
        self.effectSummary = effectSummary
    }
}

/// A complete request from the planner to the broker.
public struct IntentInvocation: Sendable, Hashable {
    public let descriptor: IntentDescriptor
    public let parameters: ParameterSet
    public let blastRadius: BlastRadius

    public init(
        descriptor: IntentDescriptor,
        parameters: ParameterSet,
        blastRadius: BlastRadius
    ) {
        self.descriptor = descriptor
        self.parameters = parameters
        self.blastRadius = blastRadius
    }
}
