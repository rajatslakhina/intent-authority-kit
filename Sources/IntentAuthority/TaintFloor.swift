//
//  TaintFloor.swift
//  IntentAuthority
//

/// A monotone high-water mark of what the *session* has been exposed to.
///
/// The baton-pass problem, which NowSecure's August 2026 teardown of the iOS 27
/// App Intents surface names as the worst of the three failure modes: when one
/// agent hands off to another inside a session, the downstream agent inherits
/// the full transcript, injection included. If taint lived only on individual
/// parameter values, the handoff would launder it — agent B authors a "fresh"
/// value and it looks clean, because B never touched the poisoned bytes itself.
///
/// So exposure is a property of the session, it only ever rises, and it is
/// inherited across handoff. `.clean` is not recoverable within a session; the
/// only way back is a new session, which is a deliberate design cost.
public enum TaintFloor: Int, Sendable, Hashable, Comparable, CaseIterable {
    /// Nothing but user input and app state has entered the session.
    case clean = 0
    /// A planner has authored content in this session, but has read nothing
    /// untrusted.
    case plannerOnly = 1
    /// The session has ingested content from outside the trust boundary, or has
    /// inherited a transcript from a session that did.
    case contentExposed = 2

    public static func < (lhs: TaintFloor, rhs: TaintFloor) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// The join. Raising the floor is the only permitted transition.
    public func raised(to other: TaintFloor) -> TaintFloor {
        rawValue >= other.rawValue ? self : other
    }
}

extension TaintFloor {

    /// The floor implied by a value's provenance entering the session.
    public static func implied(by provenance: Provenance) -> TaintFloor {
        switch provenance {
        case .userConfirmed, .appDerived: return .clean
        case .plannerAuthored: return .plannerOnly
        case .contentDerived: return .contentExposed
        }
    }

    /// The selection-trust ceiling this floor imposes.
    ///
    /// **The asymmetry that carries the design.** `.userConfirmed` values are
    /// exempt from the floor and handled by the caller
    /// (`selectionTrust(for:under:)`), because a value the user typed themselves
    /// was not selected by the planner and cannot be retroactively poisoned by
    /// what the planner later read.
    ///
    /// `.appDerived` values are deliberately **not** exempt. Their bytes are the
    /// app's own, so their content trust stays `.authentic` — but the planner
    /// chose which record to name, and after the session has read attacker
    /// content that choice is attacker-influenced. This is the case the obvious
    /// single-axis implementation gets wrong: it sees "value came from our own
    /// database" and waves the commit through.
    public var selectionCeiling: SelectionTrust {
        switch self {
        case .clean: return .authentic
        case .plannerOnly: return .unverified
        case .contentExposed: return .untrusted
        }
    }
}

/// Computes the selection-trust of a value with the given provenance in a
/// session standing at the given floor.
public func selectionTrust(for provenance: Provenance, under floor: TaintFloor) -> SelectionTrust {
    // The user picking a value in a system-mediated interface is an act the
    // planner did not perform, so the session floor does not apply to it.
    if case .userConfirmed = provenance {
        return .authentic
    }
    return floor.selectionCeiling
}

/// The full two-axis verdict for a value under a session floor.
public func effectiveTrust(for provenance: Provenance, under floor: TaintFloor) -> EffectiveTrust {
    EffectiveTrust(
        content: provenance.contentTrust,
        selection: selectionTrust(for: provenance, under: floor)
    )
}
