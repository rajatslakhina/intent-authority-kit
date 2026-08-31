//
//  AuthorityAudit.swift
//  IntentAuthority
//

/// One property the package claims, and whether it holds.
public struct AuditFinding: Sendable, Hashable {
    public let name: String
    public let holds: Bool
    public let detail: String

    public init(name: String, holds: Bool, detail: String) {
        self.name = name
        self.holds = holds
        self.detail = detail
    }
}

/// Runnable proof of the properties the README claims.
///
/// Every property below is checked against a policy supplied by the caller, not
/// against a hardcoded one — so pointing it at `PermissiveAuthorizationPolicy`
/// makes it report failures rather than passes. That is the point: a checker
/// that can only ever pass is decoration, and the test suite asserts both
/// directions.
public enum AuthorityAudit {

    /// Sample provenances covering every case, including two distinct content
    /// sources so `SourceSet` union is genuinely exercised.
    public static let sampleProvenances: [Provenance] = [
        .userConfirmed,
        .appDerived,
        .plannerAuthored,
        .contentDerived(SourceID("inbox-message-1")),
        .contentDerived(SourceID("web-page-7")),
        .contentDerived(SourceSet([SourceID("inbox-message-1"), SourceID("web-page-7")])),
        // A set past `SourceSet.capacity`, so the laws are checked where the cap
        // and the truncation flag actually bite. Without this the samples all sit
        // comfortably under the cap and "checked exhaustively" would outrun the
        // evidence — the laws would hold, but not because anything verified them.
        .contentDerived(SourceSet((0..<(SourceSet.capacity + 8)).map { SourceID("bulk-\($0)") }))
    ]

    public static func verify(
        policy: any AuthorizationPolicy = DefaultAuthorizationPolicy(),
        limits: AuthorityLimits = .standard
    ) -> [AuditFinding] {
        [
            provenanceLatticeIsCommutative(),
            provenanceLatticeIsAssociative(),
            provenanceLatticeIsIdempotent(),
            requirementJoinIsOrderIndependent(),
            contentTaintedCommitIsRefused(policy: policy, limits: limits),
            emptyEffectCommitIsRefused(policy: policy, limits: limits),
            requirementIsMonotoneInBlastRadius(policy: policy, limits: limits),
            requirementIsMonotoneInTaintFloor(policy: policy, limits: limits),
            appDerivedCommitEscalatesUnderExposure(policy: policy, limits: limits)
        ]
    }

    public static func allHold(
        policy: any AuthorizationPolicy = DefaultAuthorizationPolicy(),
        limits: AuthorityLimits = .standard
    ) -> Bool {
        verify(policy: policy, limits: limits).allSatisfy(\.holds)
    }

    // MARK: - Lattice laws

    static func provenanceLatticeIsCommutative() -> AuditFinding {
        for a in sampleProvenances {
            for b in sampleProvenances where a.combined(with: b) != b.combined(with: a) {
                return AuditFinding(
                    name: "provenance join is commutative",
                    holds: false,
                    detail: "\(a) ∨ \(b) differs by order"
                )
            }
        }
        return AuditFinding(
            name: "provenance join is commutative",
            holds: true,
            detail: "checked \(sampleProvenances.count * sampleProvenances.count) pairs"
        )
    }

    static func provenanceLatticeIsAssociative() -> AuditFinding {
        for a in sampleProvenances {
            for b in sampleProvenances {
                for c in sampleProvenances {
                    let left = a.combined(with: b).combined(with: c)
                    let right = a.combined(with: b.combined(with: c))
                    if left != right {
                        return AuditFinding(
                            name: "provenance join is associative",
                            holds: false,
                            detail: "(\(a) ∨ \(b)) ∨ \(c) ≠ \(a) ∨ (\(b) ∨ \(c))"
                        )
                    }
                }
            }
        }
        let n = sampleProvenances.count
        return AuditFinding(
            name: "provenance join is associative",
            holds: true,
            detail: "checked \(n * n * n) triples"
        )
    }

    static func provenanceLatticeIsIdempotent() -> AuditFinding {
        for a in sampleProvenances where a.combined(with: a) != a {
            return AuditFinding(
                name: "provenance join is idempotent",
                holds: false,
                detail: "\(a) ∨ \(a) ≠ \(a)"
            )
        }
        return AuditFinding(
            name: "provenance join is idempotent",
            holds: true,
            detail: "checked \(sampleProvenances.count) values"
        )
    }

    static let sampleRequirements: [ConfirmationRequirement] = [
        .none, .verifyEffect, .verifyValue,
        .refuse(.emptyEffect), .refuse(.contentTaintedCommit)
    ]

    /// The property that makes "the checks may run in any order" true rather
    /// than merely intended.
    static func requirementJoinIsOrderIndependent() -> AuditFinding {
        for a in sampleRequirements {
            for b in sampleRequirements {
                if a.combined(with: b) != b.combined(with: a) {
                    return AuditFinding(
                        name: "requirement join is order-independent",
                        holds: false,
                        detail: "commutativity fails for \(a) / \(b)"
                    )
                }
                for c in sampleRequirements {
                    let left = a.combined(with: b).combined(with: c)
                    let right = a.combined(with: b.combined(with: c))
                    if left != right {
                        return AuditFinding(
                            name: "requirement join is order-independent",
                            holds: false,
                            detail: "associativity fails for \(a) / \(b) / \(c)"
                        )
                    }
                }
            }
        }
        return AuditFinding(
            name: "requirement join is order-independent",
            holds: true,
            detail: "commutative and associative over \(sampleRequirements.count) values"
        )
    }

    // MARK: - Policy invariants

    static func invocation(
        tier: EffectTier,
        provenance: Provenance,
        radius: Int,
        intent: String = "test.intent"
    ) -> IntentInvocation {
        IntentInvocation(
            descriptor: IntentDescriptor(
                id: IntentID(intent), tier: tier, effectSummary: "audit probe"
            ),
            parameters: ParameterSet([
                TaintedValue(name: "target", canonicalValue: "value", provenance: provenance)
            ]),
            blastRadius: BlastRadius(resolvedCount: radius)
        )
    }

    /// The package's headline claim. A policy that lets a content-tainted commit
    /// through — even behind a confirmation prompt — fails here.
    static func contentTaintedCommitIsRefused(
        policy: any AuthorizationPolicy,
        limits: AuthorityLimits
    ) -> AuditFinding {
        for floor in TaintFloor.allCases {
            let probe = invocation(
                tier: .commit,
                provenance: .contentDerived(SourceID("attacker-content")),
                radius: 1
            )
            let requirement = policy.requirement(
                for: probe, floor: floor, remainingCommitBudget: limits.commitBudget, limits: limits
            )
            guard case .refuse = requirement else {
                return AuditFinding(
                    name: "content-tainted commit is refused",
                    holds: false,
                    detail: "floor \(floor) returned \(requirement), not a refusal"
                )
            }
        }
        return AuditFinding(
            name: "content-tainted commit is refused",
            holds: true,
            detail: "refused at every taint floor"
        )
    }

    static func emptyEffectCommitIsRefused(
        policy: any AuthorizationPolicy,
        limits: AuthorityLimits
    ) -> AuditFinding {
        let probe = invocation(tier: .commit, provenance: .userConfirmed, radius: 0)
        let requirement = policy.requirement(
            for: probe, floor: .clean, remainingCommitBudget: limits.commitBudget, limits: limits
        )
        guard case .refuse = requirement else {
            return AuditFinding(
                name: "empty-effect commit is refused",
                holds: false,
                detail: "returned \(requirement), not a refusal"
            )
        }
        return AuditFinding(
            name: "empty-effect commit is refused",
            holds: true,
            detail: "zero resolved entities refused"
        )
    }

    /// Widening the blast radius must never make the broker ask for *less*.
    static func requirementIsMonotoneInBlastRadius(
        policy: any AuthorizationPolicy,
        limits: AuthorityLimits
    ) -> AuditFinding {
        let ceiling = min(limits.blastRadiusCeiling, 200)
        guard ceiling >= 1 else {
            return AuditFinding(
                name: "requirement is monotone in blast radius",
                holds: true,
                detail: "ceiling below 1; nothing to check"
            )
        }
        var previous = ConfirmationRequirement.none
        for radius in 1...ceiling {
            let probe = invocation(tier: .commit, provenance: .userConfirmed, radius: radius)
            let requirement = policy.requirement(
                for: probe, floor: .clean, remainingCommitBudget: limits.commitBudget, limits: limits
            )
            if requirement < previous {
                return AuditFinding(
                    name: "requirement is monotone in blast radius",
                    holds: false,
                    detail: "radius \(radius) relaxed \(previous) to \(requirement)"
                )
            }
            previous = requirement
        }
        return AuditFinding(
            name: "requirement is monotone in blast radius",
            holds: true,
            detail: "non-decreasing over radius 1...\(ceiling)"
        )
    }

    /// **The invariant that distinguishes this design from the obvious one.**
    ///
    /// A value the app pulled from its own storage has authentic *content* at
    /// every taint floor — so any policy that reads provenance alone returns the
    /// same answer for it whether or not the session has read attacker content.
    /// That is monotone, and therefore passes the check above, which is exactly
    /// why the check above is not sufficient.
    ///
    /// This one requires a *strict* increase: once the session is content-exposed,
    /// an `.appDerived` commit must be treated more carefully than it was when the
    /// session was clean, because the planner chose which record to name and that
    /// choice is now attacker-influenced.
    ///
    /// `SingleAxisAuthorizationPolicy` fails here and passes everything else.
    static func appDerivedCommitEscalatesUnderExposure(
        policy: any AuthorizationPolicy,
        limits: AuthorityLimits
    ) -> AuditFinding {
        let probe = invocation(tier: .commit, provenance: .appDerived, radius: 1)
        let clean = policy.requirement(
            for: probe, floor: .clean, remainingCommitBudget: limits.commitBudget, limits: limits
        )
        let exposed = policy.requirement(
            for: probe, floor: .contentExposed, remainingCommitBudget: limits.commitBudget, limits: limits
        )
        guard exposed > clean else {
            return AuditFinding(
                name: "app-derived commit escalates under content exposure",
                holds: false,
                detail: "clean=\(clean) exposed=\(exposed) — selection trust is being ignored"
            )
        }
        return AuditFinding(
            name: "app-derived commit escalates under content exposure",
            holds: true,
            detail: "clean=\(clean) → exposed=\(exposed)"
        )
    }

    /// Raising the session taint floor must never make the broker ask for less.
    static func requirementIsMonotoneInTaintFloor(
        policy: any AuthorizationPolicy,
        limits: AuthorityLimits
    ) -> AuditFinding {
        for provenance in sampleProvenances {
            var previous = ConfirmationRequirement.none
            for floor in TaintFloor.allCases.sorted() {
                let probe = invocation(tier: .commit, provenance: provenance, radius: 1)
                let requirement = policy.requirement(
                    for: probe,
                    floor: floor,
                    remainingCommitBudget: limits.commitBudget,
                    limits: limits
                )
                if requirement < previous {
                    return AuditFinding(
                        name: "requirement is monotone in taint floor",
                        holds: false,
                        detail: "floor \(floor) relaxed \(previous) to \(requirement) for \(provenance)"
                    )
                }
                previous = requirement
            }
        }
        return AuditFinding(
            name: "requirement is monotone in taint floor",
            holds: true,
            detail: "non-decreasing over every floor, for every sampled provenance"
        )
    }
}
