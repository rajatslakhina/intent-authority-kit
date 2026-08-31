import XCTest
@testable import IntentAuthority

final class TaintLatticeTests: XCTestCase {

    private let all = AuthorityAudit.sampleProvenances

    func testJoinTakesTheLeastTrustedInput() {
        XCTAssertEqual(Provenance.userConfirmed.combined(with: .appDerived), .appDerived)
        XCTAssertEqual(Provenance.appDerived.combined(with: .plannerAuthored), .plannerAuthored)
        let tainted = Provenance.contentDerived(SourceID("x"))
        XCTAssertEqual(Provenance.userConfirmed.combined(with: tainted), tainted)
    }

    /// Interpolating an attacker substring into a user-typed template yields a
    /// tainted value without the call site having to remember that.
    func testDerivedValueInheritsWorstProvenance() {
        let template = TaintedValue(
            name: "subject", canonicalValue: "Re: ", provenance: .userConfirmed
        )
        let quoted = TaintedValue(
            name: "quote", canonicalValue: "PAY NOW", provenance: .contentDerived(SourceID("m-1"))
        )
        let composed = template.derived(
            name: "body", canonicalValue: "Re: PAY NOW", combinedWith: [quoted]
        )
        XCTAssertEqual(composed.provenance.contentTrust, .untrusted)
    }

    func testSourceSetsAccumulateAcrossJoins() {
        let a = Provenance.contentDerived(SourceID("inbox-1"))
        let b = Provenance.contentDerived(SourceID("web-7"))
        guard case let .contentDerived(sources) = a.combined(with: b) else {
            return XCTFail("expected contentDerived")
        }
        XCTAssertEqual(sources.sources.map(\.rawValue), ["inbox-1", "web-7"])
    }

    func testEmptyCombinationIsTheLatticeTop() {
        XCTAssertEqual(Provenance.combining([]), .userConfirmed)
    }

    func testLatticeLawsHoldExhaustivelyOverSamples() {
        for a in all {
            XCTAssertEqual(a.combined(with: a), a, "idempotence failed for \(a)")
            for b in all {
                XCTAssertEqual(
                    a.combined(with: b), b.combined(with: a), "commutativity failed for \(a)/\(b)"
                )
                for c in all {
                    XCTAssertEqual(
                        a.combined(with: b).combined(with: c),
                        a.combined(with: b.combined(with: c)),
                        "associativity failed for \(a)/\(b)/\(c)"
                    )
                }
            }
        }
    }

    // MARK: - The two-axis model

    func testUserConfirmedValuesAreExemptFromTheSessionFloor() {
        for floor in TaintFloor.allCases {
            XCTAssertEqual(
                selectionTrust(for: .userConfirmed, under: floor), .authentic,
                "the user's own choice cannot be retroactively poisoned (floor \(floor))"
            )
        }
    }

    /// The asymmetry the package turns on: app-derived bytes stay authentic, but
    /// their *selection* degrades once the session has read untrusted content.
    func testAppDerivedValuesAreNotExemptFromTheSessionFloor() {
        let clean = effectiveTrust(for: .appDerived, under: .clean)
        let exposed = effectiveTrust(for: .appDerived, under: .contentExposed)

        XCTAssertEqual(clean.content, .authentic)
        XCTAssertEqual(exposed.content, .authentic, "our own bytes do not become attacker bytes")

        XCTAssertEqual(clean.selection, .authentic)
        XCTAssertEqual(exposed.selection, .untrusted, "but the planner chose which record")
    }

    func testTaintFloorOnlyRises() {
        XCTAssertEqual(TaintFloor.contentExposed.raised(to: .clean), .contentExposed)
        XCTAssertEqual(TaintFloor.clean.raised(to: .plannerOnly), .plannerOnly)
        XCTAssertEqual(TaintFloor.plannerOnly.raised(to: .contentExposed), .contentExposed)
    }

    func testFloorRaisingIsMonotoneOverEveryPair() {
        for a in TaintFloor.allCases {
            for b in TaintFloor.allCases {
                let raised = a.raised(to: b)
                XCTAssertGreaterThanOrEqual(raised, a)
                XCTAssertGreaterThanOrEqual(raised, b)
                XCTAssertEqual(raised, b.raised(to: a))
            }
        }
    }

    func testParameterSetJoinsDuplicateNamesRatherThanDropping() {
        // A dropped duplicate would drop its taint with it.
        let set = ParameterSet([
            TaintedValue(name: "to", canonicalValue: "Priya", provenance: .userConfirmed),
            TaintedValue(name: "to", canonicalValue: "Priya", provenance: .contentDerived(SourceID("m")))
        ])
        XCTAssertEqual(set.values.count, 1)
        XCTAssertEqual(set.contentTrust, .untrusted)
    }

    func testParameterSetIsOrderIndependent() {
        let a = TaintedValue(name: "a", canonicalValue: "1", provenance: .userConfirmed)
        let b = TaintedValue(name: "b", canonicalValue: "2", provenance: .appDerived)
        XCTAssertEqual(ParameterSet([a, b]), ParameterSet([b, a]))
    }

    /// The two axes deliberately disagree about an empty parameter set, and this
    /// test exists to pin that disagreement down.
    ///
    /// A parameterless intent has no bytes, so there is nothing to distrust on
    /// the content axis. But it is pure planner choice, so on the selection axis
    /// it takes the floor's ceiling like anything else that a human did not
    /// choose. An earlier version of this test asserted `.authentic` on *both*
    /// axes and passed against an implementation that let "pay my balance" run
    /// unprompted in a content-exposed session.
    func testEmptyParameterSetIsCleanOnContentButNotExemptFromTheFloor() {
        let empty = ParameterSet([])

        XCTAssertEqual(empty.contentTrust, .authentic)

        // Clean session: nothing has steered the planner, so nothing to flag.
        XCTAssertEqual(empty.selectionTrust(under: .clean), .authentic)

        // Exposed session: the *decision to invoke at all* is what may have been
        // steered, and there are no parameters to make that visible.
        XCTAssertEqual(empty.selectionTrust(under: .plannerOnly), TaintFloor.plannerOnly.selectionCeiling)
        XCTAssertEqual(empty.selectionTrust(under: .contentExposed), TaintFloor.contentExposed.selectionCeiling)
        XCTAssertNotEqual(empty.selectionTrust(under: .contentExposed), .authentic)
    }

    /// The end-to-end consequence of the above: a parameterless commit in an
    /// exposed session must not be waved through.
    ///
    /// This is the assertion that would have failed against the old behaviour.
    func testParameterlessCommitIsNotWavedThroughInAnExposedSession() {
        let policy = DefaultAuthorizationPolicy()
        let invocation = IntentInvocation(
            descriptor: IntentDescriptor(
                id: IntentID("account.payBalance"),
                tier: .commit,
                effectSummary: "Pay the full statement balance"
            ),
            parameters: ParameterSet([]),
            blastRadius: BlastRadius(resolvedCount: 1)
        )
        let requirement = policy.requirement(
            for: invocation,
            floor: .contentExposed,
            remainingCommitBudget: 10,
            limits: AuthorityLimits()
        )
        XCTAssertNotEqual(requirement, ConfirmationRequirement.none,
                          "A parameterless commit in a content-exposed session must still be gated.")
    }

    func testUntrustedNamesReportsNamesNotValues() {
        let set = ParameterSet([
            TaintedValue(name: "safe", canonicalValue: "ok", provenance: .userConfirmed),
            TaintedValue(
                name: "poisoned", canonicalValue: "ATTACKER TEXT",
                provenance: .contentDerived(SourceID("m"))
            )
        ])
        XCTAssertEqual(set.untrustedNames, ["poisoned"])
    }
}
