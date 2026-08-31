import XCTest
@testable import IntentAuthority

final class PolicyTests: XCTestCase {

    private let policy = DefaultAuthorizationPolicy()
    private let limits = AuthorityLimits.standard

    private func requirement(
        tier: EffectTier = .commit,
        provenance: Provenance = .userConfirmed,
        floor: TaintFloor = .clean,
        radius: Int = 1,
        budget: Int? = nil
    ) -> ConfirmationRequirement {
        policy.requirement(
            for: AuthorityAudit.invocation(tier: tier, provenance: provenance, radius: radius),
            floor: floor,
            remainingCommitBudget: budget ?? limits.commitBudget,
            limits: limits
        )
    }

    func testCleanSingleTargetCommitAsksNothing() {
        XCTAssertEqual(requirement(), .none)
    }

    /// The headline refusal. Note this is asserted at *every* floor, including
    /// clean — content taint is a property of the value, not of the session.
    func testContentTaintedCommitIsRefusedAtEveryFloor() {
        for floor in TaintFloor.allCases {
            XCTAssertEqual(
                requirement(provenance: .contentDerived(SourceID("m")), floor: floor),
                .refuse(.contentTaintedCommit)
            )
        }
    }

    func testPlannerAuthoredValueRequiresValueConfirmation() {
        XCTAssertEqual(requirement(provenance: .plannerAuthored), .verifyValue)
    }

    /// Authentic bytes, attacker-influenced choice: show the noun.
    func testAppDerivedValueUnderExposureRequiresValueConfirmation() {
        XCTAssertEqual(requirement(provenance: .appDerived, floor: .contentExposed), .verifyValue)
    }

    func testAppDerivedValueInACleanSessionAsksNothing() {
        XCTAssertEqual(requirement(provenance: .appDerived, floor: .clean), .none)
    }

    func testEmptyEffectCommitIsRefused() {
        XCTAssertEqual(requirement(radius: 0), .refuse(.emptyEffect))
    }

    func testOversizedBlastRadiusIsRefused() {
        XCTAssertEqual(
            requirement(radius: limits.blastRadiusCeiling + 1), .refuse(.blastRadiusExceeded)
        )
    }

    func testMultiTargetCommitRequiresEffectConfirmation() {
        XCTAssertEqual(requirement(radius: 2), .verifyEffect)
    }

    func testExhaustedBudgetIsRefused() {
        XCTAssertEqual(requirement(budget: 0), .refuse(.commitBudgetExhausted))
    }

    func testReadsAndProposalsAreInertEvenWhenFullyTainted() {
        for tier in [EffectTier.read, .propose] {
            XCTAssertEqual(
                requirement(
                    tier: tier, provenance: .contentDerived(SourceID("m")),
                    floor: .contentExposed, radius: 400
                ),
                .none,
                "\(tier) must stay inert — a proposal is how a tainted planner is still useful"
            )
        }
    }

    /// A commit that trips several checks reports the most severe one, and the
    /// answer does not depend on which check ran first.
    func testWorstCheckWinsRegardlessOfOrder() {
        let both = requirement(
            provenance: .contentDerived(SourceID("m")), floor: .contentExposed, radius: 0
        )
        XCTAssertTrue(both.isRefusal)
        // .emptyEffect sorts before .contentTaintedCommit alphabetically, so a
        // deterministic total order is what makes this assertion stable.
        XCTAssertEqual(both, ConfirmationRequirement.refuse(.emptyEffect)
            .combined(with: .refuse(.contentTaintedCommit)))
    }

    func testRequirementSeverityOrdering() {
        XCTAssertLessThan(ConfirmationRequirement.none, .verifyEffect)
        XCTAssertLessThan(ConfirmationRequirement.verifyEffect, .verifyValue)
        XCTAssertLessThan(ConfirmationRequirement.verifyValue, .refuse(.emptyEffect))
    }

    func testJoinIsCommutativeAndAssociativeOverSamples() {
        let samples = AuthorityAudit.sampleRequirements
        for a in samples {
            for b in samples {
                XCTAssertEqual(a.combined(with: b), b.combined(with: a))
                for c in samples {
                    XCTAssertEqual(
                        a.combined(with: b).combined(with: c),
                        a.combined(with: b.combined(with: c))
                    )
                }
            }
        }
    }
}
