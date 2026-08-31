import XCTest
@testable import IntentAuthority
@testable import IntentAuthorityUI

/// The seven-row table in both READMEs is generated from this catalog. Without
/// these tests, a policy change could silently make the published table wrong —
/// the worst outcome for a repo whose whole pitch is "the verdicts are computed,
/// not asserted."
final class ScenarioCatalogTests: XCTestCase {

    /// The demo app compiles these in; they must match or the table is a lie.
    private let limits = AuthorityLimits(
        blastRadiusCeiling: 50,
        blastRadiusConfirmThreshold: 1,
        commitBudget: 4
    )
    private let policy = DefaultAuthorizationPolicy()

    private func requirement(for scenario: AuthorityScenario) -> ConfirmationRequirement {
        policy.requirement(
            for: scenario.invocation,
            floor: scenario.floor,
            remainingCommitBudget: limits.commitBudget,
            limits: limits
        )
    }

    private func scenario(_ id: String) throws -> AuthorityScenario {
        try XCTUnwrap(AuthorityScenario.catalog.first { $0.id == id }, "no scenario \(id)")
    }

    func testCatalogHasSevenDistinctScenarios() {
        XCTAssertEqual(AuthorityScenario.catalog.count, 7)
        XCTAssertEqual(Set(AuthorityScenario.catalog.map(\.id)).count, 7)
    }

    /// Every verdict printed in the READMEs, pinned.
    func testEveryPublishedVerdictStillHolds() throws {
        let expected: [String: ConfirmationRequirement] = [
            "clean-commit": .none,
            "planner-authored": .verifyValue,
            "content-derived": .refuse(.contentTaintedCommit),
            "baton-pass": .verifyValue,
            "multi-target": .verifyEffect,
            "blast-radius": .refuse(.blastRadiusExceeded),
            "tainted-read": .none
        ]
        for (id, want) in expected {
            XCTAssertEqual(try requirement(for: scenario(id)), want, "scenario \(id)")
        }
    }

    /// The catalog must exercise all three tiers of requirement and more than one
    /// refusal reason, or "the table shows the broker's full range" is marketing.
    func testCatalogCoversEveryRequirementTierAndTwoRefusalReasons() {
        let requirements = AuthorityScenario.catalog.map(requirement(for:))
        XCTAssertTrue(requirements.contains(.none))
        XCTAssertTrue(requirements.contains(.verifyEffect))
        XCTAssertTrue(requirements.contains(.verifyValue))
        let reasons = Set(requirements.compactMap { req -> RefusalReason? in
            if case let .refuse(reason) = req { return reason }
            return nil
        })
        XCTAssertGreaterThanOrEqual(reasons.count, 2, "one refusal reason is not a range")
    }

    /// The baton pass is the scenario both READMEs lead with. It only makes its
    /// point if the parameter is genuinely clean and the floor is genuinely high.
    func testBatonPassIsCleanBytesUnderAnExposedFloor() throws {
        let s = try scenario("baton-pass")
        XCTAssertEqual(s.floor, .contentExposed)
        XCTAssertEqual(s.invocation.parameters.contentTrust, .authentic,
                       "the bytes must be trustworthy, or this is just the content-derived case again")
        XCTAssertNotEqual(s.invocation.parameters.selectionTrust(under: s.floor), .authentic,
                          "the selection axis is the only thing that can flag this")
    }

    /// Regression for a blank panel: every scenario must be able to explain its
    /// own floor, and every exposed one must name a real source.
    func testEveryScenarioExplainsItsFloor() {
        for s in AuthorityScenario.catalog {
            XCTAssertFalse(s.floorOrigin.isEmpty, "scenario \(s.id) cannot explain its floor")
            if s.floor == .contentExposed {
                XCTAssertFalse(s.exposedBy.isEmpty,
                               "scenario \(s.id) is exposed but names no source")
            } else {
                XCTAssertTrue(s.exposedBy.isEmpty,
                              "scenario \(s.id) names an ingested source but is not exposed")
            }
        }
        // And the sources are distinct, so the panel's lines disambiguate.
        let named = AuthorityScenario.catalog.flatMap(\.exposedBy).map(\.rawValue)
        XCTAssertEqual(Set(named).count, named.count, "exposure labels must not collide")
    }

    /// Replaying `exposedBy` through a real session must produce the declared
    /// floor. This is what lets the console start clean and derive it.
    func testReplayingExposureProducesTheDeclaredFloor() async throws {
        for s in AuthorityScenario.catalog where !s.exposedBy.isEmpty {
            let clock = ManualClock()
            let session = BrokerSession(
                id: SessionID("t-\(s.id)"),
                presenter: AlwaysDeclinePresenter(),
                clock: clock,
                initialFloor: .clean
            )
            for source in s.exposedBy { await session.noteContentIngested(from: source) }
            let derived = await session.currentFloor
            XCTAssertEqual(derived, s.floor, "scenario \(s.id) derived \(derived), declares \(s.floor)")
            let retained = await session.ingestedSources
            XCTAssertEqual(retained.map(\.rawValue), s.exposedBy.map(\.rawValue))
        }
    }
}
