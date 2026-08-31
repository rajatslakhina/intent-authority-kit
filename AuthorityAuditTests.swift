import XCTest
@testable import IntentAuthority

/// A checker that can only ever pass is decoration. These tests assert both
/// directions: the real policy satisfies every invariant, and two deliberately
/// wrong policies — each wrong in a *different* way — are caught by the specific
/// invariant that exists to catch them.
final class AuthorityAuditTests: XCTestCase {

    private func finding(_ findings: [AuditFinding], _ name: String) -> AuditFinding? {
        findings.first { $0.name == name }
    }

    func testDefaultPolicySatisfiesEveryInvariant() {
        let findings = AuthorityAudit.verify()
        XCTAssertFalse(findings.isEmpty)
        for finding in findings {
            XCTAssertTrue(finding.holds, "\(finding.name): \(finding.detail)")
        }
        XCTAssertTrue(AuthorityAudit.allHold())
    }

    /// "Just ask the user" — the policy a reasonable engineer writes when they
    /// believe a confirmation prompt is protection. It must fail.
    func testPermissivePolicyFailsTheContentTaintInvariant() {
        let findings = AuthorityAudit.verify(policy: PermissiveAuthorizationPolicy())
        XCTAssertFalse(AuthorityAudit.allHold(policy: PermissiveAuthorizationPolicy()))

        let contentCheck = finding(findings, "content-tainted commit is refused")
        XCTAssertNotNil(contentCheck)
        XCTAssertEqual(contentCheck?.holds, false)

        // It also lets a zero-target commit through.
        XCTAssertEqual(finding(findings, "empty-effect commit is refused")?.holds, false)
    }

    /// The subtler failure, and the reason a monotonicity check alone is not
    /// enough: a single-axis policy is perfectly monotone — it just never moves.
    func testSingleAxisPolicyPassesMonotonicityAndStillFails() {
        let policy = SingleAxisAuthorizationPolicy()
        let findings = AuthorityAudit.verify(policy: policy)

        XCTAssertEqual(finding(findings, "content-tainted commit is refused")?.holds, true)
        XCTAssertEqual(finding(findings, "empty-effect commit is refused")?.holds, true)
        XCTAssertEqual(finding(findings, "requirement is monotone in taint floor")?.holds, true,
                       "a constant function is monotone — which is why this check cannot catch it")

        XCTAssertEqual(
            finding(findings, "app-derived commit escalates under content exposure")?.holds, false,
            "the single-axis policy must be caught by the selection-trust invariant"
        )
        XCTAssertFalse(AuthorityAudit.allHold(policy: policy))
    }

    func testLatticeFindingsHold() {
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsCommutative().holds)
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsAssociative().holds)
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsIdempotent().holds)
        XCTAssertTrue(AuthorityAudit.requirementJoinIsOrderIndependent().holds)
    }

    /// The sample set the lattice checks run over must actually contain the cases
    /// that can break the laws.
    ///
    /// This replaces an earlier assertion that the "checked N triples" detail
    /// string contained `n*n*n` — which was vacuous, because it recomputed the
    /// implementation's own expression from the implementation's own count. That
    /// test passed against a checker with the loop deleted. This one does not:
    /// it constrains the *inputs*, which is the thing a gutted checker cannot fake.
    func testLatticeSamplesCoverEveryProvenanceShape() {
        let samples = AuthorityAudit.sampleProvenances
        XCTAssertTrue(samples.contains(.userConfirmed))
        XCTAssertTrue(samples.contains(.appDerived))
        XCTAssertTrue(samples.contains(.plannerAuthored))

        let contentCases = samples.filter { if case .contentDerived = $0 { return true }; return false }
        XCTAssertGreaterThanOrEqual(contentCases.count, 3,
            "need two single-source cases and a multi-source one, or SourceSet union is never exercised")

        var sourceCounts = Set<Int>()
        for case let .contentDerived(set) in samples { sourceCounts.insert(set.sources.count) }
        XCTAssertTrue(sourceCounts.contains(1))
        XCTAssertTrue(sourceCounts.contains(2), "no multi-source sample means union is untested by the audit")
    }

    /// The counterexample check itself: a checker that cannot fail is decoration.
    /// Feed the audit a policy broken in a *known* way and assert it reports that
    /// exact invariant — not merely that something, somewhere, failed.
    func testAuditFailsLoudlyOnAKnownBrokenPolicy() {
        let findings = AuthorityAudit.verify(policy: PermissiveAuthorizationPolicy())
        let failed = Set(findings.filter { !$0.holds }.map(\.name))
        XCTAssertTrue(failed.contains("content-tainted commit is refused"))
        XCTAssertTrue(failed.contains("empty-effect commit is refused"))
        XCTAssertTrue(failed.contains("app-derived commit escalates under content exposure"))
        // And it must not indiscriminately fail everything — the lattice laws are
        // properties of the package, not of the injected policy.
        let held = Set(findings.filter(\.holds).map(\.name))
        XCTAssertTrue(held.contains("provenance join is associative"))
    }
}
