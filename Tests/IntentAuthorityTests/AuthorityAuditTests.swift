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

    /// Guards the guard: if the lattice laws were checked against a hardcoded
    /// answer rather than the real implementation, this would not be possible.
    func testLatticeFindingsAreComputedNotAsserted() {
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsCommutative().holds)
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsAssociative().holds)
        XCTAssertTrue(AuthorityAudit.provenanceLatticeIsIdempotent().holds)
        XCTAssertTrue(AuthorityAudit.requirementJoinIsOrderIndependent().holds)

        // The detail strings report real counts, so a silently-empty sample set
        // cannot masquerade as a pass.
        let n = AuthorityAudit.sampleProvenances.count
        XCTAssertTrue(
            AuthorityAudit.provenanceLatticeIsAssociative().detail.contains("\(n * n * n)")
        )
    }
}
