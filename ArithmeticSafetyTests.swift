import XCTest
@testable import IntentAuthority

/// Every value in this package that an attacker can influence is a count, and
/// Swift's integer operators trap on overflow. A crashed host app is a worse
/// outcome than a refused intent, so these paths saturate.
final class ArithmeticSafetyTests: XCTestCase {

    func testAdditionSaturatesAtBothEnds() {
        XCTAssertEqual(Saturating.adding(Int.max, 1), Int.max)
        XCTAssertEqual(Saturating.adding(Int.max, Int.max), Int.max)
        XCTAssertEqual(Saturating.adding(Int.min, -1), Int.min)
        XCTAssertEqual(Saturating.adding(2, 3), 5)
    }

    func testSubtractionSaturatesIncludingTheIntMinNegationCase() {
        XCTAssertEqual(Saturating.subtracting(Int.min, 1), Int.min)
        // `0 - Int.min` overflows because `-Int.min` is not representable — the
        // same family of bug as `Int.min / -1`.
        XCTAssertEqual(Saturating.subtracting(0, Int.min), Int.max)
        XCTAssertEqual(Saturating.subtracting(5, 3), 2)
    }

    func testMultiplicationSaturatesWithCorrectSign() {
        XCTAssertEqual(Saturating.multiplying(Int.max, 2), Int.max)
        XCTAssertEqual(Saturating.multiplying(Int.max, -2), Int.min)
        XCTAssertEqual(Saturating.multiplying(Int.min, -1), Int.max)
        XCTAssertEqual(Saturating.multiplying(6, 7), 42)
    }

    func testBlastRadiusClampsNegativeInput() {
        XCTAssertEqual(BlastRadius(resolvedCount: -5).resolvedCount, 0)
        XCTAssertEqual(BlastRadius(resolvedCount: Int.max).resolvedCount, Int.max)
    }

    /// `Int.max` resolved entities must be refused by policy, not crash the app.
    func testExtremeBlastRadiusIsRefusedRatherThanTrapping() {
        let requirement = DefaultAuthorizationPolicy().requirement(
            for: AuthorityAudit.invocation(
                tier: .commit, provenance: .userConfirmed, radius: Int.max
            ),
            floor: .clean,
            remainingCommitBudget: 8,
            limits: .standard
        )
        XCTAssertEqual(requirement, .refuse(.blastRadiusExceeded))
    }

    // MARK: - Timestamps

    /// A `NaN` age compares `false` against every bound, so an expired receipt
    /// would read as fresh and an old ledger record would read as un-evictable.
    /// Rejecting at the boundary is what stops that.
    func testTimestampRejectsNonFiniteAndAbsurdValues() {
        XCTAssertNil(Timestamp(secondsSinceEpoch: .nan))
        XCTAssertNil(Timestamp(secondsSinceEpoch: .infinity))
        XCTAssertNil(Timestamp(secondsSinceEpoch: -.infinity))
        XCTAssertNil(Timestamp(secondsSinceEpoch: Double.greatestFiniteMagnitude))
        XCTAssertNotNil(Timestamp(secondsSinceEpoch: 0))
        XCTAssertNotNil(Timestamp(secondsSinceEpoch: Timestamp.magnitudeLimit))
    }

    func testTimestampDifferencesAreAlwaysFinite() {
        let high = Timestamp(secondsSinceEpoch: Timestamp.magnitudeLimit)!
        let low = Timestamp(secondsSinceEpoch: -Timestamp.magnitudeLimit)!
        XCTAssertTrue(high.seconds(since: low).isFinite)
        XCTAssertTrue(low.seconds(since: high).isFinite)
    }

    func testManualClockIgnoresNonFiniteAdvancesAndNeverGoesBackwards() {
        let clock = ManualClock()
        clock.advance(bySeconds: .nan)
        clock.advance(bySeconds: -100)
        XCTAssertEqual(clock.now, .zero)
        clock.advance(bySeconds: 5)
        XCTAssertEqual(clock.now.secondsSinceEpoch, 5)
    }

    func testLimitsSanitiseHostileConfiguration() {
        let limits = AuthorityLimits(
            blastRadiusCeiling: -1,
            commitBudget: -10,
            receiptValiditySeconds: .nan,
            idempotencyHorizonSeconds: -1,
            idempotencyCapacity: 0,
            auditCapacity: -3
        )
        XCTAssertEqual(limits.blastRadiusCeiling, 0)
        XCTAssertEqual(limits.commitBudget, 0)
        XCTAssertEqual(limits.receiptValiditySeconds, 120)
        XCTAssertEqual(limits.idempotencyHorizonSeconds, 300)
        XCTAssertGreaterThanOrEqual(limits.idempotencyCapacity, 1)
        XCTAssertGreaterThanOrEqual(limits.auditCapacity, 1)
        XCTAssertGreaterThanOrEqual(limits.ingestedSourceCapacity, 1)
    }

    /// `SourceSet` accumulates on every join and a planner controls how many
    /// joins happen, so it is capped — and says when it truncated rather than
    /// silently claiming complete attribution.
    func testSourceSetIsBoundedAndReportsTruncation() {
        let many = (0..<(SourceSet.capacity + 10)).map { SourceID("source-\($0)") }
        let set = SourceSet(many)
        XCTAssertEqual(set.sources.count, SourceSet.capacity)
        XCTAssertTrue(set.isTruncated)

        let small = SourceSet([SourceID("a")])
        XCTAssertFalse(small.isTruncated)

        // Sticky truncation, tested with a join that GENUINELY FITS.
        //
        // The obvious version — union with a disjoint source — is vacuous: the
        // result has 33 unique sources, so `init` sets the flag from the count
        // alone and the test passes even with the sticky line deleted. Joining a
        // *subset* keeps the result at exactly the cap, so the flag can only be
        // true if it was carried across.
        let subset = SourceSet([set.sources[0]])
        let rejoined = set.union(subset)
        XCTAssertEqual(rejoined.sources.count, SourceSet.capacity, "this join fits; nothing new is dropped")
        XCTAssertTrue(rejoined.isTruncated, "truncation must survive a join that fits")
        XCTAssertTrue(subset.union(set).isTruncated, "and it must survive in either order")
    }
}
