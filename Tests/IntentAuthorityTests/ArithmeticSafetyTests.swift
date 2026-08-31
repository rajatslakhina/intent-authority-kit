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

    func testUnsignedNonceSaturates() {
        XCTAssertEqual(Saturating.addingUInt64(UInt64.max, 1), UInt64.max)
        XCTAssertEqual(Saturating.addingUInt64(1, 1), 2)
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
    }
}
