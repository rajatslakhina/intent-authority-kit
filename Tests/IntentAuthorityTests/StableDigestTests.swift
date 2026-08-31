import XCTest
@testable import IntentAuthority

/// The digest is the mechanism that makes a confirmation receipt mean anything,
/// so it is tested against values computed by a *separate* implementation of
/// FNV-1a (a Python script following the same encoding, run once when these
/// vectors were authored) rather than against itself.
///
/// This matters because the obvious test — call the function twice in one
/// process and assert the results match — passes for `Hasher` too, which is the
/// exact bug the digest exists to avoid. A frozen vector fails the moment the
/// algorithm changes, in any process.
final class StableDigestTests: XCTestCase {

    private let session = SessionID("session-A")
    private let intent = IntentID("intent.alpha")

    private func binding(
        _ parameters: [TaintedValue],
        radius: Int = 1
    ) -> StableDigest {
        ReceiptBinding.digest(
            sessionID: session,
            intentID: intent,
            parameters: ParameterSet(parameters),
            blastRadius: BlastRadius(resolvedCount: radius)
        )
    }

    func testGoldenVectorEmptyParameters() {
        XCTAssertEqual(binding([]).value, 0xf6c6_c27f_47ca_aa23)
    }

    func testGoldenVectorSingleUserConfirmedParameter() {
        let digest = binding([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed)
        ])
        XCTAssertEqual(digest.value, 0x8ee2_6d6f_aa9c_90c1)
    }

    /// Provenance is inside the digest: the same bytes with a different origin
    /// must not satisfy a receipt issued for the trusted one.
    func testProvenanceChangesTheDigest() {
        let userConfirmed = binding([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed)
        ])
        let appDerived = binding([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .appDerived)
        ])
        XCTAssertEqual(appDerived.value, 0xa5e6_6d0c_b359_07dd)
        XCTAssertNotEqual(userConfirmed, appDerived)
    }

    func testGoldenVectorContentDerivedWithTwoSources() {
        let digest = binding([
            TaintedValue(
                name: "recipient",
                canonicalValue: "Priya Nair",
                provenance: .contentDerived(SourceSet([SourceID("web-page-7"), SourceID("inbox-1")]))
            )
        ])
        XCTAssertEqual(digest.value, 0x2437_145f_5494_266c)
    }

    /// Source ordering must not affect the digest, or a receipt would stop
    /// matching purely because two sources were recorded in the other order.
    func testSourceSetOrderDoesNotAffectDigest() {
        let forward = binding([
            TaintedValue(
                name: "recipient", canonicalValue: "Priya Nair",
                provenance: .contentDerived(SourceSet([SourceID("inbox-1"), SourceID("web-page-7")]))
            )
        ])
        let reverse = binding([
            TaintedValue(
                name: "recipient", canonicalValue: "Priya Nair",
                provenance: .contentDerived(SourceSet([SourceID("web-page-7"), SourceID("inbox-1")]))
            )
        ])
        XCTAssertEqual(forward, reverse)
    }

    /// The reason blast radius is inside the digest: otherwise a receipt granted
    /// for one message satisfies a re-resolution to four hundred.
    func testBlastRadiusChangesTheDigest() {
        let single = binding([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed)
        ], radius: 1)
        let many = binding([
            TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed)
        ], radius: 400)
        XCTAssertEqual(many.value, 0xa277_0d1d_8f89_ce7f)
        XCTAssertNotEqual(single, many)
    }

    /// Length prefixing. Without it these two serialise to the same byte stream,
    /// and a planner could move a character across a field boundary while still
    /// presenting a matching receipt.
    func testFieldBoundariesAreUnambiguous() {
        let a = ReceiptBinding.digest(
            sessionID: SessionID("s"), intentID: IntentID("i"),
            parameters: ParameterSet([
                TaintedValue(name: "ab", canonicalValue: "c", provenance: .userConfirmed)
            ]),
            blastRadius: .single
        )
        let b = ReceiptBinding.digest(
            sessionID: SessionID("s"), intentID: IntentID("i"),
            parameters: ParameterSet([
                TaintedValue(name: "a", canonicalValue: "bc", provenance: .userConfirmed)
            ]),
            blastRadius: .single
        )
        XCTAssertEqual(a.value, 0xa764_01f5_8480_48a0)
        XCTAssertEqual(b.value, 0x0425_14f1_4572_dc0c)
        XCTAssertNotEqual(a, b)
    }

    /// Domain separation: the idempotency key is derived from the binding digest
    /// but must not equal it, or a receipt digest could be presented as a key.
    func testIdempotencyKeyIsDomainSeparated() {
        let invocation = IntentInvocation(
            descriptor: IntentDescriptor(id: intent, tier: .commit, effectSummary: "s"),
            parameters: ParameterSet([
                TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed)
            ]),
            blastRadius: .single
        )
        let key = IdempotencyKey(sessionID: session, invocation: invocation)
        XCTAssertEqual(key.digest.value, 0x7bf4_3bb7_7d8f_062a)
        XCTAssertNotEqual(
            key.digest.value,
            ReceiptBinding.digest(sessionID: session, invocation: invocation).value
        )
    }

    func testDescriptionIsZeroPaddedHex() {
        XCTAssertEqual(StableDigest(value: 1).description, "0000000000000001")
        XCTAssertEqual(StableDigest(value: UInt64.max).description, "ffffffffffffffff")
        XCTAssertEqual(StableDigest(value: 0).description, "0000000000000000")
    }
}
