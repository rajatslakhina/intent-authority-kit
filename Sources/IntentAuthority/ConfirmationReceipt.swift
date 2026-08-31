//
//  ConfirmationReceipt.swift
//  IntentAuthority
//

/// Identifies a broker session.
public struct SessionID: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public var description: String { rawValue }
}

/// Proof that the user was asked, and what they were shown.
///
/// **Why this is a digest over the values and not a boolean.** The obvious
/// implementation sets `confirmed = true` on the pending invocation and lets the
/// commit proceed. But App Intents *re-resolves* parameters, and a planner that
/// retries produces a fresh resolution — so between the moment the user approved
/// and the moment the commit runs, the values can legitimately change. A flag
/// cannot tell. A digest can: the commit recomputes it from the parameters it is
/// actually about to use, and a mismatch is refused rather than silently
/// re-asked, because a silent re-ask is how a user gets trained to approve twice.
public struct ConfirmationReceipt: Sendable, Hashable {
    public let sessionID: SessionID
    public let intentID: IntentID
    public let parameterDigest: StableDigest
    /// The strength of confirmation the user actually gave.
    public let granted: ConfirmationRequirement
    public let issuedAt: Timestamp
    /// Distinguishes two receipts issued for identical values, so a receipt
    /// cannot be replayed to satisfy a second commit.
    public let nonce: UInt64

    public init(
        sessionID: SessionID,
        intentID: IntentID,
        parameterDigest: StableDigest,
        granted: ConfirmationRequirement,
        issuedAt: Timestamp,
        nonce: UInt64
    ) {
        self.sessionID = sessionID
        self.intentID = intentID
        self.parameterDigest = parameterDigest
        self.granted = granted
        self.issuedAt = issuedAt
        self.nonce = nonce
    }
}

/// Computes the digest a receipt binds to.
public enum ReceiptBinding {

    public static let domain = "IntentAuthorityKit/v1/parameter-binding"

    /// Digest over the session, the intent, the blast radius, and every
    /// parameter's name, value and provenance.
    ///
    /// The blast radius is *inside* the digest deliberately. Without it, a
    /// receipt granted for "archive this 1 message" would satisfy a re-resolved
    /// "archive these 400 messages" — same intent, same parameter values, wildly
    /// different effect.
    public static func digest(
        sessionID: SessionID,
        intentID: IntentID,
        parameters: ParameterSet,
        blastRadius: BlastRadius
    ) -> StableDigest {
        var hasher = StableDigestHasher(domain: domain)
        hasher.combine(string: sessionID.rawValue)
        hasher.combine(string: intentID.rawValue)
        hasher.combine(count: blastRadius.resolvedCount)
        hasher.combine(count: parameters.values.count)
        // `ParameterSet` guarantees name-sorted, duplicate-free storage, so this
        // walk is canonical.
        for value in parameters.values {
            hasher.combine(string: value.name)
            hasher.combine(string: value.canonicalValue)
            value.provenance.combine(into: &hasher)
        }
        return hasher.finalized()
    }

    public static func digest(
        sessionID: SessionID,
        invocation: IntentInvocation
    ) -> StableDigest {
        digest(
            sessionID: sessionID,
            intentID: invocation.descriptor.id,
            parameters: invocation.parameters,
            blastRadius: invocation.blastRadius
        )
    }
}

/// Asks the user. Injected so the host app owns the presentation.
public protocol ConfirmationPresenter: Sendable {
    /// Presents `requirement` for `invocation` and returns the receipt if the
    /// user approved, or `nil` if they declined.
    ///
    /// Implementations must render only `descriptor.effectSummary` and
    /// parameters whose content trust is `.authentic`. The broker never asks for
    /// confirmation of an untrusted-content commit at all, so a correct
    /// implementation is never handed attacker bytes to display — but
    /// `ParameterSet.untrustedNames` exists so a presenter can assert that.
    func confirm(
        invocation: IntentInvocation,
        requirement: ConfirmationRequirement,
        sessionID: SessionID
    ) async -> ConfirmationReceipt?
}

/// Issues receipts. Separated from presentation so the digest is computed by the
/// broker's own code and a presenter cannot mint a receipt for values other than
/// the ones it was shown.
public struct ReceiptIssuer: Sendable {
    private let clock: AuthorityClock

    public init(clock: AuthorityClock) {
        self.clock = clock
    }

    public func issue(
        sessionID: SessionID,
        invocation: IntentInvocation,
        granted: ConfirmationRequirement,
        nonce: UInt64
    ) -> ConfirmationReceipt {
        ConfirmationReceipt(
            sessionID: sessionID,
            intentID: invocation.descriptor.id,
            parameterDigest: ReceiptBinding.digest(sessionID: sessionID, invocation: invocation),
            granted: granted,
            issuedAt: clock.now,
            nonce: nonce
        )
    }
}

extension ConfirmationReceipt {

    /// Validates this receipt against the invocation about to execute.
    ///
    /// Returns `nil` when the receipt is acceptable, or the reason it is not.
    public func validate(
        against invocation: IntentInvocation,
        sessionID: SessionID,
        required: ConfirmationRequirement,
        now: Timestamp,
        validitySeconds: Double
    ) -> RefusalReason? {
        guard self.sessionID == sessionID else { return .receiptSessionMismatch }
        guard self.intentID == invocation.descriptor.id else { return .receiptValueMismatch }

        let expected = ReceiptBinding.digest(sessionID: sessionID, invocation: invocation)
        guard expected == parameterDigest else { return .receiptValueMismatch }

        // A receipt for a weaker confirmation does not satisfy a stronger
        // requirement. "Are you sure?" is not an answer to "which one?".
        guard granted >= required else { return .receiptInsufficient }

        let age = now.seconds(since: issuedAt)
        // A receipt from the future is as suspect as an expired one; both mean
        // the clock moved under us.
        guard age >= 0, age <= validitySeconds else { return .receiptExpired }

        return nil
    }
}
