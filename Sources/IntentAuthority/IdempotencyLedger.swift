//
//  IdempotencyLedger.swift
//  IntentAuthority
//

/// A key that is stable across a planner's retries and distinct across genuinely
/// different requests.
public struct IdempotencyKey: Sendable, Hashable, CustomStringConvertible {
    public let digest: StableDigest
    public var description: String { digest.description }

    public static let domain = "IntentAuthorityKit/v1/idempotency"

    /// Derived from the session, the intent and the exact resolved parameters —
    /// the same inputs the receipt binds to. A retry re-resolving to identical
    /// values produces an identical key; a retry that resolves differently
    /// produces a different key and is correctly treated as a new request.
    ///
    /// Built on `StableDigest`, not `hashValue`, for the reason spelled out in
    /// `StableDigest`: a per-process seed makes every key change at relaunch,
    /// which is exactly when a retry arrives.
    public init(sessionID: SessionID, invocation: IntentInvocation) {
        var hasher = StableDigestHasher(domain: IdempotencyKey.domain)
        hasher.combine(
            rawUInt64: ReceiptBinding.digest(sessionID: sessionID, invocation: invocation).value
        )
        self.digest = hasher.finalized()
    }
}

/// What happened the first time a key was seen.
public struct LedgerRecord: Sendable, Hashable {
    public let key: IdempotencyKey
    public let outcome: CommitOutcome
    public let recordedAt: Timestamp

    public init(key: IdempotencyKey, outcome: CommitOutcome, recordedAt: Timestamp) {
        self.key = key
        self.outcome = outcome
        self.recordedAt = recordedAt
    }
}

/// The recorded result of an admitted commit.
public enum CommitOutcome: Sendable, Hashable {
    /// Admitted and handed to the app, outcome not yet reported. A replay
    /// arriving in this state must not re-execute: the first attempt may still
    /// be in flight against the backend, and the backend dedupes on this same key.
    case inFlight
    case executed
    case failed(String)
}

/// Bounded store of recent commit keys.
///
/// **Eviction is the dangerous operation here**, because dropping a record
/// re-admits a retry as a fresh commit and double-commits. So eviction is
/// permitted only for records older than the retry horizon — past which a
/// repeat genuinely is a new request, by the same contract the backend applies —
/// and never for pressure. When the ledger is full of records that are all still
/// inside the horizon, the broker refuses.
///
/// That refusal is deliberately unreachable in normal operation: the commit
/// budget is smaller than the capacity, so budget exhaustion fires first and
/// saturation is defence in depth rather than the primary limiter.
public struct IdempotencyLedger: Sendable {
    private var records: [IdempotencyKey: LedgerRecord] = [:]
    private let capacity: Int
    private let horizonSeconds: Double

    public init(capacity: Int, horizonSeconds: Double) {
        self.capacity = max(1, Saturating.nonNegative(capacity))
        self.horizonSeconds = AuthorityLimits.sanitised(horizonSeconds, fallback: 300)
    }

    public var count: Int { records.count }

    /// Removes every record older than the horizon.
    public mutating func prune(now: Timestamp) {
        records = records.filter { _, record in
            now.seconds(since: record.recordedAt) <= horizonSeconds
        }
    }

    /// The recorded outcome for `key`, if this is a replay within the horizon.
    public func replay(of key: IdempotencyKey, now: Timestamp) -> LedgerRecord? {
        guard let record = records[key] else { return nil }
        guard now.seconds(since: record.recordedAt) <= horizonSeconds else { return nil }
        return record
    }

    /// Reserves space for a new key. Prunes first; refuses if still full.
    public mutating func canRecord(_ key: IdempotencyKey, now: Timestamp) -> Bool {
        if records[key] != nil { return true }
        prune(now: now)
        return records.count < capacity
    }

    /// Records an outcome. Returns `false` if there was no room, in which case
    /// nothing was stored and the caller must refuse.
    @discardableResult
    public mutating func record(
        _ key: IdempotencyKey,
        outcome: CommitOutcome,
        now: Timestamp
    ) -> Bool {
        guard canRecord(key, now: now) else { return false }
        records[key] = LedgerRecord(key: key, outcome: outcome, recordedAt: now)
        return true
    }

    /// Updates the outcome of an already-recorded key, preserving its original
    /// timestamp so that settling does not extend the retry horizon.
    ///
    /// Returns `false` if the key is unknown — settling something that was never
    /// admitted is a caller bug, and inventing a record for it would make the
    /// ledger claim an admission that never happened.
    @discardableResult
    public mutating func settle(_ key: IdempotencyKey, outcome: CommitOutcome) -> Bool {
        guard let existing = records[key] else { return false }
        records[key] = LedgerRecord(key: key, outcome: outcome, recordedAt: existing.recordedAt)
        return true
    }

    /// Discards a record entirely. Used only when an admission is rolled back
    /// before any effect could occur, so that a later genuine retry is not
    /// answered from a phantom `inFlight` record that will never settle.
    public mutating func discard(_ key: IdempotencyKey) {
        records.removeValue(forKey: key)
    }
}
