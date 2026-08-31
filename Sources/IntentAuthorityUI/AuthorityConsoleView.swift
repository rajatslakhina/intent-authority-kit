//
//  AuthorityConsoleView.swift
//  IntentAuthorityUI
//

#if canImport(SwiftUI)

import SwiftUI
import IntentAuthority

/// One scenario's verdict, as displayed.
public struct ScenarioVerdict: Sendable, Hashable {
    public let requirement: ConfirmationRequirement
    public let trust: EffectiveTrust
    public let decision: BrokerDecision?

    public init(
        requirement: ConfirmationRequirement,
        trust: EffectiveTrust,
        decision: BrokerDecision?
    ) {
        self.requirement = requirement
        self.trust = trust
        self.decision = decision
    }
}

/// The demo's root view.
///
/// Populated on first render without any user action: every scenario's
/// requirement and two trust axes are pure functions of the invocation and the
/// session floor, so the table has real content before anything is tapped.
/// Running a scenario additionally drives a real `BrokerSession` — spending
/// budget, minting or refusing receipts, and appending to the audit ledger.
public struct AuthorityConsoleView: View {

    private let limits: AuthorityLimits
    private let policy: any AuthorizationPolicy

    @State private var verdicts: [String: ScenarioVerdict] = [:]
    /// Real `AuditRecord`s, read back from the sessions that produced them.
    @State private var auditRecords: [AuditRecord] = []
    @State private var auditDropped = 0
    @State private var ingestedLog: [String] = []
    @State private var budgetLine = ""
    @State private var drainLog: [String] = []
    @State private var remainingBudget: Int
    @State private var isRunning = false

    /// Deliberately `let`, not `@State`.
    ///
    /// It never changes after construction, and SwiftUI re-creates the `View`
    /// struct on every invalidation — so as `@State` this would re-run
    /// `AuthorityAudit.verify()` (343 associativity triples plus a radius sweep)
    /// on every re-render and throw the result away each time, because
    /// `State(initialValue:)` only takes effect on the first construction. That
    /// is the classic `State(initialValue:)` trap, and it is worth not falling
    /// into it in the one SwiftUI file here.
    private let auditFindings: [AuditFinding]

    /// The host app supplies the limits and the policy. They are compiled into
    /// the app on purpose: a single mis-published remote config field should not
    /// be able to lift every commit ceiling in the fleet at once.
    public init(
        limits: AuthorityLimits = .standard,
        policy: any AuthorizationPolicy = DefaultAuthorizationPolicy()
    ) {
        self.limits = limits
        self.policy = policy
        _remainingBudget = State(initialValue: limits.commitBudget)

        // Computed here, not in `onAppear`. Every requirement and both trust axes
        // are pure functions of the invocation and the session floor, so there is
        // no reason to render an empty table for a frame and then fill it — and
        // "the table is populated before you touch anything" should be true of
        // the very first paint, not almost true.
        var initial: [String: ScenarioVerdict] = [:]
        for scenario in AuthorityScenario.catalog {
            let requirement = policy.requirement(
                for: scenario.invocation,
                floor: scenario.floor,
                remainingCommitBudget: limits.commitBudget,
                limits: limits
            )
            initial[scenario.id] = ScenarioVerdict(
                requirement: requirement,
                trust: scenario.invocation.parameters.effectiveTrust(under: scenario.floor),
                decision: nil
            )
        }
        _verdicts = State(initialValue: initial)
        auditFindings = AuthorityAudit.verify(policy: policy, limits: limits)
    }

    public var body: some View {
        NavigationStack {
            List {
                headerSection
                scenarioSection
                if !drainLog.isEmpty {
                    budgetSection
                }
                if !ingestedLog.isEmpty {
                    exposureSection
                }
                if !auditRecords.isEmpty {
                    auditSection
                }
                invariantSection
            }
            .navigationTitle("Intent Authority")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Run all") { runAll() }
                        .disabled(isRunning)
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Drain budget") { drainBudget() }
                        .disabled(isRunning)
                }
            }
        }
    }

    // MARK: - Sections

    private var headerSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                Text("Your intent surface now has an untrusted LLM planner as a caller.")
                    .font(.subheadline)
                Text("Every row below is scored on two axes: can the bytes be trusted, and can the reason this value was chosen be trusted. They are different questions.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Each scenario below runs in its own session, because the taint floor is monotone and they start from different floors. “Drain budget” uses a single session so the allowance is actually spendable.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if !budgetLine.isEmpty {
                    Text(budgetLine)
                        .font(.caption.monospaced())
                        // Both branches are spelled `Color.` on purpose. A bare
                        // `.secondary` resolves to `HierarchicalShapeStyle` while
                        // `.red` resolves to `Color`, and a ternary needs one type —
                        // so the shorthand form does not compile for iOS.
                        .foregroundStyle(remainingBudget > 0 ? Color.secondary : Color.red)
                }
            }
            .padding(.vertical, 2)
        }
    }

    private var scenarioSection: some View {
        Section("Scenarios") {
            ForEach(AuthorityScenario.catalog) { scenario in
                scenarioRow(scenario)
            }
        }
    }

    @ViewBuilder
    private func scenarioRow(_ scenario: AuthorityScenario) -> some View {
        let verdict = verdicts[scenario.id]
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(scenario.title).font(.headline)
                Spacer()
                Text(scenario.invocation.descriptor.tier.label)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.15), in: Capsule())
            }
            Text("“\(scenario.request)”")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            if let verdict {
                HStack(spacing: 8) {
                    badge("content", verdict.trust.content.label, verdict.trust.content.tone)
                    badge("selection", verdict.trust.selection.label, verdict.trust.selection.tone)
                    badge("floor", scenario.floor.label, .secondary)
                }
                HStack(spacing: 6) {
                    Text(verdict.requirement.label)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(verdict.requirement.tone)
                    if let decision = verdict.decision {
                        Text("→ \(decision.label)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Text(scenario.note)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }

    /// Renders the library's real `AuditRecord`s — sequence number, tiers, the
    /// bound parameter digest, and the *names* of untrusted parameters. Never the
    /// values: copying attacker-controlled bytes into a support tool is how the
    /// audit trail becomes the next attack surface.
    private var auditSection: some View {
        Section("Audit ledger (\(auditRecords.count) records\(auditDropped > 0 ? ", \(auditDropped) dropped" : ""))") {
            // Enumerated rather than keyed on a record field: sequence numbers
            // restart per session, so they collide across scenarios.
            ForEach(Array(auditRecords.enumerated()), id: \.offset) { _, record in
                VStack(alignment: .leading, spacing: 2) {
                    Text("#\(record.sequence)  \(record.intentID.rawValue)  [\(record.tier.label)]")
                        .font(.caption2.monospaced().weight(.semibold))
                    Text("floor=\(record.floor.label) content=\(record.trust.content.label) selection=\(record.trust.selection.label) targets=\(record.blastRadius.resolvedCount)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    Text("→ \(record.decision.label)  digest=\(record.parameterDigest.description.prefix(12))…")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    if !record.untrustedParameterNames.isEmpty {
                        Text("untrusted parameters (names only): \(record.untrustedParameterNames.joined(separator: ", "))")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.red)
                    }
                }
                .padding(.vertical, 1)
            }
        }
    }

    private var exposureSection: some View {
        Section("Session exposure — what raised each floor") {
            ForEach(Array(ingestedLog.enumerated()), id: \.offset) { _, line in
                Text(line).font(.caption2.monospaced())
            }
        }
    }

    private var budgetSection: some View {
        Section("Commit budget — one session, repeated commits") {
            ForEach(Array(drainLog.enumerated()), id: \.offset) { _, line in
                Text(line).font(.caption2.monospaced())
            }
        }
    }

    private var invariantSection: some View {
        Section("Invariants (runnable, not asserted in prose)") {
            ForEach(auditFindings, id: \.name) { finding in
                HStack(alignment: .top, spacing: 6) {
                    Text(finding.holds ? "PASS" : "FAIL")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(finding.holds ? Color.green : Color.red)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(finding.name).font(.caption2)
                        Text(finding.detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func badge(_ caption: String, _ value: String, _ tone: Color) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(caption.uppercased())
                .font(.system(size: 8, weight: .semibold))
                .foregroundStyle(.tertiary)
            Text(value)
                .font(.caption2.weight(.medium))
                .foregroundStyle(tone)
        }
    }

    // MARK: - Behaviour

    private func runAll() {
        isRunning = true
        // Clear the budget panel: these are fresh per-scenario sessions, and
        // leaving "0 of 4 remaining" on screen next to four new admissions would
        // be a straightforwardly false reading.
        drainLog = []
        budgetLine = ""
        remainingBudget = limits.commitBudget
        Task {
            let clock = ManualClock()
            let presenter = AlwaysApprovePresenter(clock: clock)
            var updated = verdicts
            var records: [AuditRecord] = []
            var exposures: [String] = []
            var dropped = 0

            for scenario in AuthorityScenario.catalog {
                // One session per scenario, on purpose: the taint floor is
                // monotone, so a shared session could not start one scenario
                // clean after another had gone content-exposed.
                //
                // Scenarios that declare `exposedBy` start **clean** and are
                // raised by replaying real `noteContentIngested(from:)` calls,
                // so the floor the row displays is one the broker derived, not
                // one the demo asserted. The `precondition`-style check below
                // fails loudly if the two ever disagree.
                let startingFloor: TaintFloor = scenario.exposedBy.isEmpty
                    ? scenario.floor
                    : .clean
                let session = BrokerSession(
                    id: SessionID("demo-\(scenario.id)"),
                    policy: policy,
                    presenter: presenter,
                    clock: clock,
                    limits: limits,
                    initialFloor: startingFloor
                )
                for source in scenario.exposedBy {
                    await session.noteContentIngested(from: source)
                }
                let derivedFloor = await session.currentFloor
                let result = await session.authorize(scenario.invocation)
                updated[scenario.id] = ScenarioVerdict(
                    requirement: result.requirement,
                    trust: result.trust,
                    decision: result.decision
                )
                records.append(contentsOf: await session.auditRecords)

                // Every scenario contributes a line, including the clean ones.
                // A panel that is blank for the rows it exists to explain is
                // worse than no panel.
                let ingested = await session.ingestedSources
                var line = "\(scenario.title) [\(scenario.id)] — \(scenario.floorOrigin)"
                if derivedFloor != scenario.floor {
                    // Not reachable with the shipped catalog; shown rather than
                    // swallowed, because a demo that quietly disagrees with
                    // itself is exactly the thing this library is about.
                    line += "  ⚠︎ declared \(scenario.floor) but derived \(derivedFloor)"
                }
                if !scenario.exposedBy.isEmpty && ingested.isEmpty {
                    line += "  ⚠︎ exposure declared but no source was retained"
                }
                exposures.append(line)
                dropped = Saturating.adding(dropped, await session.auditDroppedCount)
                clock.advance(bySeconds: 1)
            }

            verdicts = updated
            auditRecords = records
            ingestedLog = exposures
            auditDropped = dropped
            isRunning = false
        }
    }

    /// Spends a real allowance on a real session, one commit at a time, until the
    /// broker refuses. This is the only place the budget is observable, because
    /// it is the only place a single session is used more than once.
    private func drainBudget() {
        isRunning = true
        Task {
            let clock = ManualClock()
            let session = BrokerSession(
                id: SessionID("demo-budget"),
                policy: policy,
                presenter: AlwaysApprovePresenter(clock: clock),
                clock: clock,
                limits: limits,
                initialFloor: .clean
            )
            var log: [String] = []
            // One more attempt than the allowance, so the refusal is shown —
            // but capped. `AuthorityLimits` only clamps `commitBudget` to
            // non-negative and this view is public API, so a `commitBudget` of
            // `Int.max` would saturate into an effectively unbounded loop. Here
            // saturating arithmetic converts a would-be trap into a hang, which
            // is worse; the display cap is what actually bounds it.
            let displayCap = 12
            let attempts = min(displayCap, Saturating.adding(limits.commitBudget, 1))
            for attempt in 1...max(1, attempts) {
                let invocation = AuthorityScenario.makeInvocation(
                    intent: "mail.archive", tier: .commit,
                    summary: "Archive a conversation", radius: 1,
                    parameters: [
                        TaintedValue(
                            name: "thread",
                            canonicalValue: "Thread #\(attempt)",
                            provenance: .userConfirmed
                        )
                    ]
                )
                let result = await session.authorize(invocation)
                let left = await session.remainingCommitBudget
                log.append("commit \(attempt): \(result.decision.label)  budget left = \(left)")
                if case let .allowedCommit(key) = result.decision {
                    await session.settle(key, outcome: .executed)
                }
                clock.advance(bySeconds: 1)
            }
            remainingBudget = await session.remainingCommitBudget
            budgetLine = "Commit budget: \(remainingBudget) of \(limits.commitBudget) remaining"
            drainLog = log
            auditRecords = await session.auditRecords
            auditDropped = await session.auditDroppedCount
            isRunning = false
        }
    }
}

// MARK: - Display helpers

extension EffectTier {
    var label: String {
        switch self {
        case .read: return "READ"
        case .propose: return "PROPOSE"
        case .commit: return "COMMIT"
        }
    }
}

extension ContentTrust {
    var label: String {
        switch self {
        case .untrusted: return "untrusted"
        case .unverified: return "unverified"
        case .authentic: return "authentic"
        }
    }
    var tone: Color {
        switch self {
        case .untrusted: return .red
        case .unverified: return .orange
        case .authentic: return .green
        }
    }
}

extension SelectionTrust {
    var label: String {
        switch self {
        case .untrusted: return "untrusted"
        case .unverified: return "unverified"
        case .authentic: return "authentic"
        }
    }
    var tone: Color {
        switch self {
        case .untrusted: return .red
        case .unverified: return .orange
        case .authentic: return .green
        }
    }
}

extension TaintFloor {
    var label: String {
        switch self {
        case .clean: return "clean"
        case .plannerOnly: return "planner"
        case .contentExposed: return "exposed"
        }
    }
}

extension ConfirmationRequirement {
    var label: String {
        switch self {
        case .none: return "NO PROMPT"
        case .verifyEffect: return "CONFIRM EFFECT — “are you sure?”"
        case .verifyValue: return "CONFIRM VALUE — “which one?”"
        case let .refuse(reason): return "REFUSED — \(reason.rawValue)"
        }
    }
    var tone: Color {
        switch self {
        case .none: return .green
        case .verifyEffect: return .orange
        case .verifyValue: return .orange
        case .refuse: return .red
        }
    }
}

extension BrokerDecision {
    var label: String {
        switch self {
        case .allowedInert: return "allowed (inert)"
        case .allowedCommit: return "committed"
        case let .replayed(outcome): return "replayed(\(outcome.label))"
        case let .refused(reason): return "refused(\(reason.rawValue))"
        case .declined: return "declined by user"
        }
    }
}

extension CommitOutcome {
    var label: String {
        switch self {
        case .inFlight: return "in-flight"
        case .executed: return "executed"
        case let .failed(message): return "failed: \(message)"
        }
    }
}

#Preview {
    AuthorityConsoleView()
}

#endif
