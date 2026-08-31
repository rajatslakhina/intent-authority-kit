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
    @State private var auditLines: [String] = []
    @State private var remainingBudget: Int
    @State private var isRunning = false
    @State private var auditFindings: [AuditFinding] = []

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
    }

    public var body: some View {
        NavigationStack {
            List {
                headerSection
                scenarioSection
                if !auditLines.isEmpty {
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
            }
        }
        .onAppear(perform: refreshStaticVerdicts)
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
                Text("Commit budget remaining: \(remainingBudget) of \(limits.commitBudget)")
                    .font(.caption.monospaced())
                    .foregroundStyle(remainingBudget > 0 ? .secondary : .red)
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

    private var auditSection: some View {
        Section("Audit ledger") {
            ForEach(Array(auditLines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.caption2.monospaced())
            }
        }
    }

    private var invariantSection: some View {
        Section("Invariants (runnable, not asserted in prose)") {
            ForEach(auditFindings.isEmpty ? AuthorityAudit.verify(policy: policy, limits: limits) : auditFindings, id: \.name) { finding in
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

    /// Fills the table before anything is tapped. Pure; no session state moves.
    private func refreshStaticVerdicts() {
        guard verdicts.isEmpty else { return }
        var next: [String: ScenarioVerdict] = [:]
        for scenario in AuthorityScenario.catalog {
            let requirement = policy.requirement(
                for: scenario.invocation,
                floor: scenario.floor,
                remainingCommitBudget: limits.commitBudget,
                limits: limits
            )
            next[scenario.id] = ScenarioVerdict(
                requirement: requirement,
                trust: scenario.invocation.parameters.effectiveTrust(under: scenario.floor),
                decision: nil
            )
        }
        verdicts = next
        auditFindings = AuthorityAudit.verify(policy: policy, limits: limits)
    }

    private func runAll() {
        isRunning = true
        Task {
            let clock = ManualClock()
            let presenter = AlwaysApprovePresenter(clock: clock)
            var lines: [String] = []
            var updated = verdicts
            var lastRemaining = limits.commitBudget

            for scenario in AuthorityScenario.catalog {
                let session = BrokerSession(
                    id: SessionID("demo-\(scenario.id)"),
                    policy: policy,
                    presenter: presenter,
                    clock: clock,
                    limits: limits,
                    initialFloor: scenario.floor
                )
                let result = await session.authorize(scenario.invocation)
                lastRemaining = await session.remainingCommitBudget
                updated[scenario.id] = ScenarioVerdict(
                    requirement: result.requirement,
                    trust: result.trust,
                    decision: result.decision
                )
                lines.append(
                    "\(scenario.invocation.descriptor.id.rawValue) "
                    + "floor=\(scenario.floor.label) "
                    + "c=\(result.trust.content.label) s=\(result.trust.selection.label) "
                    + "→ \(result.decision.label)"
                )
                clock.advance(bySeconds: 1)
            }

            verdicts = updated
            auditLines = lines
            remainingBudget = lastRemaining
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
