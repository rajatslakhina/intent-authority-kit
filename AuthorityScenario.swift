//
//  AuthorityScenario.swift
//  IntentAuthorityUI
//

import IntentAuthority

/// A canned agent request, used to make the broker's reasoning visible.
///
/// Each scenario is a real `IntentInvocation` plus the session taint floor it
/// arrives under — the two inputs that decide everything. Nothing here is
/// pre-baked: the console runs them through the same `DefaultAuthorizationPolicy`
/// and `BrokerSession` a host app would use.
public struct AuthorityScenario: Sendable, Identifiable, Hashable {
    public let id: String
    public let title: String
    /// What the planner is trying to do, in the planner's words.
    public let request: String
    /// Why this case is interesting.
    public let note: String
    public let floor: TaintFloor
    public let invocation: IntentInvocation

    public init(
        id: String,
        title: String,
        request: String,
        note: String,
        floor: TaintFloor,
        invocation: IntentInvocation
    ) {
        self.id = id
        self.title = title
        self.request = request
        self.note = note
        self.floor = floor
        self.invocation = invocation
    }
}

public extension AuthorityScenario {

    static func makeInvocation(
        intent: String,
        tier: EffectTier,
        summary: String,
        radius: Int,
        parameters: [TaintedValue]
    ) -> IntentInvocation {
        IntentInvocation(
            descriptor: IntentDescriptor(id: IntentID(intent), tier: tier, effectSummary: summary),
            parameters: ParameterSet(parameters),
            blastRadius: BlastRadius(resolvedCount: radius)
        )
    }

    /// The cases that separate this design from the obvious one — including one
    /// per confirmation tier, so no rung of the model is left undemonstrated.
    static let catalog: [AuthorityScenario] = [
        AuthorityScenario(
            id: "clean-commit",
            title: "User picked the recipient",
            request: "Send £40 to Priya",
            note: "Authentic content, authentic selection, one entity. Nothing to ask.",
            floor: .clean,
            invocation: makeInvocation(
                intent: "payments.send", tier: .commit,
                summary: "Send a payment", radius: 1,
                parameters: [
                    TaintedValue(name: "recipient", canonicalValue: "Priya Nair", provenance: .userConfirmed),
                    TaintedValue(name: "amount", canonicalValue: "40.00 GBP", provenance: .userConfirmed)
                ]
            )
        ),
        AuthorityScenario(
            id: "planner-authored",
            title: "Planner wrote the recipient",
            request: "Send £40 to the person I mentioned",
            note: "Bytes came from the planner, not the user. Show the noun, not just the verb.",
            floor: .plannerOnly,
            invocation: makeInvocation(
                intent: "payments.send", tier: .commit,
                summary: "Send a payment", radius: 1,
                parameters: [
                    TaintedValue(name: "recipient", canonicalValue: "P. Nair", provenance: .plannerAuthored),
                    TaintedValue(name: "amount", canonicalValue: "40.00 GBP", provenance: .userConfirmed)
                ]
            )
        ),
        AuthorityScenario(
            id: "content-derived",
            title: "Recipient came out of an email",
            request: "Pay the invoice in that message",
            note: "The confirmation prompt would render the attacker's string. Refuse — you cannot confirm your way out of this one.",
            floor: .contentExposed,
            invocation: makeInvocation(
                intent: "payments.send", tier: .commit,
                summary: "Send a payment", radius: 1,
                parameters: [
                    TaintedValue(
                        name: "recipient",
                        canonicalValue: "ACME Supplies (acct 0099)",
                        provenance: .contentDerived(SourceID("inbox/message-4821"))
                    ),
                    TaintedValue(name: "amount", canonicalValue: "40.00 GBP", provenance: .plannerAuthored)
                ]
            )
        ),
        AuthorityScenario(
            id: "baton-pass",
            title: "App's own contact, after a baton pass",
            request: "Archive the thread from Priya",
            note: "Authentic bytes from our database — but the session read untrusted content, so the *choice* is attacker-influenced. This is the case a single-axis model waves through.",
            floor: .contentExposed,
            invocation: makeInvocation(
                intent: "mail.archive", tier: .commit,
                summary: "Archive a conversation", radius: 1,
                parameters: [
                    TaintedValue(name: "thread", canonicalValue: "Thread #331 — Priya Nair", provenance: .appDerived)
                ]
            )
        ),
        AuthorityScenario(
            id: "multi-target",
            title: "\"That\" turned out to mean 12 messages",
            request: "Archive those",
            note: "Everything is authentic and the session is clean — but blast radius belongs to the resolved set, not the verb. One target asks nothing; twelve asks whether you meant it.",
            floor: .clean,
            invocation: makeInvocation(
                intent: "mail.archive", tier: .commit,
                summary: "Archive conversations", radius: 12,
                parameters: [
                    TaintedValue(name: "query", canonicalValue: "from:Priya is:unread", provenance: .appDerived)
                ]
            )
        ),
        AuthorityScenario(
            id: "blast-radius",
            title: "\"That\" turned out to mean 400 messages",
            request: "Archive all of those",
            note: "Same intent, same perform() body, at 400 targets — past the ceiling the app compiled in. Some blast radii are not a confirmation problem; they are a refusal.",
            floor: .plannerOnly,
            invocation: makeInvocation(
                intent: "mail.archive", tier: .commit,
                summary: "Archive conversations", radius: 400,
                parameters: [
                    TaintedValue(name: "query", canonicalValue: "is:unread", provenance: .appDerived)
                ]
            )
        ),
        AuthorityScenario(
            id: "tainted-read",
            title: "Tainted read",
            request: "Summarise that message",
            note: "Reads are inert and always allowed — but recorded, because the result leaves through the planner and the audit trail is the only place that exposure is reconstructable.",
            floor: .contentExposed,
            invocation: makeInvocation(
                intent: "mail.summarise", tier: .read,
                summary: "Summarise a conversation", radius: 1,
                parameters: [
                    TaintedValue(
                        name: "thread",
                        canonicalValue: "Thread #4821",
                        provenance: .contentDerived(SourceID("inbox/message-4821"))
                    )
                ]
            )
        )
    ]
}
