import XCTest
@testable import IntentAuthority

/// Actor isolation gives mutual exclusion *between* suspension points and
/// nothing across them. `await presenter.confirm(...)` sits in the middle of a
/// check-then-act sequence, so where the budget is taken relative to that
/// `await` is a real correctness decision.
///
/// These tests drive the *same* actor through the *same* interleaving with only
/// `CommitAdmissionOrder` changed, so the difference cannot be attributed to two
/// separately-written implementations. The barrier presenter is a genuine
/// concurrent writer: it parks inside the suspension point and holds it open
/// until the test releases it.
/// Free function rather than a method: under Swift 6 strict concurrency a task
/// group closure that touches `self` captures the (non-`Sendable`) `XCTestCase`,
/// which is a genuine data race and is correctly rejected.
private func plannerAuthoredCommit(_ index: Int) -> IntentInvocation {
    IntentInvocation(
        descriptor: IntentDescriptor(
            id: IntentID("mail.archive"), tier: .commit, effectSummary: "Archive"
        ),
        // Distinct values so each has its own idempotency key and the replay
        // path cannot mask an admission.
        parameters: ParameterSet([
            TaintedValue(
                name: "thread", canonicalValue: "Thread #\(index)",
                provenance: .plannerAuthored
            )
        ]),
        blastRadius: .single
    )
}

final class AdmissionReentrancyTests: XCTestCase {

    private func runConcurrently(
        order: CommitAdmissionOrder,
        taskCount: Int,
        budget: Int,
        arrivalsToAwait: Int
    ) async -> (admitted: Int, refused: Int, prompts: Int) {
        let clock = ManualClock()
        let presenter = BarrierConfirmationPresenter(clock: clock)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: presenter,
            clock: clock,
            limits: AuthorityLimits(commitBudget: budget),
            admissionOrder: order
        )

        let invocations = (0..<taskCount).map(plannerAuthoredCommit)

        async let results: [BrokerDecision] = withTaskGroup(of: BrokerDecision.self) { group in
            for index in 0..<taskCount {
                group.addTask {
                    await session.authorize(invocations[index]).decision
                }
            }
            var collected: [BrokerDecision] = []
            for await decision in group { collected.append(decision) }
            return collected
        }

        // Hold the suspension point open until the expected number of
        // invocations have genuinely reached it, then let them all proceed.
        await presenter.waitForArrivals(arrivalsToAwait)
        await presenter.release()

        let decisions = await results
        let prompts = await presenter.arrivalCount

        var admitted = 0
        var refused = 0
        for decision in decisions {
            switch decision {
            case .allowedCommit: admitted += 1
            case .refused: refused += 1
            default: break
            }
        }
        return (admitted, refused, prompts)
    }

    /// The invariant that must hold under either order: a session never commits
    /// more than its allowance, however the calls interleave.
    func testAdmissionsNeverExceedBudgetUnderConcurrency() async {
        for order in [CommitAdmissionOrder.reserveBeforeConfirmation, .reserveAfterConfirmation] {
            let outcome = await runConcurrently(
                order: order, taskCount: 6, budget: 2,
                arrivalsToAwait: order == .reserveBeforeConfirmation ? 1 : 2
            )
            XCTAssertLessThanOrEqual(outcome.admitted, 2, "over-admitted under \(order)")
            XCTAssertGreaterThanOrEqual(outcome.admitted, 1, "under-admitted under \(order)")
        }
    }

    /// The bug the correct order actually prevents.
    ///
    /// With the budget taken *after* the prompt, every concurrent invocation
    /// computes its requirement against the same pre-award balance, so all of
    /// them raise a confirmation the session can never honour. A budget of one
    /// becomes an unbounded number of prompts — which is a confirmation-fatigue
    /// vector an attacker can drive deliberately, and fatigue is exactly what
    /// makes per-action approval stop working.
    func testNaiveOrderPromptsForCommitsItCannotHonour() async {
        let naive = await runConcurrently(
            order: .reserveAfterConfirmation, taskCount: 4, budget: 1, arrivalsToAwait: 4
        )
        XCTAssertEqual(naive.admitted, 1)
        XCTAssertEqual(naive.refused, 3)
        XCTAssertEqual(
            naive.prompts, 4,
            "the naive order asks the user four times for one available slot"
        )
    }

    func testCorrectOrderPromptsExactlyOnce() async {
        let correct = await runConcurrently(
            order: .reserveBeforeConfirmation, taskCount: 4, budget: 1, arrivalsToAwait: 1
        )
        XCTAssertEqual(correct.admitted, 1)
        XCTAssertEqual(correct.refused, 3)
        XCTAssertEqual(
            correct.prompts, 1,
            "taking the budget before the suspension point makes the other three refuse without asking"
        )
    }

    /// Guards the barrier itself. If `BarrierConfirmationPresenter` did not
    /// actually park, both orders would serialise and the comparison above would
    /// be meaningless — so assert the parking is observable.
    func testBarrierGenuinelyHoldsInvocationsOpen() async {
        let clock = ManualClock()
        let presenter = BarrierConfirmationPresenter(clock: clock)
        let session = BrokerSession(
            id: SessionID("s-1"),
            presenter: presenter,
            clock: clock,
            limits: AuthorityLimits(commitBudget: 4),
            admissionOrder: .reserveAfterConfirmation
        )

        let firstInvocation = plannerAuthoredCommit(0)
        let secondInvocation = plannerAuthoredCommit(1)
        async let first = session.authorize(firstInvocation).decision
        async let second = session.authorize(secondInvocation).decision

        await presenter.waitForArrivals(2)
        let parkedCount = await presenter.arrivalCount
        XCTAssertEqual(parkedCount, 2, "both invocations must be inside the suspension point at once")

        await presenter.release()
        _ = await first
        _ = await second
    }
}
