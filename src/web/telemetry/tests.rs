use super::*;
use crate::config::WebCarrier;
use crate::web::manager::CarrierFailure;

#[test]
fn fixed_counter_sets_and_acceptor_guard_are_exact() {
    let telemetry = WebTelemetry::new();
    let guard = telemetry.acceptor_guard();
    assert_eq!(telemetry.live_acceptors(), 1);
    telemetry.record_rejection(WebRejectionReason::HttpConnectionCapacity);
    telemetry.record_overload(WebHttpConnectionOverloadOutcome::Dropped);
    telemetry.record_decoy(WebDecoyUpstreamOutcome::ConnectRefused);
    telemetry.record_carrier_selection(
        WebCarrier::Https,
        WebCarrierSelectionDisposition::Cold,
    );
    telemetry.record_carrier_failure(
        WebCarrier::Https,
        WebCarrierFailurePhase::Provisional,
        CarrierFailure::Network,
    );
    telemetry.record_carrier_learning(
        WebCarrier::Https,
        WebCarrierLearningOutcome::Recorded,
    );
    assert_eq!(telemetry.rejection_counters().len(), WebRejectionReason::ALL.len());
    assert_eq!(
        telemetry.overload_counters().len(),
        WebHttpConnectionOverloadOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.decoy_counters().len(),
        WebDecoyUpstreamOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_selection_counters().len(),
        WebCarrier::ALL.len() * WebCarrierSelectionDisposition::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_failure_counters().len(),
        WebCarrier::ALL.len()
            * WebCarrierFailurePhase::ALL.len()
            * CarrierFailure::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_learning_counters().len(),
        WebCarrier::ALL.len() * WebCarrierLearningOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.rejection_total(WebRejectionReason::HttpConnectionCapacity),
        1
    );
    assert_eq!(
        telemetry.last_decoy().map(|value| value.0),
        Some("connect_refused")
    );
    drop(guard);
    assert_eq!(telemetry.live_acceptors(), 0);
}
