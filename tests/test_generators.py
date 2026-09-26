"""Generator behaviour: realism guarantees the ML phase depends on."""

from __future__ import annotations

import ipaddress
import json

import pytest

from forensics.ingestion.generators import GROUND_TRUTH_LABEL, TelemetryGenerator
from forensics.ingestion.schemas import EventCategory


def _drain(gen: TelemetryGenerator, count: int) -> list:
    events = []
    while len(events) < count:
        events.extend(gen.next_events())
    return events[:count]


def test_generation_is_deterministic_for_a_seed() -> None:
    """Reproducibility matters: a training set must be regenerable exactly."""
    a = _drain(TelemetryGenerator(seed=99), 200)
    b = _drain(TelemetryGenerator(seed=99), 200)
    # event_id/timestamp are intentionally nondeterministic; compare content.
    assert [e.message for e in a] == [e.message for e in b]
    assert [e.host.name for e in a] == [e.host.name for e in b]
    # Campaign correlators must come from the seeded RNG too, not uuid4().
    assert [e.labels.get(GROUND_TRUTH_LABEL, {}).get("campaign_id") for e in a] == [
        e.labels.get(GROUND_TRUTH_LABEL, {}).get("campaign_id") for e in b
    ]


def test_different_seeds_diverge() -> None:
    a = _drain(TelemetryGenerator(seed=1), 100)
    b = _drain(TelemetryGenerator(seed=2), 100)
    assert [e.message for e in a] != [e.message for e in b]


@pytest.mark.parametrize("target", [0.0, 0.01, 0.05, 0.25])
def test_anomaly_ratio_converges_to_target(target: float) -> None:
    gen = TelemetryGenerator(seed=5, anomaly_rate=target)
    _drain(gen, 20_000)
    assert gen.observed_anomaly_ratio == pytest.approx(target, abs=0.01)


def test_zero_anomaly_rate_produces_a_clean_baseline() -> None:
    gen = TelemetryGenerator(seed=3, anomaly_rate=0.0)
    events = _drain(gen, 2000)
    assert all(GROUND_TRUTH_LABEL not in e.labels for e in events)


def test_every_event_serialises_to_json(generator: TelemetryGenerator) -> None:
    for event in _drain(generator, 1000):
        payload = json.loads(event.to_json())
        assert payload["event_id"] and payload["timestamp"]
        assert payload["host"]["name"]
        assert 0 <= payload["severity"] <= 7


def test_all_categories_are_represented(generator: TelemetryGenerator) -> None:
    categories = {e.category for e in _drain(generator, 3000)}
    assert {
        EventCategory.AUTHENTICATION,
        EventCategory.PROCESS,
        EventCategory.NETWORK,
    } <= categories


def test_campaign_events_share_an_id_and_are_contiguous() -> None:
    gen = TelemetryGenerator(seed=21, anomaly_rate=0.3)
    events = _drain(gen, 5000)
    campaigns: dict[str, list[int]] = {}
    for index, event in enumerate(events):
        truth = event.labels.get(GROUND_TRUTH_LABEL)
        if truth:
            campaigns.setdefault(truth["campaign_id"], []).append(index)
    assert campaigns, "expected at least one campaign"
    for positions in campaigns.values():
        # A campaign must not be interleaved with unrelated traffic, otherwise
        # Phase 2's session windows cannot reconstruct it.
        assert positions == list(range(positions[0], positions[0] + len(positions)))


def test_campaign_steps_are_ordered() -> None:
    gen = TelemetryGenerator(seed=8, anomaly_rate=0.3)
    campaigns: dict[str, list[int]] = {}
    for event in _drain(gen, 5000):
        truth = event.labels.get(GROUND_TRUTH_LABEL)
        if truth:
            campaigns.setdefault(truth["campaign_id"], []).append(truth["step"])
    for steps in campaigns.values():
        assert steps == sorted(steps)


def test_no_routable_public_ips_are_emitted(generator: TelemetryGenerator) -> None:
    """Synthetic data must never reference real internet hosts."""
    documentation_ranges = [
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
    ]
    for event in _drain(generator, 3000):
        if event.network is None:
            continue
        for value in (event.network.source_ip, event.network.destination_ip):
            address = ipaddress.ip_address(value)
            assert address.is_private or any(
                address in net for net in documentation_ranges
            ), f"{value} is a routable public address"


def test_brute_force_campaign_shape() -> None:
    """The signature Phase 3 must learn: repeated failures, one source, one host."""
    gen = TelemetryGenerator(seed=2, anomaly_rate=0.5)
    events = _drain(gen, 8000)
    by_campaign: dict[str, list] = {}
    for event in events:
        truth = event.labels.get(GROUND_TRUTH_LABEL)
        if truth and truth["scenario"].startswith("ssh_brute_force"):
            by_campaign.setdefault(truth["campaign_id"], []).append(event)

    assert by_campaign, "expected brute-force campaigns"
    for campaign in by_campaign.values():
        failures = [e for e in campaign if e.outcome == "failure"]
        assert len(failures) >= 12
        assert len({e.host.name for e in campaign}) == 1
        assert len({e.network.source_ip for e in failures if e.network}) == 1


def test_beaconing_intervals_are_low_variance() -> None:
    """Periodicity is the detection signal, so the generator must preserve it."""
    import datetime as dt

    gen = TelemetryGenerator(seed=17, anomaly_rate=0.5)
    events = _drain(gen, 8000)
    beacons: dict[str, list[dt.datetime]] = {}
    for event in events:
        truth = event.labels.get(GROUND_TRUTH_LABEL)
        if truth and truth["scenario"] == "c2_beaconing":
            beacons.setdefault(truth["campaign_id"], []).append(
                dt.datetime.fromisoformat(event.timestamp)
            )

    assert beacons, "expected beaconing campaigns"
    for stamps in beacons.values():
        if len(stamps) < 3:
            continue
        gaps = [
            (b - a).total_seconds()
            for a, b in zip(sorted(stamps), sorted(stamps)[1:], strict=False)
        ]
        mean_gap = sum(gaps) / len(gaps)
        # Jitter is +/-5% of the interval, so spread stays well under 25%.
        assert max(abs(g - mean_gap) for g in gaps) < mean_gap * 0.25
