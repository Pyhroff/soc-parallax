"""Build and query behavioral baselines.

A baseline is, per (entity_type, entity_id, feature), a frequency histogram
{value: count} plus a sample_count. Probability of a value = count / sample_count.
Unseen values get a smoothed probability so rarity scoring stays finite.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.baseline.features import extract
from app.config import settings
from app.db import postgres as pg
from app.schemas.event import UnifiedEvent

# Laplace smoothing: pretend we've seen this many "other" possible values.
SMOOTHING = 0.5


def build_baselines(training_window_days: int | None = None) -> dict:
    """Scan the events table over the training window and (re)build all baselines.

    Returns a small summary for the API/CLI.
    """
    days = training_window_days or settings.training_window_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    rows = pg.query(
        'SELECT payload, "timestamp" FROM events WHERE "timestamp" >= %s',
        (cutoff,),
    )

    # histograms[(etype, eid, feature)] = {value: count}
    histograms: dict[tuple[str, str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    seen: dict[tuple[str, str, str], list[datetime]] = defaultdict(list)

    for row in rows:
        ev = UnifiedEvent.model_validate(row["payload"])
        for o in extract(ev):
            key = (o.entity_type, o.entity_id, o.feature)
            histograms[key][o.value] += 1
            seen[key].append(ev.timestamp)

    written = 0
    for (etype, eid, feature), hist in histograms.items():
        times = seen[(etype, eid, feature)]
        sample_count = sum(hist.values())
        pg.execute(
            """
            INSERT INTO baselines
                (entity_type, entity_id, feature, distribution, sample_count, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (entity_type, entity_id, feature) DO UPDATE SET
                distribution = EXCLUDED.distribution,
                sample_count = EXCLUDED.sample_count,
                first_seen   = LEAST(baselines.first_seen, EXCLUDED.first_seen),
                last_seen    = GREATEST(baselines.last_seen, EXCLUDED.last_seen),
                updated_at   = now()
            """,
            (etype, eid, feature, pg.as_jsonb(dict(hist)), sample_count, min(times), max(times)),
        )
        written += 1

    return {
        "training_window_days": days,
        "events_scanned": len(rows),
        "baselines_written": written,
        "entities": len({(e, i) for (e, i, _f) in histograms}),
    }


def get_baseline(entity_type: str, entity_id: str, feature: str) -> dict | None:
    rows = pg.query(
        """SELECT distribution, sample_count, first_seen, last_seen
           FROM baselines
           WHERE entity_type=%s AND entity_id=%s AND feature=%s""",
        (entity_type, entity_id, feature),
    )
    return rows[0] if rows else None


def probability(baseline: dict | None, value: str) -> float:
    """Smoothed probability of `value` given a baseline histogram.

    No baseline at all -> return a small constant so the entity isn't penalized
    for simply being new (that's handled separately by 'cold start' logic).
    """
    if not baseline:
        return 0.05
    dist: dict[str, int] = baseline["distribution"]
    total = baseline["sample_count"]
    distinct = len(dist)
    count = dist.get(value, 0)
    return (count + SMOOTHING) / (total + SMOOTHING * (distinct + 1))


def rarity_score(baseline: dict | None, value: str) -> float:
    """Map probability to a 0..1 anomaly strength via normalized surprise.

    surprise = -log(p); we squash with a logistic-ish cap so a single ultra-rare
    value can't dominate beyond 1.0.
    """
    p = probability(baseline, value)
    surprise = -math.log(p)
    # -log(0.05) ~= 3.0 (a fresh/unseen value); scale so ~3.0 -> ~0.9
    return min(1.0, surprise / 3.3)


def numeric_zscore(baseline: dict | None, value: float) -> float:
    """For numeric features stored as {mean, std}. Returns 0..1 strength."""
    if not baseline:
        return 0.0
    dist = baseline["distribution"]
    mean = dist.get("mean", 0.0)
    std = dist.get("std", 1.0) or 1.0
    z = abs((value - mean) / std)
    return min(1.0, z / 4.0)   # |z|>=4 -> max
