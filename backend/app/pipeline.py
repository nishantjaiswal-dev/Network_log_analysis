"""
Pipeline orchestration.

Wires the stages together:

    raw records -> normalize -> [store, unanalyzed]
                                      |
                       run_analysis()  (feature extraction -> ML -> risk scoring)
                                      |
                                 [store, analyzed]

Split into two entry points (`ingest_raw_events` and `run_analysis`)
deliberately, matching spec section 8's `POST /analysis/run`: collection
and analysis are separate steps an investigator can trigger
independently (e.g. collect now, review later, re-run analysis after
tuning).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.filtering import apply_event_scope, scope_payload
from app.normalizer.normalize import normalize_batch
from app.features.feature_extraction import extract_features
from app.ml.anomaly_detector import AnomalyDetector
from app.scoring.risk_scoring import score_event
from app.schemas import NormalizedEvent


def new_batch_id(prefix: str = "batch") -> str:
    return f"{prefix}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}"


def ingest_raw_events(db: Session, raw_events: list[dict], batch_id: str | None = None) -> dict:
    """
    Normalize and store a batch of raw records. Does NOT run ML/risk
    scoring - that happens in a separate, explicit `run_analysis` call
    (spec section 8: POST /analysis/run).

    Enforces cryptographic chain-of-custody by linking each new event to
    the preceding event's SHA-256 evidence digest.
    """
    batch_id = batch_id or new_batch_id()
    normalized = normalize_batch(raw_events)

    last_row = db.query(models.Event).order_by(models.Event.id.desc()).first()
    current_prev_hash = last_row.evidence_hash if (last_row and last_row.evidence_hash) else ("0" * 64)

    inserted = 0
    for ne in normalized:
        ne.previous_hash = current_prev_hash
        row = models.Event(
            event_uid=ne.event_uid,
            data_origin=ne.data_origin,
            operating_system=ne.operating_system,
            timestamp=ne.timestamp,
            event_id=ne.event_id,
            log_source=ne.log_source,
            provider=ne.provider,
            level=ne.level,
            computer=ne.computer,
            user=ne.user,
            process_id=ne.process_id,
            message=ne.message,
            parent_process=ne.parent_process,
            process_name=ne.process_name,
            command_line=ne.command_line,
            source_ip=ne.source_ip,
            destination_ip=ne.destination_ip,
            source_port=ne.source_port,
            destination_port=ne.destination_port,
            event_type=ne.event_type,
            severity=ne.severity,
            raw_data=ne.raw_data,
            evidence_hash=ne.evidence_hash,
            previous_hash=current_prev_hash,
            analyzed=False,
            batch_id=batch_id,
        )
        current_prev_hash = ne.evidence_hash or current_prev_hash
        db.add(row)
        inserted += 1

    db.commit()
    return {"batch_id": batch_id, "events_ingested": inserted}


def _row_to_normalized(row: models.Event) -> NormalizedEvent:
    """Rehydrate a NormalizedEvent from a DB row for the ML/scoring stages."""
    return NormalizedEvent(
        event_uid=row.event_uid,
        data_origin=row.data_origin,
        operating_system=row.operating_system,
        timestamp=row.timestamp,
        event_id=row.event_id,
        log_source=row.log_source,
        provider=row.provider,
        level=row.level,
        computer=row.computer,
        user=row.user,
        process_id=row.process_id,
        message=row.message,
        parent_process=row.parent_process,
        process_name=row.process_name,
        command_line=row.command_line,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        source_port=row.source_port,
        destination_port=row.destination_port,
        event_type=row.event_type,
        severity=row.severity,
        raw_data=row.raw_data,
        evidence_hash=row.evidence_hash or "",
        previous_hash=row.previous_hash,
    )


def verify_evidence_integrity(db: Session, limit: int = 5000) -> dict:
    """
    Audit cryptographic chain of custody. Verifies that every stored row's
    `raw_data` matches its `evidence_hash` (detecting database modifications)
    and that the hash sequence has no broken links.
    """
    rows = db.query(models.Event).order_by(models.Event.id.asc()).limit(limit).all()
    if not rows:
        return {"status": "EMPTY", "total_checked": 0, "tampered_events": []}

    tampered = []
    expected_prev = "0" * 64

    for r in rows:
        # 1. Verify content integrity (detect in-place edits to raw_data / timestamp)
        expected_hash = hashlib.sha256(
            f"{r.raw_data}:{r.event_uid}:{r.timestamp}".encode("utf-8")
        ).hexdigest()

        if r.evidence_hash and r.evidence_hash != expected_hash:
            tampered.append({
                "id": r.id,
                "event_uid": r.event_uid,
                "reason": "Hash mismatch: raw_data or timestamp altered in database.",
                "stored_hash": r.evidence_hash,
                "computed_hash": expected_hash,
            })
        elif r.previous_hash and r.previous_hash != expected_prev and expected_prev != ("0" * 64):
            tampered.append({
                "id": r.id,
                "event_uid": r.event_uid,
                "reason": "Broken chain link: row inserted, deleted, or out of order.",
                "expected_previous_hash": expected_prev,
                "stored_previous_hash": r.previous_hash,
            })

        if r.evidence_hash:
            expected_prev = r.evidence_hash

    return {
        "status": "TAMPER_DETECTED" if tampered else "INTEGRITY_VERIFIED",
        "total_checked": len(rows),
        "tampered_count": len(tampered),
        "tampered_events": tampered,
    }


def run_analysis(
    db: Session,
    batch_id: str | None = None,
    rerun_all: bool = False,
    operating_system: str | None = None,
    data_origin: str | None = None,
) -> dict:
    """
    Run feature extraction -> Isolation Forest -> risk scoring over
    events, then write the results back.

    - If `batch_id`, `operating_system`, or `data_origin` is given, analyzes
      only that selected scope (and fits an isolated baseline for it).
    - Otherwise, if `rerun_all` is True, re-analyzes the entire table
      as one baseline.
    - Otherwise (default), analyzes whatever hasn't been analyzed yet.

    Only ML/risk-related columns are updated - `raw_data` and all
    normalized fields are left untouched (evidence preservation).
    """
    query = db.query(models.Event)
    if batch_id:
        query = query.filter(models.Event.batch_id == batch_id)
    query = apply_event_scope(
        query,
        models.Event,
        operating_system=operating_system,
        data_origin=data_origin,
    )

    # A selected batch/source is an explicit re-analysis scope, matching the
    # original batch behavior.  The unscoped default remains unchanged: it
    # only processes newly ingested events unless rerun_all=True.
    if not (batch_id or operating_system or data_origin or rerun_all):
        query = query.filter(models.Event.analyzed == False)  # noqa: E712

    rows = query.order_by(models.Event.timestamp.asc()).all()
    if not rows:
        return {
            "analyzed_events": 0,
            "message": "No events to analyze.",
            "batch_id": batch_id,
            "filters": scope_payload(operating_system, data_origin),
        }

    normalized_events = [_row_to_normalized(r) for r in rows]

    feature_df = extract_features(normalized_events)  # also fills e.features in place

    detector = AnomalyDetector()
    anomaly_scores = detector.fit_predict(feature_df)

    now = datetime.now(timezone.utc)
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for row, ne, anomaly_score in zip(rows, normalized_events, anomaly_scores):
        risk_score, risk_level, reasons = score_event(ne, float(anomaly_score))

        row.features_json = json.dumps(ne.features)
        row.anomaly_score = round(float(anomaly_score), 4)
        row.risk_score = risk_score
        row.risk_level = risk_level
        row.analysis_reasons = json.dumps(reasons)
        row.analyzed = True
        row.analyzed_at = now

        risk_counts[risk_level] += 1

    db.commit()

    return {
        "analyzed_events": len(rows),
        "risk_level_breakdown": risk_counts,
        "batch_id": batch_id,
        "filters": scope_payload(operating_system, data_origin),
    }
