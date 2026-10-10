import { useEffect, useState } from 'react';
import RiskBadge, { DataOriginTag } from './RiskBadge';
import Icon from './Icon';
import { formatFullDateTime } from '../format';
import './EventDetailPanel.css';

function getTacticTag(reason = '') {
  const text = reason.toLowerCase();
  if (text.includes('admin') || text.includes('privilege') || text.includes('group')) return 'Privilege Escalation';
  if (text.includes('encoded') || text.includes('command') || text.includes('powershell')) return 'Execution';
  if (text.includes('logon') || text.includes('credential') || text.includes('password') || text.includes('failed')) return 'Credential Access';
  if (text.includes('service') || text.includes('schedule') || text.includes('persist')) return 'Persistence';
  if (text.includes('evasion') || text.includes('clear') || text.includes('tamper')) return 'Defense Evasion';
  return null;
}

function Field({ label, value, mono, wide, onPivot }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className={`detail-field ${wide ? 'detail-field--wide' : ''}`}>
      <dt className="detail-field__label">
        <span>{label}</span>
        {onPivot && (
          <button
            type="button"
            className="pivot-btn"
            onClick={() => onPivot(String(value))}
            title={`Filter by ${label}: ${value}`}
          >
            <Icon name="crosshair" size={11} />
            <span>Pivot</span>
          </button>
        )}
      </dt>
      <dd className={`detail-field__value ${mono ? 'mono' : ''}`}>{value}</dd>
    </div>
  );
}

function ScoreGauge({ score, level }) {
  const value = score == null ? 0 : Math.round(score);
  const circumference = 2 * Math.PI * 26;
  return (
    <div className={`gauge gauge--${(level || 'none').toLowerCase()}`} aria-label={`Risk score ${score == null ? 'not available' : value + ' out of 100'}`}>
      <svg viewBox="0 0 64 64" width="64" height="64" aria-hidden="true">
        <circle cx="32" cy="32" r="26" className="gauge__track" />
        <circle
          cx="32" cy="32" r="26"
          className="gauge__fill"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - value / 100)}
        />
      </svg>
      <span className="gauge__value">{score == null ? '—' : value}</span>
    </div>
  );
}

function Collapsible({ title, children, onCopy }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(onCopy());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable - ignore */
    }
  }

  return (
    <section className="detail-section">
      <div className="collapsible-head">
        <button className="collapsible-toggle" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          <Icon name={open ? 'chevronDown' : 'chevron'} size={14} />
          {title}
        </button>
        {open && onCopy && (
          <button className="btn btn--quiet collapsible-copy" onClick={copy}>
            {copied ? <><Icon name="check" size={13} /> Copied</> : 'Copy'}
          </button>
        )}
      </div>
      {open && children}
    </section>
  );
}

export default function EventDetailPanel({ event, loading, onClose, onPivot }) {
  const open = Boolean(event) || loading;

  useEffect(() => {
    if (!open) return undefined;
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) {
    return (
      <aside className="panel detail-panel detail-panel--empty" aria-label="Event detail">
        <div className="detail-empty">
          <div className="detail-empty__icon"><Icon name="file" size={22} /></div>
          <h2>No event selected</h2>
          <p>Pick an event from the table or timeline to see why it was flagged, its extracted fields, and the original raw evidence.</p>
        </div>
      </aside>
    );
  }

  if (loading && !event) {
    return (
      <>
        <div className="detail-backdrop" onClick={onClose} />
        <aside className="panel detail-panel is-open" aria-label="Event detail" aria-busy="true">
          <div className="detail-panel__body">
            <div className="skeleton" style={{ height: 22, width: '60%' }} />
            <div className="skeleton" style={{ height: 64, marginTop: 16 }} />
            <div className="skeleton" style={{ height: 120, marginTop: 16 }} />
          </div>
        </aside>
      </>
    );
  }

  let prettyRaw = event.raw_data;
  try {
    prettyRaw = JSON.stringify(JSON.parse(event.raw_data), null, 2);
  } catch {
    /* leave as-is if not JSON */
  }
  const reasons = event.analysis_reasons || [];
  const network = (ip, port) => (ip ? `${ip}${port ? ':' + port : ''}` : null);

  // Compute breakdown points
  const anomalyPts = event.anomaly_score != null ? Math.round(event.anomaly_score * 40) : 0;
  const rulePts = event.risk_score != null ? Math.max(0, Math.round(event.risk_score) - anomalyPts) : 0;

  return (
    <>
      <div className="detail-backdrop" onClick={onClose} />
      <aside className="panel detail-panel is-open" aria-labelledby="detail-title">
        <div className="detail-panel__head">
          <div className="detail-panel__titles">
            <span className="detail-panel__case mono">EVT-{String(event.id).padStart(5, '0')}</span>
            <h2 className="detail-panel__title" id="detail-title">{event.event_type}</h2>
            <div className="detail-panel__badges">
              <RiskBadge level={event.risk_level} />
              <DataOriginTag origin={event.data_origin} />
              {event.operating_system && <span className="os-chip">{event.operating_system}</span>}
            </div>
          </div>
          <button className="btn btn--quiet btn--icon" onClick={onClose} aria-label="Close event detail">
            <Icon name="close" />
          </button>
        </div>

        <div className="detail-panel__body">
          <section className="detail-scores">
            <ScoreGauge score={event.risk_score} level={event.risk_level} />
            <div className="detail-scores__text">
              <div className="detail-scores__row">
                <span>Forensic risk score</span>
                <strong className="mono">{event.risk_score != null ? Math.round(event.risk_score) : '—'}<small>/100</small></strong>
              </div>
              <div className="detail-scores__row">
                <span>ML anomaly score</span>
                <strong className="mono">{event.anomaly_score != null ? event.anomaly_score.toFixed(2) : '—'}<small>/1.00</small></strong>
              </div>
              <div className="score-breakdown-bar" title={`Anomaly: ~${anomalyPts} pts, Rules: ~${rulePts} pts`}>
                <span className="score-breakdown-bar__ml" style={{ width: `${anomalyPts}%` }} />
                <span className="score-breakdown-bar__rules" style={{ width: `${rulePts}%` }} />
              </div>
              <p className="detail-scores__note">
                Score composed of <strong>~{anomalyPts} pts</strong> ML anomaly signal + <strong>~{rulePts} pts</strong> rule heuristics.
              </p>
            </div>
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Why flagged & MITRE ATT&CK Mapping</h3>
            {reasons.length > 0 ? (
              <ul className="reason-list">
                {reasons.map((r, i) => {
                  const tactic = getTacticTag(r);
                  return (
                    <li key={i} className={r.startsWith('No significant') ? 'is-benign' : ''}>
                      <Icon name={r.startsWith('No significant') ? 'check' : r.startsWith('High ML') ? 'sparkle' : 'alert'} size={14} />
                      <div className="reason-text-wrap">
                        {tactic && <span className="detail-tactic-chip">{tactic}</span>}
                        <span>{r}</span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="reason-list__empty">Not analyzed yet — run analysis to generate a risk assessment.</p>
            )}
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Event facts & Pivoting</h3>
            <dl className="detail-grid">
              <Field label="Timestamp" value={formatFullDateTime(event.timestamp)} mono wide />
              <Field label="Event ID" value={event.event_id} mono onPivot={onPivot} />
              <Field label="Source" value={event.log_source} onPivot={onPivot} />
              <Field label="Provider" value={event.provider} wide />
              <Field label="Host" value={event.computer} onPivot={onPivot} />
              <Field label="User" value={event.user} onPivot={onPivot} />
              <Field label="Level" value={event.level} />
              <Field label="Process" value={event.process_name} mono wide onPivot={onPivot} />
              <Field label="Process ID" value={event.process_id} mono />
              <Field label="Parent process" value={event.parent_process} mono wide onPivot={onPivot} />
              <Field label="Command line" value={event.command_line} mono wide />
              <Field label="Source IP" value={network(event.source_ip, event.source_port)} mono onPivot={event.source_ip ? () => onPivot(event.source_ip) : null} />
              <Field label="Destination IP" value={network(event.destination_ip, event.destination_port)} mono onPivot={event.destination_ip ? () => onPivot(event.destination_ip) : null} />
            </dl>
          </section>

          <section className="detail-section">
            <h3 className="detail-section__title">Message</h3>
            <p className="detail-message">{event.message || '—'}</p>
          </section>

          {event.features && Object.keys(event.features).length > 0 && (
            <Collapsible title="Extracted ML features" onCopy={() => JSON.stringify(event.features, null, 2)}>
              <div className="feature-grid">
                {Object.entries(event.features).map(([k, v]) => (
                  <div key={k} className="feature-grid__row">
                    <span>{k.replaceAll('_', ' ')}</span>
                    <span className="mono">{String(v)}</span>
                  </div>
                ))}
              </div>
            </Collapsible>
          )}

          {event.evidence_hash && (
            <Collapsible title="Cryptographic evidence integrity (SHA-256)" onCopy={() => event.evidence_hash}>
              <div className="feature-grid">
                <div className="feature-grid__row">
                  <span>Evidence SHA-256</span>
                  <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-all', color: 'var(--accent)' }}>
                    {event.evidence_hash}
                  </span>
                </div>
                {event.previous_hash && (
                  <div className="feature-grid__row">
                    <span>Chain Link (Previous)</span>
                    <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-all' }}>
                      {event.previous_hash}
                    </span>
                  </div>
                )}
              </div>
            </Collapsible>
          )}

          <Collapsible title="Raw event (original evidence)" onCopy={() => prettyRaw}>
            <pre className="raw-block mono">{prettyRaw}</pre>
          </Collapsible>
        </div>
      </aside>
    </>
  );
}
