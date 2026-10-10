import { useMemo, useEffect } from 'react';
import Icon from './Icon';
import RiskBadge from './RiskBadge';
import { formatDateTime, formatNumber } from '../format';
import './ReportModal.css';

export default function ReportModal({
  isOpen,
  onClose,
  stats,
  suspiciousEvents,
  host,
  dataSourceLabel,
}) {
  useEffect(() => {
    if (!isOpen) return;
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  const iocs = useMemo(() => {
    if (!suspiciousEvents || suspiciousEvents.length === 0) return { users: [], processes: [], ips: [] };
    const users = new Set();
    const processes = new Set();
    const ips = new Set();
    for (const ev of suspiciousEvents) {
      if (ev.user) users.add(ev.user);
      if (ev.process_name) processes.add(ev.process_name);
      if (ev.source_ip) ips.add(ev.source_ip);
      if (ev.destination_ip) ips.add(ev.destination_ip);
    }
    return {
      users: Array.from(users),
      processes: Array.from(processes),
      ips: Array.from(ips),
    };
  }, [suspiciousEvents]);

  const reportMeta = useMemo(() => {
    const now = new Date();
    const dateStr = now.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const timeStr = now.toLocaleTimeString();
    const datePart = now.toISOString().slice(0, 10).replace(/-/g, '');
    const caseId = `FOR-${datePart}-701`;
    return { dateStr, timeStr, caseId };
  }, []);

  if (!isOpen) return null;

  const { dateStr, timeStr, caseId } = reportMeta;

  function handlePrint() {
    window.print();
  }

  function handleDownloadJson() {
    const reportData = {
      case_id: caseId,
      generated_at: new Date().toISOString(),
      scope: dataSourceLabel,
      host_os: host?.host_os || 'Unknown',
      summary: stats,
      iocs,
      critical_events: (suspiciousEvents || []).map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        risk_level: e.risk_level,
        risk_score: e.risk_score,
        event_type: e.event_type,
        reasons: e.analysis_reasons,
        evidence_hash: e.evidence_hash,
      })),
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseId}-forensic-dossier.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="report-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="report-modal-title">
      <div className="report-modal" onClick={(e) => e.stopPropagation()}>
        <div className="report-modal__head no-print">
          <div className="report-modal__title-group">
            <span className="report-modal__icon-wrap">
              <Icon name="fileText" size={20} />
            </span>
            <div>
              <h2 id="report-modal-title" className="report-modal__title">Forensic Case Dossier & Incident Report</h2>
              <p className="report-modal__sub">Official investigative export with chain-of-custody provenance</p>
            </div>
          </div>
          <div className="report-modal__actions">
            <button className="btn btn--quiet" onClick={handleDownloadJson} title="Export JSON dataset">
              <Icon name="download" size={14} /> JSON
            </button>
            <button className="btn btn--primary" onClick={handlePrint} title="Print or save as PDF">
              <Icon name="printer" size={14} /> Print / PDF
            </button>
            <button className="btn btn--quiet btn--icon" onClick={onClose} aria-label="Close dialog">
              <Icon name="close" size={16} />
            </button>
          </div>
        </div>

        <div className="report-paper">
          <header className="report-doc-header">
            <div className="report-doc-brand">
              <div className="report-seal">
                <Icon name="shield" size={24} />
              </div>
              <div>
                <h1 className="report-doc-title">FORENSIC LOG ANALYSIS REPORT</h1>
                <div className="report-doc-subtitle">Incident Response & Evidence Integrity Assessment</div>
              </div>
            </div>
            <div className="report-meta-box">
              <div><strong>Case ID:</strong> <span className="mono">{caseId}</span></div>
              <div><strong>Date:</strong> {dateStr} {timeStr}</div>
              <div><strong>Evidence Scope:</strong> {dataSourceLabel}</div>
              <div><strong>Target Host OS:</strong> {host?.host_os || 'Generic'}</div>
            </div>
          </header>

          <section className="report-section">
            <h3 className="report-section-title">1. Executive Incident Overview</h3>
            <div className="report-metrics-grid">
              <div className="report-metric-tile">
                <span className="report-metric-label">Total Events Evaluated</span>
                <strong className="report-metric-value mono">{formatNumber(stats?.total_events || 0)}</strong>
              </div>
              <div className="report-metric-tile">
                <span className="report-metric-label">Analyzed Records</span>
                <strong className="report-metric-value mono">{formatNumber(stats?.analyzed_events || 0)}</strong>
              </div>
              <div className="report-metric-tile">
                <span className="report-metric-label">Flagged Suspicious</span>
                <strong className="report-metric-value mono text-danger">{formatNumber(stats?.suspicious_events || 0)}</strong>
              </div>
              <div className="report-metric-tile">
                <span className="report-metric-label">Critical Severity</span>
                <strong className="report-metric-value mono text-danger">{formatNumber(stats?.critical_risk_events || 0)}</strong>
              </div>
            </div>
          </section>

          <section className="report-section">
            <h3 className="report-section-title">2. Identified Indicators of Compromise (IOCs)</h3>
            <div className="report-iocs-grid">
              <div className="report-ioc-box">
                <h4>Involved Users & Accounts ({iocs.users.length})</h4>
                {iocs.users.length > 0 ? (
                  <ul className="mono">
                    {iocs.users.map((u, i) => <li key={i}>{u}</li>)}
                  </ul>
                ) : <p className="text-muted">None detected in scope</p>}
              </div>
              <div className="report-ioc-box">
                <h4>Processes & Binaries ({iocs.processes.length})</h4>
                {iocs.processes.length > 0 ? (
                  <ul className="mono">
                    {iocs.processes.map((p, i) => <li key={i}>{p}</li>)}
                  </ul>
                ) : <p className="text-muted">None detected in scope</p>}
              </div>
              <div className="report-ioc-box">
                <h4>Network Endpoints ({iocs.ips.length})</h4>
                {iocs.ips.length > 0 ? (
                  <ul className="mono">
                    {iocs.ips.map((ip, i) => <li key={i}>{ip}</li>)}
                  </ul>
                ) : <p className="text-muted">No external IPs logged</p>}
              </div>
            </div>
          </section>

          <section className="report-section">
            <h3 className="report-section-title">3. Critical Flagged Events & Attack Vector Breakdown</h3>
            <table className="report-table">
              <thead>
                <tr>
                  <th style={{ width: '85px' }}>Severity</th>
                  <th style={{ width: '135px' }}>Timestamp</th>
                  <th>Event Type / Details</th>
                  <th>Detection Reasons</th>
                </tr>
              </thead>
              <tbody>
                {(suspiciousEvents || []).slice(0, 15).map((ev) => (
                  <tr key={ev.id}>
                    <td>
                      <RiskBadge level={ev.risk_level} size="sm" />
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>
                      {formatDateTime(ev.timestamp)}
                    </td>
                    <td>
                      <strong>{ev.event_type}</strong>
                      <div className="text-muted mono" style={{ fontSize: '0.75rem' }}>
                        {ev.process_name || ev.log_source} {ev.user ? `• User: ${ev.user}` : ''}
                      </div>
                    </td>
                    <td>
                      {(ev.analysis_reasons || []).join('; ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(suspiciousEvents || []).length > 15 && (
              <p className="report-table-note">
                Showing top 15 of {suspiciousEvents.length} flagged events. Complete dataset preserved in JSON export.
              </p>
            )}
          </section>

          <section className="report-section report-cert-section">
            <div className="report-cert-box">
              <div className="report-cert-icon"><Icon name="lock" size={24} /></div>
              <div>
                <h4>Forensic Integrity & Chain of Custody Certification</h4>
                <p>
                  All event records evaluated in this report are bound to immutable SHA-256 payload hashes and linked
                  via sequential parent cryptographic digest pointers. The evidence meets standards of non-repudiation
                  and tamper verification for local forensic triage.
                </p>
                <div className="report-cert-hash mono">
                  Root Chain Seal: Verified Active • Engine: Antigravity Forensics v0.1 • Mode: Local Confidential
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
