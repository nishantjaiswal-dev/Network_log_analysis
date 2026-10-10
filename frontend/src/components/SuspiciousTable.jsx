import { useMemo, useState, useEffect, useRef } from 'react';
import RiskBadge, { DataOriginTag } from './RiskBadge';
import Icon from './Icon';
import { formatDateTime, formatNumber, parseTime } from '../format';
import './SuspiciousTable.css';

const LEVEL_OPTIONS = [
  { value: 'MEDIUM', label: 'Medium+' },
  { value: 'HIGH', label: 'High+' },
  { value: 'CRITICAL', label: 'Critical' },
];

function searchText(ev) {
  return [
    ev.event_type, ev.log_source, ev.provider, ev.event_id, ev.message, ev.user,
    ev.process_name, ev.command_line, ev.source_ip, ev.destination_ip, ev.computer,
    ...(ev.analysis_reasons || []),
  ].filter(Boolean).join(' ').toLowerCase();
}

function getTacticTag(reasons = []) {
  const text = reasons.join(' ').toLowerCase();
  if (text.includes('admin') || text.includes('privilege') || text.includes('group')) return 'Privilege Escalation';
  if (text.includes('encoded') || text.includes('command') || text.includes('powershell')) return 'Execution';
  if (text.includes('logon') || text.includes('credential') || text.includes('password')) return 'Credential Access';
  if (text.includes('service') || text.includes('schedule') || text.includes('persist')) return 'Persistence';
  if (text.includes('evasion') || text.includes('clear') || text.includes('tamper')) return 'Defense Evasion';
  return null;
}

function ScoreBar({ score, level }) {
  const value = score == null ? 0 : Math.round(score);
  return (
    <div className={`score-bar score-bar--${(level || 'low').toLowerCase()}`} title={`Risk score ${value}/100`}>
      <span className="score-bar__value">{score == null ? '—' : value}</span>
      <span className="score-bar__track"><span className="score-bar__fill" style={{ width: `${value}%` }} /></span>
    </div>
  );
}

function SkeletonRows() {
  return Array.from({ length: 6 }, (_, i) => (
    <tr key={i} className="skeleton-row">
      <td colSpan={5}><div className="skeleton" style={{ height: 18, width: `${90 - i * 8}%` }} /></td>
    </tr>
  ));
}

export default function SuspiciousTable({
  events,
  total,
  selectedId,
  onSelect,
  minRiskLevel,
  onChangeMinRiskLevel,
  loading,
  hasUnanalyzed,
  timeFilter,
  onClearTimeFilter,
  query,
  onQueryChange,
}) {
  const [internalQuery, setInternalQuery] = useState('');
  const activeQuery = query !== undefined ? query : internalQuery;
  const setQuery = onQueryChange || setInternalQuery;

  const [sortField, setSortField] = useState('risk');
  const [sortDir, setSortDir] = useState('desc'); // 'desc' or 'asc'
  const tableRef = useRef(null);

  // Filter by query and by time range
  const filtered = useMemo(() => {
    let list = events || [];
    if (timeFilter) {
      list = list.filter((ev) => {
        const t = parseTime(ev.timestamp);
        return t != null && t >= timeFilter.startTime && t <= timeFilter.endTime;
      });
    }

    const q = (activeQuery || '').trim().toLowerCase();
    if (q) {
      list = list.filter((ev) => searchText(ev).includes(q));
    }

    // Sort
    return [...list].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'risk') {
        cmp = (a.risk_score ?? 0) - (b.risk_score ?? 0);
      } else if (sortField === 'time') {
        cmp = (parseTime(a.timestamp) ?? 0) - (parseTime(b.timestamp) ?? 0);
      } else if (sortField === 'event') {
        cmp = (a.event_type || '').localeCompare(b.event_type || '');
      } else if (sortField === 'anomaly') {
        cmp = (a.anomaly_score ?? 0) - (b.anomaly_score ?? 0);
      }
      return sortDir === 'desc' ? -cmp : cmp;
    });
  }, [events, timeFilter, activeQuery, sortField, sortDir]);

  function handleSort(field) {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir(field === 'event' ? 'asc' : 'desc');
    }
  }

  // Keyboard navigation through rows
  useEffect(() => {
    function onKeyDown(e) {
      if (!tableRef.current || document.activeElement?.tagName === 'INPUT') return;
      if (e.key === 'ArrowDown' || e.key === 'j') {
        e.preventDefault();
        const currentIndex = filtered.findIndex((ev) => ev.id === selectedId);
        const nextIndex = Math.min(filtered.length - 1, currentIndex + 1);
        if (filtered[nextIndex]) onSelect(filtered[nextIndex].id);
      } else if (e.key === 'ArrowUp' || e.key === 'k') {
        e.preventDefault();
        const currentIndex = filtered.findIndex((ev) => ev.id === selectedId);
        const prevIndex = Math.max(0, currentIndex - 1);
        if (filtered[prevIndex]) onSelect(filtered[prevIndex].id);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [filtered, selectedId, onSelect]);

  const emptyMessage = activeQuery
    ? `No suspicious events match “${activeQuery}”.`
    : timeFilter
      ? 'No flagged events inside this time window.'
      : hasUnanalyzed
        ? 'Events are waiting to be scored — click Run analysis to find suspicious activity.'
        : 'Nothing at this risk level. That’s a good sign — try a lower threshold to review more.';

  return (
    <section className="panel suspicious-panel" aria-labelledby="suspicious-title" ref={tableRef}>
      <div className="panel__header">
        <div>
          <h2 className="panel__title" id="suspicious-title">Suspicious events</h2>
          <p className="panel__subtitle">
            {total == null
              ? 'Ranked by risk score, most severe first.'
              : `${activeQuery || timeFilter ? `${formatNumber(filtered.length)} of ` : ''}${formatNumber(total)} flagged, most severe first.`}
            {total != null && total > events.length && !timeFilter && ` Showing top ${formatNumber(events.length)}.`}
          </p>
        </div>
        <div className="suspicious-panel__controls">
          <label className="search-field">
            <Icon name="search" size={14} />
            <span className="sr-only">Search suspicious events</span>
            <input
              type="search"
              placeholder="Search type, user, process, reason…"
              value={activeQuery}
              onChange={(e) => setQuery(e.target.value)}
            />
            {activeQuery && (
              <button
                className="search-field__clear"
                onClick={() => setQuery('')}
                title="Clear search"
                type="button"
              >
                <Icon name="close" size={12} />
              </button>
            )}
          </label>
          <div className="segmented" role="radiogroup" aria-label="Minimum risk level">
            {LEVEL_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                role="radio"
                aria-checked={minRiskLevel === opt.value}
                className={`segmented__item segmented__item--${opt.value.toLowerCase()} ${minRiskLevel === opt.value ? 'is-active' : ''}`}
                onClick={() => onChangeMinRiskLevel(opt.value)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {(timeFilter || activeQuery) && (
        <div className="table-active-filters">
          <span className="table-active-filters__label">Active filters:</span>
          {timeFilter && (
            <span className="filter-badge">
              <Icon name="clock" size={12} />
              <span>Time window active</span>
              <button onClick={onClearTimeFilter} title="Remove time filter">×</button>
            </span>
          )}
          {activeQuery && (
            <span className="filter-badge">
              <Icon name="search" size={12} />
              <span>Matching “{activeQuery}”</span>
              <button onClick={() => setQuery('')} title="Clear search">×</button>
            </span>
          )}
          <span className="table-active-filters__kb-hint">Press <kbd>↑</kbd> / <kbd>↓</kbd> or <kbd>j</kbd>/<kbd>k</kbd> to step through rows</span>
        </div>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col" className="col-risk is-sortable" onClick={() => handleSort('risk')}>
                <div className="th-content">
                  <span>Risk</span>
                  <Icon name={sortField === 'risk' ? (sortDir === 'asc' ? 'sortAsc' : 'sortDesc') : 'sortAsc'} size={12} className={sortField === 'risk' ? 'is-active' : 'is-dim'} />
                </div>
              </th>
              <th scope="col" className="col-time is-sortable" onClick={() => handleSort('time')}>
                <div className="th-content">
                  <span>When</span>
                  <Icon name={sortField === 'time' ? (sortDir === 'asc' ? 'sortAsc' : 'sortDesc') : 'sortAsc'} size={12} className={sortField === 'time' ? 'is-active' : 'is-dim'} />
                </div>
              </th>
              <th scope="col" className="is-sortable" onClick={() => handleSort('event')}>
                <div className="th-content">
                  <span>Event</span>
                  <Icon name={sortField === 'event' ? (sortDir === 'asc' ? 'sortAsc' : 'sortDesc') : 'sortAsc'} size={12} className={sortField === 'event' ? 'is-active' : 'is-dim'} />
                </div>
              </th>
              <th scope="col" className="col-reason">Why flagged</th>
              <th scope="col" className="col-anomaly is-sortable" onClick={() => handleSort('anomaly')}>
                <div className="th-content">
                  <span>Anomaly</span>
                  <Icon name={sortField === 'anomaly' ? (sortDir === 'asc' ? 'sortAsc' : 'sortDesc') : 'sortAsc'} size={12} className={sortField === 'anomaly' ? 'is-active' : 'is-dim'} />
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            {loading && events.length === 0 && <SkeletonRows />}
            {filtered.map((ev) => {
              const reasons = ev.analysis_reasons || [];
              const tactic = getTacticTag(reasons);
              return (
                <tr
                  key={ev.id}
                  className={ev.id === selectedId ? 'is-selected' : ''}
                  onClick={() => onSelect(ev.id)}
                  tabIndex={0}
                  aria-selected={ev.id === selectedId}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(ev.id);
                    }
                  }}
                >
                  <td className="col-risk">
                    <RiskBadge level={ev.risk_level} size="sm" />
                    <ScoreBar score={ev.risk_score} level={ev.risk_level} />
                  </td>
                  <td className="col-time mono">
                    <span className="cell-time">{formatDateTime(ev.timestamp)}</span>
                    <DataOriginTag origin={ev.data_origin} />
                  </td>
                  <td className="col-event">
                    <div className="cell-primary">{ev.event_type}</div>
                    <div className="cell-secondary">
                      <span>{ev.log_source}</span>
                      {ev.event_id != null && <span className="mono">ID {ev.event_id}</span>}
                      {ev.user && <span className="entity-chip" onClick={(e) => { e.stopPropagation(); setQuery(ev.user); }} title="Filter by this user">{ev.user}</span>}
                    </div>
                  </td>
                  <td className="col-reason">
                    <div className="cell-reason" title={reasons.join('\n')}>
                      {tactic && <span className="table-tactic-tag">{tactic}</span>}
                      {reasons[0] || '—'}
                    </div>
                    {reasons.length > 1 && <div className="cell-more">+{reasons.length - 1} more reason{reasons.length > 2 ? 's' : ''}</div>}
                  </td>
                  <td className="col-anomaly mono">{ev.anomaly_score != null ? ev.anomaly_score.toFixed(2) : '—'}</td>
                </tr>
              );
            })}
            {!loading && filtered.length === 0 && (
              <tr className="empty-row">
                <td colSpan={5}>
                  <Icon name={activeQuery || timeFilter ? 'search' : 'check'} size={18} />
                  <span>{emptyMessage}</span>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
