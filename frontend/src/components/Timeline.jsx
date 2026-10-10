import { useMemo, useState, useRef } from 'react';
import { formatAxis, formatDateTime, formatNumber, parseTime } from '../format';
import Icon from './Icon';
import './Timeline.css';

const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const RISK_COLOR_VAR = {
  LOW: '--risk-low',
  MEDIUM: '--risk-medium',
  HIGH: '--risk-high',
  CRITICAL: '--risk-critical',
};
const TICKS = 5;

function getTacticTag(reasons = []) {
  const text = reasons.join(' ').toLowerCase();
  if (text.includes('admin') || text.includes('privilege') || text.includes('group')) return 'Privilege Escalation';
  if (text.includes('encoded') || text.includes('command') || text.includes('powershell')) return 'Execution';
  if (text.includes('logon') || text.includes('credential') || text.includes('password')) return 'Credential Access';
  if (text.includes('service') || text.includes('schedule') || text.includes('persist')) return 'Persistence';
  if (text.includes('evasion') || text.includes('clear') || text.includes('tamper')) return 'Defense Evasion';
  return null;
}

export default function Timeline({
  events,
  selectedId,
  onSelect,
  timeFilter,
  onTimeFilterChange,
}) {
  const [hover, setHover] = useState(null);
  const [dragStartPct, setDragStartPct] = useState(null);
  const [dragCurrentPct, setDragCurrentPct] = useState(null);
  const trackRef = useRef(null);

  const { points, ticks, minTime, spanTime } = useMemo(() => {
    const timed = (events || [])
      .map((e) => ({ e, t: parseTime(e.timestamp) }))
      .filter((p) => p.t != null);
    if (timed.length === 0) return { points: [], ticks: [], minTime: 0, spanTime: 1 };

    const min = Math.min(...timed.map((p) => p.t));
    const max = Math.max(...timed.map((p) => p.t));
    const span = Math.max(max - min, 1);

    const pts = timed
      .map(({ e, t }) => ({
        id: e.id,
        t,
        pct: ((t - min) / span) * 100,
        heightPct: e.analyzed ? Math.max(12, e.risk_score ?? 0) : 8,
        level: e.analyzed ? (e.risk_level || 'LOW') : null,
        event: e,
        tactic: getTacticTag(e.analysis_reasons || []),
      }))
      .sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level));

    const tickList = Array.from({ length: TICKS }, (_, i) => {
      const t = min + (span * i) / (TICKS - 1);
      return { pct: (i / (TICKS - 1)) * 100, label: formatAxis(t, span) };
    });
    return { points: pts, ticks: tickList, minTime: min, spanTime: span };
  }, [events]);

  const hoverPoint = hover != null ? points.find((p) => p.id === hover) : null;

  // Drag selection helpers
  function getPctFromEvent(e) {
    if (!trackRef.current) return 0;
    const rect = trackRef.current.getBoundingClientRect();
    const x = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
    return (x / rect.width) * 100;
  }

  function handleMouseDown(e) {
    // Only primary mouse button and not clicking on a timeline bar
    if (e.button !== 0 || e.target.closest('.timeline-bar')) return;
    const pct = getPctFromEvent(e);
    setDragStartPct(pct);
    setDragCurrentPct(pct);
  }

  function handleMouseMove(e) {
    if (dragStartPct == null) return;
    setDragCurrentPct(getPctFromEvent(e));
  }

  function handleMouseUp() {
    if (dragStartPct != null && dragCurrentPct != null) {
      const p1 = Math.min(dragStartPct, dragCurrentPct);
      const p2 = Math.max(dragStartPct, dragCurrentPct);
      // If drag span is noticeable (greater than 2%), apply filter
      if (p2 - p1 > 2 && onTimeFilterChange) {
        const startTime = minTime + (p1 / 100) * spanTime;
        const endTime = minTime + (p2 / 100) * spanTime;
        onTimeFilterChange({ startTime, endTime, p1, p2 });
      }
    }
    setDragStartPct(null);
    setDragCurrentPct(null);
  }

  const selectionOverlay = useMemo(() => {
    if (dragStartPct != null && dragCurrentPct != null) {
      const left = Math.min(dragStartPct, dragCurrentPct);
      const width = Math.abs(dragCurrentPct - dragStartPct);
      return { left: `${left}%`, width: `${width}%`, isDragging: true };
    }
    if (timeFilter && timeFilter.p1 != null && timeFilter.p2 != null) {
      return { left: `${timeFilter.p1}%`, width: `${timeFilter.p2 - timeFilter.p1}%`, isDragging: false };
    }
    return null;
  }, [dragStartPct, dragCurrentPct, timeFilter]);

  const filteredPointsCount = useMemo(() => {
    if (!timeFilter) return points.length;
    return points.filter((p) => p.t >= timeFilter.startTime && p.t <= timeFilter.endTime).length;
  }, [points, timeFilter]);

  return (
    <div className="timeline" role="group" aria-labelledby="timeline-title">
      <div className="panel__header">
        <div>
          <h2 className="panel__title" id="timeline-title">Incident trace</h2>
          <p className="panel__subtitle">
            {points.length > 0
              ? `The ${formatNumber(points.length)} events in scope. Drag across track to zoom into an incident burst.`
              : 'Chronological view of the selected scope.'}
          </p>
        </div>
        <div className="timeline-header-actions">
          {timeFilter && (
            <div className="timeline-filter-pill">
              <span className="timeline-filter-pill__icon"><Icon name="filter" size={12} /></span>
              <span>Window: <strong>{filteredPointsCount} events</strong></span>
              <button
                className="timeline-filter-pill__clear"
                onClick={() => onTimeFilterChange && onTimeFilterChange(null)}
                title="Clear time window filter"
              >
                Clear
              </button>
            </div>
          )}
          {points.some((p) => !p.level) && (
            <div className="timeline-legend">
              <span className="timeline-legend__item">
                <span className="timeline-legend__dot timeline-legend__dot--pending" />
                Pending analysis
              </span>
            </div>
          )}
        </div>
      </div>

      {points.length === 0 ? (
        <div className="timeline-empty">No events in this scope yet.</div>
      ) : (
        <div className="timeline-body">
          <div
            className={`timeline-track ${dragStartPct != null ? 'is-dragging-range' : ''}`}
            ref={trackRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={() => {
              setHover(null);
              if (dragStartPct != null) handleMouseUp();
            }}
          >
            <div className="timeline-track__grid">
              {ticks.map((t) => <span key={t.pct} style={{ left: `${t.pct}%` }} />)}
            </div>
            <div className="timeline-track__baseline" />

            {selectionOverlay && (
              <div
                className={`timeline-selection-range ${selectionOverlay.isDragging ? 'is-live' : 'is-applied'}`}
                style={{ left: selectionOverlay.left, width: selectionOverlay.width }}
              />
            )}

            {points.map((p) => {
              const inRange = !timeFilter || (p.t >= timeFilter.startTime && p.t <= timeFilter.endTime);
              return (
                <button
                  key={p.id}
                  className={`timeline-bar ${p.id === selectedId ? 'is-selected' : ''} ${p.level ? '' : 'is-pending'} ${inRange ? '' : 'is-dimmed'}`}
                  style={{
                    left: `${p.pct}%`,
                    height: `${p.heightPct}%`,
                    background: p.level ? `var(${RISK_COLOR_VAR[p.level]})` : undefined,
                  }}
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(p.id);
                  }}
                  onMouseEnter={() => setHover(p.id)}
                  onFocus={() => setHover(p.id)}
                  onBlur={() => setHover(null)}
                  aria-label={`${formatDateTime(p.event.timestamp)} ${p.event.event_type}, ${p.level ? p.level.toLowerCase() + ' risk' : 'not analyzed'}`}
                />
              );
            })}

            {hoverPoint && (
              <div
                className="timeline-tip"
                style={{ left: `clamp(90px, ${hoverPoint.pct}%, calc(100% - 90px))` }}
                role="tooltip"
              >
                <div className="timeline-tip__time mono">{formatDateTime(hoverPoint.event.timestamp)}</div>
                <div className="timeline-tip__type">{hoverPoint.event.event_type}</div>
                <div className="timeline-tip__meta">
                  {hoverPoint.level
                    ? `${hoverPoint.level.charAt(0) + hoverPoint.level.slice(1).toLowerCase()} risk, score ${Math.round(hoverPoint.event.risk_score ?? 0)}`
                    : 'Not analyzed yet'}
                </div>
                {hoverPoint.tactic && (
                  <div className="timeline-tip__tactic">
                    <span className="tactic-tag">{hoverPoint.tactic}</span>
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="timeline-axis">
            {ticks.map((t, i) => (
              <span
                key={t.pct}
                style={{ left: `${t.pct}%` }}
                className={i === 0 ? 'is-first' : i === ticks.length - 1 ? 'is-last' : ''}
              >
                {t.label}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
