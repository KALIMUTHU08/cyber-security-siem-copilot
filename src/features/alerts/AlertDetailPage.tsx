import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ExternalLink, FileWarning, Bot } from 'lucide-react';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  PanelHeader,
  SeverityBadge,
  StatusBadge,
  RiskScoreRing,
  RawLogLine,
  LoadingState,
  ErrorState,
  Button,
} from '../../components/ui';
import { formatTimestamp } from '../../lib/utils';

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();

  const { data: alert, status, error, refetch } = useAsync(
    () => siemService.getAlertById(alertId ?? ''),
    [alertId],
  );

  const { data: matchingLogs } = useAsync(
    () => (alert?.matchingLogIds ? siemService.getLogsByIds(alert.matchingLogIds.slice(0, 10)) : Promise.resolve([])),
    [alert?.id],
  );

  if (status === 'loading') return <LoadingState message="Loading alert details…" className="py-24" />;
  if (status === 'error') return <ErrorState message="Failed to load alert" detail={error?.message} onRetry={refetch} />;
  if (!alert) return <ErrorState message="Alert not found" detail={`Alert ID: ${alertId}`} />;

  return (
    <div className="space-y-5 animate-fade-in max-w-5xl">
      {/* Back + Header */}
      <div>
        <button
          onClick={() => navigate('/alerts')}
          className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary mb-3 transition-colors"
        >
          <ArrowLeft size={13} /> Back to Alerts
        </button>
        <PageHeader
          title={alert.title}
          subtitle={`Alert ID: ${alert.id}`}
          actions={
            <div className="flex items-center gap-2">
              {alert.relatedIncidentId && (
                <Button
                  variant="secondary"
                  size="sm"
                  leftIcon={<FileWarning size={14} />}
                  onClick={() => navigate(`/incidents/${alert.relatedIncidentId}`)}
                >
                  View Incident
                </Button>
              )}
              <Button
                variant="secondary"
                size="sm"
                leftIcon={<Bot size={14} />}
                onClick={() => navigate('/copilot')}
              >
                Ask Copilot
              </Button>
            </div>
          }
        />
      </div>

      {/* Summary header cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Panel className="p-3 flex items-center gap-3">
          <RiskScoreRing riskScore={alert.riskScore} size={60} />
          <div>
            <div className="text-xs text-text-muted mb-0.5">Risk Score</div>
            <div className="text-xs font-medium" style={{ color: '#f85149' }}>{alert.riskScore.level}</div>
          </div>
        </Panel>
        {[
          { label: 'Severity', value: <SeverityBadge severity={alert.severity} /> },
          { label: 'Status', value: <StatusBadge status={alert.status} /> },
          { label: 'Match Count', value: <span className="font-mono font-bold text-text-primary">{alert.matchCount}</span> },
        ].map(({ label, value }) => (
          <Panel key={label} className="p-3">
            <div className="text-xs text-text-muted mb-1">{label}</div>
            {value}
          </Panel>
        ))}
      </div>

      {/* Metadata grid */}
      <Panel>
        <PanelHeader title="Alert Details" />
        <div className="grid grid-cols-2 md:grid-cols-3 gap-px bg-border-subtle">
          {[
            { label: 'Source IP', value: alert.sourceIp, mono: true },
            { label: 'Destination IP', value: alert.destinationIp ?? '—', mono: true },
            { label: 'Username', value: alert.username, mono: true },
            { label: 'Device', value: alert.device },
            { label: 'Detection Rule', value: alert.detectionRuleName },
            { label: 'First Seen', value: formatTimestamp(alert.firstSeen), mono: true },
            { label: 'Last Seen', value: formatTimestamp(alert.lastSeen), mono: true },
          ].map(({ label, value, mono }) => (
            <div key={label} className="bg-bg-panel px-4 py-3">
              <div className="text-xs text-text-muted mb-0.5">{label}</div>
              <div className={`text-sm text-text-primary ${mono ? 'font-mono' : ''}`}>{value}</div>
            </div>
          ))}
        </div>
      </Panel>

      {/* Why This Alert Was Generated */}
      <Panel>
        <PanelHeader title="Why This Alert Was Generated" />
        <div className="p-4 space-y-4">
          <div className="bg-bg-elevated rounded p-3 border border-border-subtle">
            <div className="text-xs text-text-muted mb-1">Detection Rule Condition</div>
            <p className="text-sm text-text-primary">{alert.detectionCondition}</p>
          </div>
          <div className="bg-bg-elevated rounded p-3 border border-border-subtle">
            <div className="text-xs text-text-muted mb-1">Match Summary</div>
            <p className="text-sm font-medium text-text-primary">{alert.matchingSummary}</p>
          </div>
          {alert.riskScore.factors.length > 0 && (
            <div>
              <div className="text-xs text-text-muted mb-2">Contributing Risk Factors</div>
              <ul className="space-y-1">
                {alert.riskScore.factors.map((f, i) => (
                  <li key={i} className="flex gap-2 text-sm text-text-secondary">
                    <span className="text-accent font-mono mt-0.5 flex-shrink-0">›</span>
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </Panel>

      {/* Matching Log Lines */}
      <Panel>
        <PanelHeader
          title="Matching Raw Log Lines"
          subtitle={`Showing ${Math.min(10, alert.matchingLogIds.length)} of ${alert.matchingLogIds.length} matching events`}
        />
        <div className="p-4 space-y-1.5 max-h-72 overflow-y-auto">
          {matchingLogs && matchingLogs.length > 0 ? (
            matchingLogs.map((log) => (
              <RawLogLine key={log.id} log={log.rawLog} />
            ))
          ) : (
            <p className="text-xs text-text-muted">Loading log lines…</p>
          )}
        </div>
      </Panel>

      {/* Related Events */}
      <Panel>
        <PanelHeader
          title="Related Events"
          actions={
            alert.relatedIncidentId ? (
              <Button
                variant="ghost"
                size="sm"
                rightIcon={<ExternalLink size={12} />}
                onClick={() => navigate(`/incidents/${alert.relatedIncidentId}`)}
              >
                View Incident
              </Button>
            ) : undefined
          }
        />
        <div className="p-4">
          {matchingLogs && matchingLogs.length > 0 ? (
            <div className="space-y-2">
              {matchingLogs.slice(0, 5).map((log) => (
                <div key={log.id} className="flex items-center gap-3 text-xs py-2 border-b border-border-subtle last:border-0">
                  <span className="font-mono text-text-muted w-36 flex-shrink-0">{formatTimestamp(log.timestamp, { relative: false }).slice(0, 17)}</span>
                  <span className="font-mono text-accent flex-shrink-0">{log.eventType}</span>
                  <span className="font-mono text-text-secondary">{log.sourceIp}</span>
                  <span className="text-text-muted">→</span>
                  <span className="font-mono text-text-secondary">{log.username}</span>
                  <span className={`ml-auto px-1.5 py-0.5 rounded text-2xs font-medium ${log.status === 'SUCCESS' ? 'text-low-text bg-low-bg' : 'text-critical-text bg-critical-bg'}`}>
                    {log.status}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-text-muted">Loading related events…</p>
          )}
        </div>
      </Panel>
    </div>
  );
}
