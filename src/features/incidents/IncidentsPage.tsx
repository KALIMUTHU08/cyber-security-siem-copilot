import { useNavigate } from 'react-router-dom';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
  RiskScoreBar,
  LoadingState,
  ErrorState,
} from '../../components/ui';
import { formatTimestamp, formatIncidentTitle, pluralize } from '../../lib/utils';

export function IncidentsPage() {
  const navigate = useNavigate();
  const { data, status, error, refetch } = useAsync(() => siemService.getIncidents(1, 20), []);

  return (
    <div className="space-y-4 animate-fade-in">
      <PageHeader
        title="Incidents"
        subtitle={data ? `${data.total} active ${pluralize(data.total, 'incident', 'incidents')}` : undefined}
      />

      {status === 'loading' && <LoadingState message="Loading incidents…" className="py-24" />}
      {status === 'error' && <ErrorState message="Failed to load incidents" detail={error?.message} onRetry={refetch} />}

      {status === 'success' && (
        <div className="space-y-3">
          {data?.items.map((inc) => (
            <Panel
              key={inc.id}
              className="cursor-pointer hover:border-border-strong transition-colors"
              onClick={() => navigate(`/incidents/${inc.id}`)}
            >
              <div className="p-4">
                <div className="flex items-start gap-3">
                  {/* Left: severity + id */}
                  <div className="flex-shrink-0 text-right min-w-[90px]">
                    <div className="text-xs font-mono text-text-muted mb-1">{inc.id}</div>
                    <SeverityBadge severity={inc.severity} />
                  </div>

                  {/* Middle: title + meta */}
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-text-primary mb-1">{formatIncidentTitle(inc)}</div>
                    <p className="text-xs text-text-secondary line-clamp-2 mb-2">{inc.summary}</p>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted font-mono">
                      <span>Source: <span className="text-text-secondary">{inc.sourceIp}</span></span>
                      <span>User: <span className="text-text-secondary">{inc.targetUser}</span></span>
                      <span>Device: <span className="text-text-secondary">{inc.affectedDevice}</span></span>
                      <span>First seen: <span className="text-text-secondary">{formatTimestamp(inc.firstSeen, { relative: true })}</span></span>
                    </div>
                  </div>

                  {/* Right: risk + status */}
                  <div className="flex-shrink-0 flex flex-col items-end gap-2 min-w-[130px]">
                    <StatusBadge status={inc.status} />
                    <div className="w-full">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-2xs text-text-muted">Risk Score</span>
                        <span className="text-xs font-mono font-bold" style={{ color: inc.riskScore.level === 'CRITICAL' ? '#f85149' : inc.riskScore.level === 'HIGH' ? '#e3872d' : '#d29922' }}>
                          {inc.riskScore.score} <span className="text-2xs font-normal">({inc.riskScore.level})</span>
                        </span>
                      </div>
                      <RiskScoreBar riskScore={inc.riskScore} showLabel={false} />
                    </div>
                    <span className="text-2xs text-text-muted">{pluralize(inc.relatedAlertIds.length, 'alert', 'alerts')}</span>
                  </div>
                </div>
              </div>
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
