import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Bot, ShieldAlert, ChevronRight } from 'lucide-react';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  Panel,
  PanelHeader,
  SeverityBadge,
  StatusBadge,
  RiskScoreRing,
  Timeline,
  ObservedEvidenceBlock,
  AiAssessmentBlock,
  RecommendationsBlock,
  RawLogLine,
  LoadingState,
  ErrorState,
  Button,
} from '../../components/ui';
import { formatTimestamp, formatIncidentTitle, pluralize, riskLevelColor } from '../../lib/utils';
import type { Incident, SecurityAlert, SecurityLog } from '../../types';
import { ResponseActionsPanel } from './ResponseActionsPanel';

// Attack chain step visualization
function AttackChainStep({
  step,
  label,
  isLast,
  severity,
}: {
  step: number;
  label: string;
  isLast: boolean;
  severity: 'critical' | 'high' | 'medium';
}) {
  const colors = {
    critical: { border: 'border-critical-border', bg: 'bg-critical-bg', text: 'text-critical-text', num: 'text-critical-DEFAULT' },
    high: { border: 'border-high-border', bg: 'bg-high-bg', text: 'text-high-text', num: 'text-high-DEFAULT' },
    medium: { border: 'border-medium-border', bg: 'bg-medium-bg', text: 'text-medium-text', num: 'text-medium-DEFAULT' },
  }[severity];

  return (
    <div className="flex items-center gap-2">
      <div className={`flex items-center gap-2.5 px-3 py-2 rounded border ${colors.border} ${colors.bg} min-w-0`}>
        <span className={`text-xs font-mono font-bold flex-shrink-0 ${colors.num}`}>{step}</span>
        <span className={`text-xs font-medium ${colors.text} truncate`}>{label}</span>
      </div>
      {!isLast && <ChevronRight size={14} className="text-text-muted flex-shrink-0" />}
    </div>
  );
}

function deriveAttackSteps(
  incident: Incident,
  alerts?: SecurityAlert[] | null,
  logs?: SecurityLog[] | null
): { label: string; severity: 'critical' | 'high' | 'medium' }[] {
  const steps: { label: string; severity: 'critical' | 'high' | 'medium'; timestamp?: string }[] = [];
  const seenLabels = new Set<string>();

  const addStep = (label: string, severity: 'critical' | 'high' | 'medium', timestamp?: string) => {
    if (!seenLabels.has(label)) {
      seenLabels.add(label);
      steps.push({ label, severity, timestamp });
    }
  };

  // 1. If alerts are loaded, extract steps from detection rules / alert types
  if (alerts && alerts.length > 0) {
    const sortedAlerts = [...alerts].sort(
      (a, b) => new Date(a.firstSeen).getTime() - new Date(b.firstSeen).getTime()
    );

    const hasRule012 = sortedAlerts.some((a) => a.detectionRuleId === 'rule-012');
    const hasRule010 = sortedAlerts.some((a) => a.detectionRuleId === 'rule-010');

    if (sortedAlerts.length === 2 && hasRule012 && hasRule010) {
      addStep('Scanner Activity', 'medium');
      addStep('Exploit Pattern', 'high');
      return steps;
    }

    for (const alert of sortedAlerts) {
      const sev = alert.severity === 'CRITICAL' ? 'critical' : alert.severity === 'HIGH' ? 'high' : 'medium';
      switch (alert.detectionRuleId) {
        case 'rule-012':
          addStep(sortedAlerts.length === 1 ? 'Scanner User-Agent Detection' : 'Scanner Activity', sev, alert.firstSeen);
          break;
        case 'rule-010':
          addStep('Exploit Pattern', sev, alert.firstSeen);
          break;
        case 'rule-001':
        case 'rule-007':
          addStep('Multiple Failed Logins', sev, alert.firstSeen);
          break;
        case 'rule-002':
          addStep('Account Compromise', 'critical', alert.firstSeen);
          break;
        case 'rule-003':
          addStep('Privilege Escalation', 'critical', alert.firstSeen);
          break;
        case 'rule-004':
          addStep('Suspicious External Activity', 'high', alert.firstSeen);
          break;
        case 'rule-005':
          addStep('Port Scan Activity', sev, alert.firstSeen);
          break;
        case 'rule-006':
          addStep('Credential Spraying', 'high', alert.firstSeen);
          break;
        case 'rule-008':
          addStep('Off-Hours Access', sev, alert.firstSeen);
          break;
        case 'rule-009':
          addStep('High-Volume Blocked Requests', sev, alert.firstSeen);
          break;
        case 'rule-011':
          addStep('Data Transfer', 'critical', alert.firstSeen);
          break;
        case 'rule-013':
          addStep('ICMP Flood Sweep', sev, alert.firstSeen);
          break;
        default:
          if (alert.detectionRuleName) {
            addStep(alert.detectionRuleName, sev, alert.firstSeen);
          }
      }
    }
  }

  // 2. Check logs for sequence patterns if alerts didn't produce a multi-stage sequence
  if (steps.length <= 1 && logs && logs.length > 0) {
    const eventTypes = logs.map((l) => l.eventType as string);
    const hasFailedLogin = eventTypes.includes('LOGIN_FAILED');
    const hasSuccessLogin = eventTypes.includes('LOGIN');
    const hasFileAccess = eventTypes.includes('FILE_ACCESS');
    const hasDataExfil = eventTypes.includes('DATA_EXFILTRATION') || eventTypes.includes('DATA_TRANSFER');

    if (hasFailedLogin && hasSuccessLogin && !seenLabels.has('Successful Authentication')) {
      addStep('Failed Authentication', 'medium');
      addStep('Successful Authentication', 'high');
    } else if (hasFileAccess && hasDataExfil && !seenLabels.has('Data Transfer')) {
      addStep('File Access', 'medium');
      addStep('Data Transfer', 'critical');
    }
  }

  // 3. Fallback to timeline event types if available
  if (steps.length === 0 && incident.timeline && incident.timeline.length > 0) {
    for (const te of incident.timeline) {
      if (te.eventType === 'ALERT' || te.eventType === 'INCIDENT_CREATED') continue;
      const sev = te.severity === 'CRITICAL' ? 'critical' : te.severity === 'HIGH' ? 'high' : 'medium';
      addStep(te.title || te.eventType, sev, te.timestamp);
    }
  }

  return steps;
}

export function IncidentDetailPage() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const navigate = useNavigate();

  const { data: incident, status, error, refetch } = useAsync(
    () => siemService.getIncidentById(incidentId ?? ''),
    [incidentId],
  );

  const { data: relatedAlerts } = useAsync(
    () => (incident?.relatedAlertIds ? siemService.getAlertsByIds(incident.relatedAlertIds) : Promise.resolve([])),
    [incident?.id],
  );

  const { data: evidenceLogs } = useAsync(
    () =>
      incident?.relatedLogIds
        ? siemService.getLogsByIds(incident.relatedLogIds.slice(0, 8))
        : Promise.resolve([]),
    [incident?.id],
  );

  if (status === 'loading') return <LoadingState message="Loading incident investigation…" className="py-24" />;
  if (status === 'error') return <ErrorState message="Failed to load incident" detail={error?.message} onRetry={refetch} />;
  if (!incident) return <ErrorState message="Incident not found" detail={`ID: ${incidentId}`} />;

  const attackSteps = deriveAttackSteps(incident, relatedAlerts, evidenceLogs);

  return (
    <div className="animate-fade-in">
      <button
        onClick={() => navigate('/incidents')}
        className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary mb-4 transition-colors"
      >
        <ArrowLeft size={13} /> Back to Incidents
      </button>

      {/* Hero header */}
      <div className="bg-bg-panel border border-border-default rounded-md p-5 mb-5">
        <div className="flex items-start gap-5">
          {/* Risk ring */}
          <div className="flex-shrink-0 hidden sm:flex flex-col items-center">
            <RiskScoreRing riskScore={incident.riskScore} size={92} />
            <span className="text-2xs text-text-muted mt-1 uppercase tracking-wider font-mono">Risk Score</span>
          </div>

          {/* Incident info */}
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="text-xs font-mono text-text-muted bg-bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                {incident.id}
              </span>
              <div className="flex items-center gap-1.5 text-xs bg-bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                <span className="text-text-muted font-normal">Incident Severity:</span>
                <SeverityBadge severity={incident.severity} size="sm" />
              </div>
              <div className="flex items-center gap-1.5 text-xs bg-bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                <span className="text-text-muted font-normal">Risk Level:</span>
                <span className="font-mono font-semibold" style={{ color: riskLevelColor(incident.riskScore.level) }}>
                  {incident.riskScore.level}
                </span>
                <span className="text-text-muted font-mono">({incident.riskScore.score}/100)</span>
              </div>
              <StatusBadge status={incident.status} />
            </div>
            <h1 className="text-lg font-semibold text-text-primary mb-1">{formatIncidentTitle(incident)}</h1>
            <p className="text-sm text-text-secondary leading-relaxed mb-3">{incident.summary}</p>

            {/* Meta grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
              {[
                { label: 'Source IP', value: incident.sourceIp, mono: true },
                { label: 'Target User', value: incident.targetUser, mono: true },
                { label: 'Affected Device', value: incident.affectedDevice },
                { label: 'First Seen', value: formatTimestamp(incident.firstSeen, { relative: true }), mono: true },
                { label: 'Last Seen', value: formatTimestamp(incident.lastSeen, { relative: true }), mono: true },
                { label: 'Related Alerts', value: pluralize(incident.relatedAlertIds.length, 'alert', 'alerts') },
              ].map(({ label, value, mono }) => (
                <div key={label} className="bg-bg-elevated rounded p-2">
                  <div className="text-2xs text-text-muted mb-0.5">{label}</div>
                  <div className={`text-xs text-text-primary font-medium ${mono ? 'font-mono' : ''}`}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex-shrink-0 flex flex-col gap-2">
            <Button
              variant="primary"
              size="sm"
              leftIcon={<Bot size={14} />}
              onClick={() => navigate('/copilot', { state: { incidentId: incident.id } })}
            >
              Ask Copilot
            </Button>
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<ShieldAlert size={14} />}
              onClick={() => navigate('/alerts')}
            >
              Related Alerts
            </Button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Main content — left 2 cols */}
        <div className="lg:col-span-2 space-y-5">

          {/* (a) Incident Timeline */}
          <Panel>
            <PanelHeader
              title="Incident Timeline"
              subtitle="Chronological sequence of observed events"
            />
            <div className="p-4">
              <Timeline events={incident.timeline} />
            </div>
          </Panel>

          {/* (b) Correlated Attack Sequence */}
          <Panel>
            <PanelHeader title={attackSteps.length > 1 ? "Correlated Attack Sequence" : "Observed Attack Sequence"} />
            <div className="p-4">
              {attackSteps.length > 0 ? (
                <div className="flex flex-wrap items-center gap-2">
                  {attackSteps.map((step, i) => (
                    <AttackChainStep
                      key={i}
                      step={i + 1}
                      label={step.label}
                      severity={step.severity}
                      isLast={i === attackSteps.length - 1}
                    />
                  ))}
                </div>
              ) : null}

              {attackSteps.length <= 1 && (
                <div className="mt-3 p-2.5 rounded bg-bg-elevated border border-border-subtle text-xs text-text-muted flex items-center gap-2">
                  <span className="font-mono text-text-secondary font-bold">ℹ</span>
                  <span>Insufficient evidence for a multi-stage attack sequence</span>
                </div>
              )}

              <p className="text-xs text-text-muted mt-3">
                Attack vector: <span className="text-text-secondary">{incident.attackVector}</span>
              </p>
            </div>
          </Panel>

          {/* (c) Evidence */}
          <Panel>
            <PanelHeader
              title="Supporting Evidence"
              subtitle={`${pluralize(incident.relatedLogIds.length, 'security event', 'security events')} correlated to this incident`}
            />
            <div className="p-4 space-y-1.5 max-h-64 overflow-y-auto">
              {evidenceLogs && evidenceLogs.length > 0 ? (
                evidenceLogs.map((log) => <RawLogLine key={log.id} log={log.rawLog} />)
              ) : (
                <p className="text-xs text-text-muted">Loading evidence logs…</p>
              )}
            </div>
          </Panel>

          {/* (d) Incident Assessment — three distinct blocks */}
          <Panel>
            <PanelHeader
              title="Incident Assessment"
              subtitle="Structured analysis: evidence → AI assessment → recommended actions"
            />
            <div className="p-4 space-y-4">
              <ObservedEvidenceBlock items={incident.observedEvidence} />
              <AiAssessmentBlock content={incident.aiAssessment} />
              <RecommendationsBlock items={incident.recommendedNextSteps} />
            </div>
          </Panel>

          {/* (e) AI-Assisted Response Actions */}
          <ResponseActionsPanel
            incidentId={incident.id}
            incidentSourceIp={incident.sourceIp}
            incidentTargetUser={incident.targetUser}
            incidentDevice={incident.affectedDevice}
          />
        </div>

        {/* Sidebar — right col */}
        <div className="space-y-4">
          {/* Related alerts */}
          <Panel>
            <PanelHeader title="Related Alerts" />
            <div className="px-3 py-2 space-y-2">
              {relatedAlerts && relatedAlerts.length > 0 ? (
                relatedAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-2.5 rounded bg-bg-elevated border border-border-subtle hover:border-border-default cursor-pointer transition-colors"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={alert.severity} size="sm" />
                      <StatusBadge status={alert.status} />
                    </div>
                    <p className="text-xs font-medium text-text-primary line-clamp-2">{alert.title}</p>
                    <p className="text-2xs text-text-muted font-mono mt-1">{alert.sourceIp}</p>
                  </div>
                ))
              ) : (
                <p className="text-xs text-text-muted py-2">Loading related alerts…</p>
              )}
            </div>
          </Panel>

          {/* Risk factors */}
          <Panel>
            <PanelHeader
              title="Risk Analysis"
              subtitle="Score classification vs derived severity"
            />
            <div className="px-3 py-3">
              <div className="grid grid-cols-2 gap-2 mb-3 bg-bg-elevated p-2.5 rounded border border-border-subtle text-xs">
                <div>
                  <div className="text-2xs text-text-muted mb-0.5">Incident Severity</div>
                  <SeverityBadge severity={incident.severity} size="sm" />
                </div>
                <div>
                  <div className="text-2xs text-text-muted mb-0.5">Risk Level (0–100)</div>
                  <div className="font-semibold" style={{ color: riskLevelColor(incident.riskScore.level) }}>
                    {incident.riskScore.level} <span className="text-text-muted font-mono font-normal">({incident.riskScore.score}/100)</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 mb-3">
                <RiskScoreRing riskScore={incident.riskScore} size={52} />
                <div>
                  <div className="text-lg font-bold font-mono text-text-primary">
                    {incident.riskScore.score}<span className="text-sm text-text-muted">/100</span>
                  </div>
                  <div className="text-2xs text-text-muted">
                    Numerical Risk Score
                  </div>
                </div>
              </div>

              <div className="text-2xs text-text-muted font-medium mb-1.5 uppercase tracking-wide">Contributing Factors:</div>
              <ul className="space-y-1.5">
                {incident.riskScore.factors.map((f, i) => (
                  <li key={i} className="flex gap-2 text-xs text-text-secondary">
                    <span className="text-high-DEFAULT font-mono mt-0.5 flex-shrink-0">›</span>
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          </Panel>

          {/* Quick copilot CTA */}
          <div
            className="p-4 rounded-md border border-ai-muted bg-ai-subtle cursor-pointer hover:border-ai/50 transition-colors"
            onClick={() => navigate('/copilot', { state: { incidentId: incident.id } })}
          >
            <div className="flex items-center gap-2 mb-2">
              <Bot size={14} className="text-ai" />
              <span className="text-xs font-semibold text-ai">SIEM Copilot</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">
              Ask the Copilot to explain this incident, investigate the attack chain, or recommend next steps.
            </p>
            <div className="mt-3 text-xs text-ai hover:underline">Open Copilot with this incident →</div>
          </div>
        </div>
      </div>
    </div>
  );
}

