import { useState } from 'react';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  PanelHeader,
  SeverityBadge,
  LoadingState,
  ErrorState,
} from '../../components/ui';
import { cn } from '../../lib/utils';

type Tab = 'rules' | 'risk-scoring' | 'log-sources' | 'ai-config' | 'preferences';

const TABS: { id: Tab; label: string }[] = [
  { id: 'rules', label: 'Detection Rules' },
  { id: 'risk-scoring', label: 'Risk Scoring' },
  { id: 'log-sources', label: 'Log Sources' },
  { id: 'ai-config', label: 'AI Configuration' },
  { id: 'preferences', label: 'Preferences' },
];

const LOG_SOURCES = [
  { name: 'Synthetic Event Generator', type: 'Internal', status: 'connected', detail: 'Producing 340 events/min' },
  { name: 'Windows Security Event Log', type: 'Windows', status: 'not-configured', detail: 'Requires Winlogbeat agent' },
  { name: 'Linux Syslog (rsyslog/journald)', type: 'Linux', status: 'not-configured', detail: 'Requires syslog forwarder' },
  { name: 'Firewall Logs (Gateway01)', type: 'Network', status: 'not-configured', detail: 'Requires syslog or API integration' },
  { name: 'Cloud Trail (AWS)', type: 'Cloud', status: 'not-configured', detail: 'Future work — requires IAM role' },
  { name: 'Active Directory Audit Logs', type: 'Windows', status: 'not-configured', detail: 'Future work — requires AD connector' },
];

const RISK_BANDS = [
  { range: '0 – 25', level: 'LOW', color: '#3fb950', bg: 'bg-low-bg', border: 'border-low-border', text: 'text-low-text',
    factors: ['Single isolated event from known source', 'Normal business-hours activity', 'No prior alerts for this source'] },
  { range: '26 – 50', level: 'MEDIUM', color: '#d29922', bg: 'bg-medium-bg', border: 'border-medium-border', text: 'text-medium-text',
    factors: ['Repeated events from same source within short window', 'Activity from previously unseen source IP', 'Off-hours login from known user'] },
  { range: '51 – 75', level: 'HIGH', color: '#e3872d', bg: 'bg-high-bg', border: 'border-high-border', text: 'text-high-text',
    factors: ['Detection rule fired with 10+ event match', 'Correlation with prior low/medium events', 'Privileged account targeted'] },
  { range: '76 – 100', level: 'CRITICAL', color: '#f85149', bg: 'bg-critical-bg', border: 'border-critical-border', text: 'text-critical-text',
    factors: ['Multi-stage attack chain detected', 'Successful auth following brute-force pattern', 'Outbound connection to non-whitelisted external IP', 'Privilege escalation in active incident window'] },
];

// Toggle switch
function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex w-10 h-5 rounded-full transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        checked ? 'bg-accent' : 'bg-bg-hover',
      )}
    >
      <span
        className={cn(
          'absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-150',
          checked ? 'translate-x-5' : 'translate-x-0',
        )}
      />
    </button>
  );
}

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('rules');
  const [prefDense, setPrefDense] = useState(false);
  const [prefAnimations, setPrefAnimations] = useState(true);
  const [prefAutoRefresh, setPrefAutoRefresh] = useState(true);

  const { data: rules, status: rulesStatus, error: rulesError } = useAsync(
    () => siemService.getDetectionRules(),
    [],
  );

  const [ruleStates, setRuleStates] = useState<Record<string, boolean>>({});

  async function handleRuleToggle(id: string, current: boolean) {
    const next = !current;
    setRuleStates((prev) => ({ ...prev, [id]: next }));
    try {
      await siemService.toggleDetectionRule(id, next);
    } catch {
      setRuleStates((prev) => ({ ...prev, [id]: current }));
    }
  }

  return (
    <div className="space-y-4 animate-fade-in max-w-4xl">
      <PageHeader title="Settings" subtitle="Configure detection rules, risk scoring, log sources, and system preferences" />

      {/* Tab bar */}
      <div className="flex items-center gap-1 border-b border-border-default">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px',
              activeTab === tab.id
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary',
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ---- TAB: Detection Rules ---- */}
      {activeTab === 'rules' && (
        <div>
          {rulesStatus === 'loading' && <LoadingState message="Loading detection rules…" />}
          {rulesStatus === 'error' && <ErrorState message="Failed to load rules" detail={rulesError?.message} />}
          {rulesStatus === 'success' && rules && (
            <div className="space-y-2">
              {rules.map((rule) => {
                const isEnabled = rule.id in ruleStates ? ruleStates[rule.id] : rule.enabled;
                return (
                  <Panel key={rule.id}>
                    <div className="p-4 flex items-start gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-semibold text-text-primary">{rule.name}</span>
                          <SeverityBadge severity={rule.severity} size="sm" />
                          <span className="text-2xs text-text-muted bg-bg-elevated border border-border-subtle px-1.5 py-0.5 rounded">
                            {rule.category}
                          </span>
                        </div>
                        <p className="text-xs text-text-secondary mb-1.5">{rule.description}</p>
                        <div className="text-xs text-text-muted">
                          Condition:{' '}
                          <span className="font-mono text-text-secondary italic">{rule.condition}</span>
                        </div>
                        {rule.conditionRaw && (
                          <div className="mt-1.5 font-mono text-2xs text-text-muted bg-bg-app border border-border-subtle rounded px-2 py-1">
                            {rule.conditionRaw}
                          </div>
                        )}
                        <div className="mt-2 text-2xs text-text-muted">
                          Triggered {rule.triggerCount} time{rule.triggerCount !== 1 ? 's' : ''} in current dataset
                        </div>
                      </div>
                      <div className="flex-shrink-0 flex flex-col items-end gap-2">
                        <Toggle
                          checked={isEnabled}
                          onChange={(v) => void handleRuleToggle(rule.id, !v)}
                        />
                        <span className={`text-xs font-medium ${isEnabled ? 'text-low-text' : 'text-text-muted'}`}>
                          {isEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                    </div>
                  </Panel>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ---- TAB: Risk Scoring ---- */}
      {activeTab === 'risk-scoring' && (
        <div className="space-y-4">
          <Panel>
            <PanelHeader title="Risk Score Bands" subtitle="This project's configurable scoring thresholds — not an industry standard" />
            <div className="p-4 space-y-3">
              <p className="text-xs text-text-secondary">
                Risk scores (0–100) are computed by the Detection Engine based on rule match severity, event count, temporal correlation, and contextual factors. The bands below define how a numeric score maps to a risk level label. These thresholds are configurable for this project.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {RISK_BANDS.map((band) => (
                  <div key={band.level} className={`rounded-md border p-3 ${band.bg} ${band.border}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`font-mono text-sm font-bold ${band.text}`}>{band.range}</span>
                      <span className={`text-xs font-semibold uppercase tracking-wide ${band.text}`}>{band.level}</span>
                    </div>
                    <ul className="space-y-1">
                      {band.factors.map((f, i) => (
                        <li key={i} className={`text-xs flex gap-1.5 ${band.text} opacity-80`}>
                          <span className="flex-shrink-0">›</span>{f}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* ---- TAB: Log Sources ---- */}
      {activeTab === 'log-sources' && (
        <Panel>
          <PanelHeader
            title="Log Sources"
            subtitle="Connected and planned data ingestion sources"
          />
          <div className="divide-y divide-border-subtle">
            {LOG_SOURCES.map((src) => (
              <div key={src.name} className="flex items-center gap-4 px-4 py-3">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-text-primary">{src.name}</div>
                  <div className="text-xs text-text-muted mt-0.5">{src.detail}</div>
                </div>
                <span className="text-xs text-text-muted bg-bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                  {src.type}
                </span>
                <span
                  className={cn(
                    'text-xs font-medium px-2 py-0.5 rounded',
                    src.status === 'connected'
                      ? 'text-low-text bg-low-bg border border-low-border'
                      : 'text-text-muted bg-bg-elevated border border-border-default',
                  )}
                >
                  {src.status === 'connected' ? 'Connected' : 'Not configured'}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ---- TAB: AI Configuration ---- */}
      {activeTab === 'ai-config' && (
        <div className="space-y-4">
          <Panel>
            <PanelHeader title="Copilot Reasoning Model" />
            <div className="p-4 space-y-3">
              <div className="p-3 bg-ai-subtle border border-ai-muted rounded-md text-sm text-text-secondary leading-relaxed">
                The SIEM Copilot reasons over <strong className="text-text-primary">structured detection-engine output</strong> — correlated alerts, parsed events, and incident timelines — not over raw log text directly. This means Copilot responses are grounded in what the detection engine has already validated, reducing noise and hallucination risk.
              </div>
              {[
                { label: 'Model Backend', value: 'Internal mock (development mode)', mono: false },
                { label: 'Context Window', value: 'Per-incident event set (up to 500 events)', mono: false },
                { label: 'Evidence Grounding', value: 'Enabled — all responses cite correlated events', mono: false },
                { label: 'Assessment Language', value: 'Hedged — Possible / Observed / Consistent with / Requires investigation', mono: false },
                { label: 'Service Status', value: 'Operational (mock)', mono: false },
              ].map(({ label, value, mono }) => (
                <div key={label} className="flex items-start gap-3 border-b border-border-subtle pb-2 last:border-0 last:pb-0">
                  <span className="text-xs text-text-muted w-40 flex-shrink-0 pt-0.5">{label}</span>
                  <span className={`text-xs text-text-primary flex-1 ${mono ? 'font-mono' : ''}`}>{value}</span>
                </div>
              ))}
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Future Backend Integration" subtitle="How to connect a real AI backend" />
            <div className="p-4 text-xs text-text-secondary space-y-2 font-mono bg-bg-app rounded-b-md">
              <div className="text-text-muted">// Replace in src/services/index.ts:</div>
              <div><span className="text-medium-text">import</span> {'{ HttpSiemService }'} <span className="text-medium-text">from</span> <span className="text-low-text">'./api/HttpSiemService'</span>;</div>
              <div><span className="text-medium-text">export const</span> siemService = <span className="text-medium-text">new</span> HttpSiemService(<span className="text-low-text">'https://your-api.com'</span>);</div>
            </div>
          </Panel>
        </div>
      )}

      {/* ---- TAB: Preferences ---- */}
      {activeTab === 'preferences' && (
        <Panel>
          <PanelHeader title="UI Preferences" />
          <div className="divide-y divide-border-subtle">
            {[
              {
                label: 'Dense Table Layout',
                desc: 'Reduce row padding in tables to show more data',
                value: prefDense,
                onChange: setPrefDense,
              },
              {
                label: 'UI Animations',
                desc: 'Enable fade/slide transitions and micro-animations',
                value: prefAnimations,
                onChange: setPrefAnimations,
              },
              {
                label: 'Auto-refresh Dashboard',
                desc: 'Automatically refresh overview data every 60 seconds',
                value: prefAutoRefresh,
                onChange: setPrefAutoRefresh,
              },
            ].map(({ label, desc, value, onChange }) => (
              <div key={label} className="flex items-center justify-between px-4 py-3 gap-4">
                <div>
                  <div className="text-sm font-medium text-text-primary">{label}</div>
                  <div className="text-xs text-text-muted mt-0.5">{desc}</div>
                </div>
                <Toggle checked={value} onChange={onChange} />
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
