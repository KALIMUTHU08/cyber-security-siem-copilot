import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Play, AlertCircle } from 'lucide-react';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  PanelHeader,
  RawLogLine,
  LoadingState,
  EmptyState,
  Button,
  Input,
} from '../../components/ui';
import type { ThreatHuntQuery } from '../../types';
import { useAsync } from '../../hooks/useAsync';
import { formatTimestamp } from '../../lib/utils';

const SUGGESTED_QUERIES = [
  'Find brute-force attempts',
  'Find suspicious login activity',
  'Show activity from an IP',
  'Find privilege escalation',
  'Show high-risk events',
  'Find unusual login patterns',
  'Find external network connections',
];

export function ThreatHuntingPage() {
  const navigate = useNavigate();
  const [queryText, setQueryText] = useState('');
  const [runningQuery, setRunningQuery] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatHuntQuery | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [huntError, setHuntError] = useState<string | null>(null);

  const { data: logMap } = useAsync(
    () =>
      result?.matchingLogIds?.length
        ? siemService.getLogsByIds(result.matchingLogIds.slice(0, 15))
        : Promise.resolve([]),
    [result?.id],
  );

  const { data: alertMap } = useAsync(
    () =>
      result?.relatedAlertIds?.length
        ? siemService.getAlertsByIds(result.relatedAlertIds)
        : Promise.resolve([]),
    [result?.id],
  );

  async function runHunt(query: string) {
    if (!query.trim()) return;
    setRunningQuery(query);
    setIsRunning(true);
    setResult(null);
    setHuntError(null);
    try {
      const r = await siemService.runThreatHunt(query);
      setResult(r);
    } catch (e) {
      setHuntError(e instanceof Error ? e.message : 'Hunt failed');
    } finally {
      setIsRunning(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    void runHunt(queryText);
  }

  return (
    <div className="space-y-5 animate-fade-in max-w-4xl">
      <PageHeader
        title="Threat Hunting"
        subtitle="Investigate your environment by querying security events, alerts, and behavioral patterns"
      />

      {/* Query input */}
      <Panel>
        <div className="p-4">
          <form onSubmit={handleSubmit} className="flex gap-2">
            <Input
              leftIcon={<Search size={14} />}
              placeholder="Ask a security question… e.g. 'Find brute-force attempts' or 'Show privilege escalation events'"
              value={queryText}
              onChange={(e) => setQueryText(e.target.value)}
              wrapperClassName="flex-1"
              className="text-base py-2.5"
            />
            <Button
              type="submit"
              variant="primary"
              size="md"
              leftIcon={<Play size={14} />}
              loading={isRunning}
              disabled={!queryText.trim()}
            >
              Run Hunt
            </Button>
          </form>

          {/* Suggested queries */}
          <div className="mt-3 flex flex-wrap gap-2">
            <span className="text-xs text-text-muted self-center">Suggested:</span>
            {SUGGESTED_QUERIES.map((q) => (
              <button
                key={q}
                onClick={() => { setQueryText(q); void runHunt(q); }}
                className="text-xs px-2.5 py-1 rounded bg-bg-elevated border border-border-default text-text-secondary hover:border-accent hover:text-accent transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {/* Running state */}
      {isRunning && (
        <LoadingState message={`Running threat hunt: "${runningQuery}"…`} />
      )}

      {/* Error */}
      {huntError && (
        <div className="flex items-start gap-2 p-4 bg-critical-bg border border-critical-border rounded-md text-sm text-critical-text">
          <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
          {huntError}
        </div>
      )}

      {/* Results */}
      {result && !isRunning && (
        <div className="space-y-4 animate-fade-in">
          {/* Query interpretation */}
          <Panel>
            <PanelHeader title="Query Interpretation" />
            <div className="p-4">
              <div className="flex items-start gap-2.5 p-3 bg-bg-elevated rounded border border-border-subtle">
                <Search size={14} className="text-accent flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs text-text-muted mb-1">Interpreted as</div>
                  <p className="text-sm text-text-primary">{result.interpretation}</p>
                </div>
              </div>
              <div className="flex items-center gap-4 mt-3 text-xs text-text-muted">
                <span>Query: <span className="font-mono text-text-secondary">"{result.queryText}"</span></span>
                <span>Executed: <span className="font-mono text-text-secondary">{formatTimestamp(result.timestamp, { relative: true })}</span></span>
                <span>Matched: <span className="font-medium text-text-primary">{result.matchingLogIds?.length ?? 0} events</span></span>
              </div>
            </div>
          </Panel>

          {/* Risk Indicators */}
          {result.riskIndicators && result.riskIndicators.length > 0 && (
            <Panel>
              <PanelHeader title="Risk Indicators" />
              <div className="p-4 space-y-2">
                {result.riskIndicators.map((r, i) => (
                  <div key={i} className="flex gap-2.5 text-sm">
                    <span className="text-high-DEFAULT font-mono mt-0.5 flex-shrink-0">⚠</span>
                    <span className="text-text-secondary">{r}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* Related Alerts */}
          {alertMap && alertMap.length > 0 && (
            <Panel>
              <PanelHeader title="Related Alerts" />
              <div className="p-3 flex flex-wrap gap-2">
                {alertMap.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded bg-bg-elevated border border-border-default hover:border-accent transition-colors text-xs"
                  >
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${alert.severity === 'CRITICAL' ? 'bg-critical-DEFAULT' : alert.severity === 'HIGH' ? 'bg-high-DEFAULT' : 'bg-medium-DEFAULT'}`} />
                    <span className="text-text-primary font-medium">{alert.title}</span>
                    <span className="text-text-muted">{alert.sourceIp}</span>
                  </button>
                ))}
              </div>
            </Panel>
          )}

          {/* Matching Events */}
          <Panel>
            <PanelHeader
              title="Matching Events"
              subtitle={`${result.matchingLogIds?.length ?? 0} events matched — showing first 15`}
            />
            {logMap && logMap.length > 0 ? (
              <div className="p-4 space-y-1.5 max-h-96 overflow-y-auto">
                {logMap.map((log) => (
                  <RawLogLine key={log.id} log={log.rawLog} />
                ))}
              </div>
            ) : (
              <EmptyState
                message="No matching events"
                description="The query did not match any security events in the current dataset."
                className="py-10"
              />
            )}
          </Panel>
        </div>
      )}

      {/* Empty state before first hunt */}
      {!result && !isRunning && !huntError && (
        <div className="py-16 text-center">
          <Search size={36} className="text-text-disabled mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-sm text-text-secondary">Enter a security question above or click a suggested query to begin hunting</p>
          <p className="text-xs text-text-muted mt-1">Results include matching events, related alerts, and risk indicators</p>
        </div>
      )}
    </div>
  );
}
