import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { Send, Bot, User, Brain, ArrowRight, ShieldAlert } from 'lucide-react';
import { siemService } from '../../services';
import { useAsync } from '../../hooks/useAsync';
import {
  Panel,
  PanelHeader,
  ObservedEvidenceBlock,
  AiAssessmentBlock,
  RecommendationsBlock,
  Button,
} from '../../components/ui';
import { formatTimestamp, formatIncidentTitle, pluralize } from '../../lib/utils';
import type { CopilotMessage } from '../../types';

// Single Copilot message bubble
function CopilotMessageBubble({ message }: { message: CopilotMessage }) {
  const navigate = useNavigate();
  const isAnalyst = message.role === 'analyst';

  if (isAnalyst) {
    return (
      <div className="flex items-start gap-3 justify-end">
        <div className="max-w-[75%]">
          <div className="bg-accent-subtle border border-accent/30 rounded-md px-3 py-2.5">
            <p className="text-sm text-text-primary">{message.content}</p>
          </div>
          <div className="text-2xs text-text-muted mt-1 text-right font-mono">
            {formatTimestamp(message.timestamp, { relative: true })}
          </div>
        </div>
        <div className="w-7 h-7 rounded-full bg-accent flex items-center justify-center flex-shrink-0 mt-0.5">
          <User size={13} className="text-white" />
        </div>
      </div>
    );
  }

  const r = message.response;

  return (
    <div className="flex items-start gap-3">
      <div className="w-7 h-7 rounded-full bg-ai-muted flex items-center justify-center flex-shrink-0 mt-0.5">
        <Bot size={13} className="text-ai" />
      </div>
      <div className="flex-1 max-w-[90%]">
        {/* Lead-in */}
        {r && (
          <div className="mb-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-medium text-text-secondary">{r.leadIn}</span>
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-ai-muted text-ai text-2xs font-medium">
                <Brain size={9} />
                {message.incidentId ? 'Evidence Grounded' : 'General Telemetry'}
              </span>
            </div>
          </div>
        )}

        {r ? (
          <div className="space-y-3">
            <ObservedEvidenceBlock items={r.observedEvidence} />
            <AiAssessmentBlock content={r.aiAssessment} />
            <RecommendationsBlock items={r.recommendedNextSteps} />

            {r.suggestedResponseActions && r.suggestedResponseActions.length > 0 && (
              <div className="p-3 rounded-xl bg-slate-950/80 border border-cyan-500/30 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-cyan-400 uppercase tracking-wide">
                    <ShieldAlert size={14} />
                    <span>AI Suggested Response Actions</span>
                  </div>
                  <span className="text-[10px] text-amber-400 font-medium">Analyst Review Required</span>
                </div>

                <p className="text-2xs text-slate-400 leading-relaxed">
                  Recommended actions require human analyst review and approval before execution.
                </p>

                <div className="space-y-1.5">
                  {r.suggestedResponseActions.map((s, idx) => (
                    <div key={idx} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                      <div className="flex items-center justify-between font-mono text-[11px] mb-0.5">
                        <span className="font-bold text-cyan-300">{s.actionType}</span>
                        <span className="text-slate-400 text-2xs">{JSON.stringify(s.parameters)}</span>
                      </div>
                      <p className="text-slate-300 text-2xs leading-relaxed">{s.reasoning}</p>
                    </div>
                  ))}
                </div>

                {message.incidentId && (
                  <div className="pt-1 flex items-center justify-end">
                    <button
                      onClick={() => navigate(`/incidents/${message.incidentId}`)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors cursor-pointer font-medium"
                    >
                      <span>View &amp; Propose in Incident</span>
                      <ArrowRight size={13} />
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="bg-ai-subtle border border-ai-muted rounded-md px-3 py-2.5">
            <p className="text-sm text-text-secondary">{message.content}</p>
          </div>
        )}

        <div className="text-2xs text-text-muted mt-2 font-mono">
          {formatTimestamp(message.timestamp, { relative: true })}
        </div>
      </div>
    </div>
  );
}

// Typing / analyzing indicator
function AnalyzingIndicator() {
  return (
    <div className="flex items-start gap-3">
      <div className="w-7 h-7 rounded-full bg-ai-muted flex items-center justify-center flex-shrink-0">
        <Bot size={13} className="text-ai" />
      </div>
      <div className="bg-ai-subtle border border-ai-muted rounded-md px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className="text-xs text-ai">Analyzing</span>
          <div className="flex gap-1">
            {[0, 1, 2].map((i) => (
              <span
                key={i}
                className="w-1.5 h-1.5 rounded-full bg-ai animate-bounce"
                style={{ animationDelay: `${i * 0.15}s` }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export function CopilotPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  // Read incident ID from URL query params first (?incidentId=...), then location.state
  const queryIncidentId = searchParams.get('incidentId')?.trim() || null;
  const stateIncidentId = ((location.state as { incidentId?: string } | undefined)?.incidentId)?.trim() || null;
  const initialIncidentId = queryIncidentId || stateIncidentId || null;

  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(initialIncidentId);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { data: incidents } = useAsync(() => siemService.getIncidents(1, 10), []);
  const {
    data: activeIncident,
    error: activeIncidentError,
    status: activeIncidentStatus,
  } = useAsync(
    () => (activeIncidentId ? siemService.getIncidentById(activeIncidentId) : Promise.resolve(null)),
    [activeIncidentId],
  );

  // Synchronize route/query changes into active incident state
  useEffect(() => {
    const qId = searchParams.get('incidentId')?.trim() || null;
    const sId = ((location.state as { incidentId?: string } | undefined)?.incidentId)?.trim() || null;
    const target = qId || sId || null;
    if (target !== activeIncidentId) {
      setActiveIncidentId(target);
      setMessages([]);
    }
  }, [searchParams, location.state]);

  const handleSelectIncident = useCallback((id: string | null) => {
    setActiveIncidentId(id);
    setMessages([]);
    if (id) {
      setSearchParams({ incidentId: id });
    } else {
      setSearchParams({});
    }
  }, [setSearchParams]);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isAnalyzing]);

  async function sendMessage(text: string) {
    if (!text.trim() || isAnalyzing) return;
    setInputValue('');
    setIsAnalyzing(true);

    // Optimistic: add analyst message immediately
    const optimisticMsg: CopilotMessage = {
      id: `opt-${Date.now()}`,
      role: 'analyst',
      content: text,
      timestamp: new Date().toISOString(),
      incidentId: activeIncidentId ?? undefined,
    };
    setMessages((prev) => [...prev, optimisticMsg]);

    try {
      const response = await siemService.sendCopilotMessage(text, activeIncidentId ?? undefined);
      setMessages((prev) => [...prev, response]);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'An error occurred while analyzing your query.';
      const errMsg: CopilotMessage = {
        id: `err-${Date.now()}`,
        role: 'copilot',
        content: `Investigation Error: ${errorMsg}`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsAnalyzing(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    void sendMessage(inputValue);
  }

  const suggestedQuestions = activeIncidentId
    ? [
        'Why is this incident suspicious?',
        'What happened after the initial detection?',
        'What should I investigate next?',
        'Summarize this incident.',
      ]
    : [
        'What is our current security posture?',
        'What detection rules are active?',
        'How should I triage high-risk alerts?',
        'Explain the correlation methodology.',
      ];

  return (
    <div className="flex gap-4 h-[calc(100vh-theme(spacing.topbar)-2.5rem-2.5rem)] animate-fade-in">
      {/* Left: Investigation context sidebar */}
      <div className="w-60 flex-shrink-0 flex flex-col gap-3">
        <Panel className="flex-shrink-0">
          <PanelHeader title="Investigation Context" />
          <div className="px-3 py-2 space-y-1.5 max-h-72 overflow-y-auto">
            {/* General scope option */}
            <button
              onClick={() => handleSelectIncident(null)}
              className={`w-full text-left p-2 rounded text-xs transition-colors ${
                activeIncidentId === null
                  ? 'bg-accent-subtle border border-accent/30 text-accent font-medium'
                  : 'bg-bg-elevated border border-border-subtle text-text-secondary hover:border-border-default'
              }`}
            >
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="font-semibold text-2xs">General Posture</span>
                <span className="text-2xs ml-auto text-text-muted">Environment</span>
              </div>
              <p className="line-clamp-1 leading-snug text-2xs text-text-muted">No specific incident selected</p>
            </button>

            {incidents?.items.map((inc) => (
              <button
                key={inc.id}
                onClick={() => handleSelectIncident(inc.id)}
                className={`w-full text-left p-2 rounded text-xs transition-colors ${
                  activeIncidentId === inc.id
                    ? 'bg-accent-subtle border border-accent/30 text-accent'
                    : 'bg-bg-elevated border border-border-subtle text-text-secondary hover:border-border-default'
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="font-mono text-2xs">{inc.id}</span>
                  <span className={`text-2xs ml-auto ${inc.severity === 'CRITICAL' ? 'text-critical-text' : inc.severity === 'HIGH' ? 'text-high-text' : 'text-medium-text'}`}>
                    {inc.severity}
                  </span>
                </div>
                <p className="line-clamp-2 leading-snug">{formatIncidentTitle(inc)}</p>
              </button>
            ))}
          </div>
        </Panel>

        {activeIncident ? (
          <Panel>
            <div className="p-3">
              <div className="text-2xs text-text-muted uppercase tracking-wide mb-2">Active Incident</div>
              <p className="text-xs font-medium text-text-primary mb-2">{formatIncidentTitle(activeIncident)}</p>
              <div className="text-2xs text-text-muted space-y-1">
                <div>Source: <span className="font-mono text-text-secondary">{activeIncident.sourceIp}</span></div>
                <div>User: <span className="font-mono text-text-secondary">{activeIncident.targetUser}</span></div>
                <div>Alerts: <span className="text-text-secondary">{pluralize(activeIncident.relatedAlertIds.length, 'alert', 'alerts')}</span></div>
              </div>
              <button
                onClick={() => navigate(`/incidents/${activeIncident.id}`)}
                className="mt-3 w-full text-xs text-accent hover:underline text-left cursor-pointer"
              >
                View full investigation →
              </button>
            </div>
          </Panel>
        ) : activeIncidentId && activeIncidentStatus === 'error' ? (
          <Panel className="border-red-500/40 bg-red-950/20">
            <div className="p-3">
              <div className="text-2xs text-red-400 uppercase tracking-wide mb-1 font-semibold">Incident Not Found</div>
              <p className="text-xs font-mono text-red-300 mb-2">{activeIncidentId}</p>
              <p className="text-2xs text-text-muted leading-relaxed mb-3">
                {activeIncidentError?.message || `Incident ${activeIncidentId} could not be found or is inaccessible in the active database.`}
              </p>
              <Button
                variant="secondary"
                size="sm"
                className="w-full text-2xs"
                onClick={() => handleSelectIncident(null)}
              >
                Reset to General Posture
              </Button>
            </div>
          </Panel>
        ) : (
          <Panel>
            <div className="p-3">
              <div className="text-2xs text-text-muted uppercase tracking-wide mb-1">Investigation Scope</div>
              <p className="text-xs font-medium text-text-primary mb-1">General Security Posture</p>
              <p className="text-2xs text-text-muted leading-relaxed">
                Evaluating environment-level telemetry. Select an incident above to focus Copilot on specific incident evidence.
              </p>
            </div>
          </Panel>
        )}
      </div>

      {/* Right: Chat area */}
      <Panel className="flex-1 flex flex-col min-h-0">
        {/* Chat header */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border-default flex-shrink-0">
          <div className="w-8 h-8 rounded-full bg-ai-muted flex items-center justify-center">
            <Bot size={16} className="text-ai" />
          </div>
          <div>
            <div className="text-sm font-semibold text-text-primary">SIEM Copilot</div>
            <div className="text-2xs text-ai">Evidence-grounded investigation assistant</div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-2xs text-text-muted bg-bg-elevated border border-border-subtle px-2 py-0.5 rounded font-mono">
              {activeIncidentId
                ? (activeIncidentStatus === 'error' ? `Context: ${activeIncidentId} (Not Found)` : `Context: ${activeIncidentId}`)
                : 'Context: General Analysis'}
            </span>
            <div className="flex items-center gap-1.5 text-2xs text-low-text bg-low-bg border border-low-border px-2 py-0.5 rounded">
              <span className="w-1.5 h-1.5 rounded-full bg-low-DEFAULT animate-pulse-slow" />
              Operational
            </div>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-5">
          {messages.length === 0 && !isAnalyzing && (
            <div className="flex flex-col items-center justify-center h-full text-center py-12">
              <div className="w-12 h-12 rounded-full bg-ai-subtle border border-ai-muted flex items-center justify-center mb-4">
                <Bot size={22} className="text-ai" />
              </div>
              {activeIncidentId ? (
                activeIncidentStatus === 'error' ? (
                  <>
                    <h3 className="text-sm font-medium text-critical mb-1">Incident Not Found: {activeIncidentId}</h3>
                    <p className="text-xs text-text-secondary max-w-sm leading-relaxed mb-3">
                      The specified incident could not be found or is inaccessible in the database. Copilot cannot ground analysis in non-existent telemetry.
                    </p>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleSelectIncident(null)}
                    >
                      Switch to General Posture Mode
                    </Button>
                  </>
                ) : (
                  <>
                    <h3 className="text-sm font-medium text-text-primary mb-1">Incident Copilot: {activeIncidentId}</h3>
                    <p className="text-xs text-text-secondary max-w-sm leading-relaxed">
                      Ask questions about {activeIncidentId}. Responses are strictly grounded in observed evidence, detection rules, and timeline telemetry.
                    </p>
                    {activeIncident && (
                      <div className="mt-4 px-3 py-2 bg-bg-elevated border border-border-subtle rounded text-xs text-text-secondary">
                        Context: <span className="font-mono text-accent">{activeIncidentId}</span> — {pluralize(activeIncident.relatedLogIds.length, 'event', 'events')} correlated
                      </div>
                    )}
                  </>
                )
              ) : (
                <>
                  <h3 className="text-sm font-medium text-text-primary mb-1">SIEM Copilot (General Security Analysis)</h3>
                  <p className="text-xs text-text-secondary max-w-sm leading-relaxed">
                    No incident is currently selected. Copilot is operating in general security analysis mode. Select an incident from the sidebar to ground responses in specific incident telemetry.
                  </p>
                  <div className="mt-4 px-3 py-2 bg-bg-elevated border border-border-subtle rounded text-xs text-text-muted">
                    Mode: <span className="text-accent font-medium">General Environment Guidance</span>
                  </div>
                </>
              )}
            </div>
          )}

          {messages.map((msg) => (
            <CopilotMessageBubble key={msg.id} message={msg} />
          ))}

          {isAnalyzing && <AnalyzingIndicator />}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggested questions */}
        {messages.length === 0 && (
          <div className="px-4 pb-2 flex flex-wrap gap-1.5 border-t border-border-subtle pt-2">
            {suggestedQuestions.map((q) => (
              <button
                key={q}
                onClick={() => void sendMessage(q)}
                disabled={isAnalyzing}
                className="text-xs px-2.5 py-1 rounded bg-bg-elevated border border-border-default text-text-secondary hover:border-ai hover:text-ai transition-colors disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>
        )}

        {/* Input */}
        <div className="px-4 py-3 border-t border-border-default flex-shrink-0">
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              type="text"
              placeholder={activeIncidentId ? `Ask about ${activeIncidentId}…` : 'Ask a general security question…'}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              disabled={isAnalyzing}
              className="flex-1 bg-bg-elevated border border-border-default rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-ai focus:ring-1 focus:ring-ai/30 transition-colors disabled:opacity-50"
            />
            <Button
              type="submit"
              variant="primary"
              size="md"
              leftIcon={<Send size={14} />}
              loading={isAnalyzing}
              disabled={!inputValue.trim()}
              className="bg-ai hover:bg-ai-hover"
            >
              Send
            </Button>
          </form>
          <p className="text-2xs text-text-disabled mt-1.5">
            Responses are grounded in correlated security events. AI assessments require analyst verification before action.
          </p>
        </div>
      </Panel>
    </div>
  );
}

