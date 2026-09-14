import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Play,
  Clock,
  AlertTriangle,
  Plus,
  RefreshCw,
  Ban,
  UserX,
  Eye,
  Radio,
  WifiOff,
  Sparkles,
  ArrowRight,
  Info,
  X,
} from 'lucide-react';
import type {
  ResponseAction,
  ResponseActionType,
  SuggestedResponseAction,
} from '../../types';
import { siemService } from '../../services';
import { useAuth } from '../../contexts/AuthContext';

interface ResponseActionsPanelProps {
  incidentId: string;
  incidentSourceIp?: string;
  incidentTargetUser?: string;
  incidentDevice?: string;
  suggestedActions?: SuggestedResponseAction[];
}

const ACTION_TYPES: { type: ResponseActionType; label: string; icon: any; desc: string }[] = [
  {
    type: 'BLOCK_IP',
    label: 'Block IP Address',
    icon: Ban,
    desc: 'Simulate perimeter firewall drop of inbound/outbound packets from IP',
  },
  {
    type: 'LOCK_ACCOUNT',
    label: 'Lock User Account',
    icon: UserX,
    desc: 'Simulate temporary lock on user credentials to halt suspected account takeover',
  },
  {
    type: 'ADD_WATCHLIST_IP',
    label: 'Add to IP Watchlist',
    icon: Eye,
    desc: 'Add suspicious reconnaissance source IP to perimeter watchlist for anomaly tracking',
  },
  {
    type: 'INCREASE_MONITORING',
    label: 'Increase Host Monitoring',
    icon: Radio,
    desc: 'Heighten telemetry sampling and rule evaluation for the affected system',
  },
  {
    type: 'ISOLATE_HOST',
    label: 'Isolate Host',
    icon: WifiOff,
    desc: 'Simulate endpoint quarantine from local network while maintaining SIEM agent link',
  },
];

export const ResponseActionsPanel: React.FC<ResponseActionsPanelProps> = ({
  incidentId,
  incidentSourceIp = '',
  incidentTargetUser = '',
  incidentDevice = '',
  suggestedActions = [],
}) => {
  const { hasPermission } = useAuth();
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedType, setSelectedType] = useState<ResponseActionType>('BLOCK_IP');
  const [paramIp, setParamIp] = useState(incidentSourceIp);
  const [paramUsername, setParamUsername] = useState(incidentTargetUser);
  const [paramTarget, setParamTarget] = useState(incidentDevice || incidentSourceIp);
  const [paramHost, setParamHost] = useState(incidentDevice);
  const [durationSeconds, setDurationSeconds] = useState(86400);
  const [notes, setNotes] = useState('');
  const [copilotReasoning, setCopilotReasoning] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Approve / Reject Note Modal
  const [promptAction, setPromptAction] = useState<{
    id: string;
    actionType: 'approve' | 'reject';
  } | null>(null);
  const [actionNote, setActionNote] = useState('');

  const canRecommend = hasPermission('response.recommend');
  const canApprove = hasPermission('response.approve');
  const canExecute = hasPermission('response.execute');

  const fetchActions = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await siemService.getResponseActions(incidentId);
      setActions(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch incident response actions.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, [incidentId]);

  const openCreateFromSuggestion = (suggestion: SuggestedResponseAction) => {
    setSelectedType(suggestion.actionType);
    if (suggestion.parameters.ip) setParamIp(suggestion.parameters.ip);
    if (suggestion.parameters.username) setParamUsername(suggestion.parameters.username);
    if (suggestion.parameters.target) setParamTarget(suggestion.parameters.target);
    if (suggestion.parameters.host) setParamHost(suggestion.parameters.host);
    if (suggestion.parameters.duration_seconds) setDurationSeconds(suggestion.parameters.duration_seconds);
    setCopilotReasoning(suggestion.reasoning);
    setNotes(`Recommended by SIEM Copilot AI: ${suggestion.reasoning}`);
    setShowCreateModal(true);
  };

  const handleCreateAction = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setActionSuccess(null);

    const parameters: Record<string, any> = {};
    if (selectedType === 'BLOCK_IP') {
      parameters.ip = paramIp;
      parameters.duration_seconds = durationSeconds;
    } else if (selectedType === 'LOCK_ACCOUNT') {
      parameters.username = paramUsername;
      parameters.duration_seconds = durationSeconds;
    } else if (selectedType === 'ADD_WATCHLIST_IP') {
      parameters.ip = paramIp;
    } else if (selectedType === 'INCREASE_MONITORING') {
      parameters.target = paramTarget;
    } else if (selectedType === 'ISOLATE_HOST') {
      parameters.host = paramHost;
    }

    try {
      const created = await siemService.createResponseAction(incidentId, {
        actionType: selectedType,
        parameters,
        notes,
        copilotReasoning: copilotReasoning || undefined,
      });
      setActions((prev) => [...prev, created]);
      setActionSuccess(`Response action '${created.actionType}' created in PENDING_APPROVAL state.`);
      setShowCreateModal(false);
      setNotes('');
      setCopilotReasoning('');
    } catch (err: any) {
      setError(err?.message || 'Failed to create response action.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleApprove = async () => {
    if (!promptAction) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await siemService.approveResponseAction(incidentId, promptAction.id, actionNote);
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setActionSuccess(`Action '${updated.actionType}' APPROVED by analyst.`);
      setPromptAction(null);
      setActionNote('');
    } catch (err: any) {
      setError(err?.message || 'Approval failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!promptAction) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const updated = await siemService.rejectResponseAction(incidentId, promptAction.id, actionNote);
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setActionSuccess(`Action '${updated.actionType}' REJECTED.`);
      setPromptAction(null);
      setActionNote('');
    } catch (err: any) {
      setError(err?.message || 'Rejection failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleExecute = async (actionId: string) => {
    setError(null);
    setActionSuccess(null);
    try {
      const updated = await siemService.executeResponseAction(incidentId, actionId);
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setActionSuccess(`Simulated defensive action '${updated.actionType}' EXECUTED successfully.`);
    } catch (err: any) {
      setError(err?.message || 'Execution failed.');
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PENDING_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
            <Clock className="w-3 h-3" /> PENDING APPROVAL
          </span>
        );
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
            <ShieldCheck className="w-3 h-3" /> APPROVED
          </span>
        );
      case 'EXECUTED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> EXECUTED
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/30">
            <XCircle className="w-3 h-3" /> REJECTED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/40">
            <AlertTriangle className="w-3 h-3" /> FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              AI-Assisted Incident Response Actions
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enforces strict two-tier approval: Analyst recommends/approves &rarr; Operator executes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchActions}
            title="Refresh actions"
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          {canRecommend && (
            <button
              onClick={() => {
                setCopilotReasoning('');
                setNotes('');
                setShowCreateModal(true);
              }}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow-md shadow-cyan-900/30 flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Propose Action</span>
            </button>
          )}
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div className="p-3 rounded-lg bg-slate-950/80 border border-cyan-500/20 flex items-start gap-2.5 text-xs text-slate-300">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-cyan-300">Safety &amp; Compliance Boundary:</strong> Response actions simulate defensive operations strictly within the platform database (no shell execution or external firewall commands). Every action requires human analyst approval before execution.
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {actionSuccess && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-200 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* AI Copilot Suggestions Section */}
      {suggestedActions && suggestedActions.length > 0 && (
        <div className="space-y-2.5">
          <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" />
            Copilot Recommended Defensive Proposals
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {suggestedActions.map((s, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950/70 border border-cyan-500/25 hover:border-cyan-500/40 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                      <Ban className="w-3.5 h-3.5 text-cyan-400" />
                      {s.actionType}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {s.parameters.ip || s.parameters.username || s.parameters.target || 'target'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed mb-3">{s.reasoning}</p>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-[10px] text-amber-400/90 font-medium">Analyst approval required</span>
                  {canRecommend && (
                    <button
                      onClick={() => openCreateFromSuggestion(s)}
                      className="px-2.5 py-1 rounded bg-cyan-600/80 hover:bg-cyan-600 text-white text-[11px] font-medium flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      <span>Create Action</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action Ledger */}
      <div className="space-y-3">
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Response Actions Lifecycle Ledger ({actions.length})
        </div>

        {actions.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs rounded-xl bg-slate-950/40 border border-dashed border-slate-800">
            No response actions recorded for this incident yet. Propose an action or promote a Copilot suggestion.
          </div>
        ) : (
          <div className="space-y-2.5">
            {actions.map((act) => {
              const typeMeta = ACTION_TYPES.find((t) => t.type === act.actionType);
              const Icon = typeMeta?.icon || ShieldCheck;

              return (
                <div
                  key={act.id}
                  className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/90 hover:border-slate-700/80 transition-all space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-slate-800/60 text-cyan-400 border border-slate-700/50">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-slate-100 font-mono">{act.actionType}</span>
                          {getStatusBadge(act.status)}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          Parameters: {JSON.stringify(act.parameters)}
                        </div>
                      </div>
                    </div>

                    {/* Action Controls */}
                    <div className="flex items-center gap-2 pt-2 sm:pt-0">
                      {act.status === 'PENDING_APPROVAL' && canApprove && (
                        <>
                          <button
                            onClick={() => setPromptAction({ id: act.id, actionType: 'approve' })}
                            className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>Approve</span>
                          </button>
                          <button
                            onClick={() => setPromptAction({ id: act.id, actionType: 'reject' })}
                            className="px-2.5 py-1 rounded bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-500/30 text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            <span>Reject</span>
                          </button>
                        </>
                      )}

                      {act.status === 'APPROVED' && canExecute && (
                        <button
                          onClick={() => handleExecute(act.id)}
                          className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 shadow-md shadow-emerald-900/30 transition-all cursor-pointer"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>Execute Action</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Notes & Audit Trails */}
                  {(act.notes || act.copilotReasoning) && (
                    <div className="text-xs text-slate-300 p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                      {act.copilotReasoning && (
                        <div className="text-[11px] text-cyan-300 mb-1">
                          <span className="font-semibold uppercase text-cyan-400 text-[10px]">AI Reasoning: </span>
                          {act.copilotReasoning}
                        </div>
                      )}
                      {act.notes && (
                        <div className="text-[11px] text-slate-300">
                          <span className="font-semibold uppercase text-slate-400 text-[10px]">Analyst Note: </span>
                          {act.notes}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Footer metadata */}
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-slate-500 font-mono pt-1">
                    <span>Proposed: {new Date(act.recommendedAt).toLocaleTimeString()}</span>
                    {act.approvedAt && <span className="text-blue-400">Approved: {new Date(act.approvedAt).toLocaleTimeString()}</span>}
                    {act.executedAt && <span className="text-emerald-400">Executed: {new Date(act.executedAt).toLocaleTimeString()}</span>}
                    {act.rejectedAt && <span className="text-red-400">Rejected: {new Date(act.rejectedAt).toLocaleTimeString()}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Propose Action Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                Propose Incident Response Action
              </h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateAction} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Action Type (Whitelisted)</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {ACTION_TYPES.map((t) => {
                    const Icon = t.icon;
                    const isSelected = selectedType === t.type;
                    return (
                      <button
                        key={t.type}
                        type="button"
                        onClick={() => setSelectedType(t.type)}
                        className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                            : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                          <span className="text-xs font-bold font-mono">{t.type}</span>
                        </div>
                        <p className="text-[10px] text-slate-400 line-clamp-2 leading-tight">{t.desc}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Dynamic Inputs Based on Selected Type */}
              {selectedType === 'BLOCK_IP' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">IPv4 Address to Block</label>
                    <input
                      type="text"
                      required
                      value={paramIp}
                      onChange={(e) => setParamIp(e.target.value)}
                      placeholder="e.g. 198.51.100.42"
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">Simulated Duration (seconds)</label>
                    <input
                      type="number"
                      value={durationSeconds}
                      onChange={(e) => setDurationSeconds(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                </div>
              )}

              {selectedType === 'LOCK_ACCOUNT' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">Username to Lock</label>
                    <input
                      type="text"
                      required
                      value={paramUsername}
                      onChange={(e) => setParamUsername(e.target.value)}
                      placeholder="e.g. admin or alice"
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">Simulated Duration (seconds)</label>
                    <input
                      type="number"
                      value={durationSeconds}
                      onChange={(e) => setDurationSeconds(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                </div>
              )}

              {selectedType === 'ADD_WATCHLIST_IP' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Watchlist IP Address</label>
                  <input
                    type="text"
                    required
                    value={paramIp}
                    onChange={(e) => setParamIp(e.target.value)}
                    placeholder="e.g. 203.0.113.15"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              )}

              {selectedType === 'INCREASE_MONITORING' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Target Host or Resource</label>
                  <input
                    type="text"
                    required
                    value={paramTarget}
                    onChange={(e) => setParamTarget(e.target.value)}
                    placeholder="e.g. srv-app-01 or 192.168.1.50"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              )}

              {selectedType === 'ISOLATE_HOST' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Endpoint Hostname to Isolate</label>
                  <input
                    type="text"
                    required
                    value={paramHost}
                    onChange={(e) => setParamHost(e.target.value)}
                    placeholder="e.g. srv-payment-gateway"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Analyst Notes &amp; Justification</label>
                <textarea
                  rows={2}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Justification for response action proposal..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition-all cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Proposing...' : 'Submit for Approval'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Note Prompt for Approve / Reject */}
      {promptAction && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
            <h3 className="text-sm font-bold text-slate-100 mb-2 capitalize">
              {promptAction.actionType} Response Action
            </h3>
            <p className="text-xs text-slate-400 mb-3">
              Add optional note documenting rationale for this decision:
            </p>

            <textarea
              rows={3}
              value={actionNote}
              onChange={(e) => setActionNote(e.target.value)}
              placeholder="e.g. Verified with threat intelligence feed..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none mb-4"
            />

            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setPromptAction(null)}
                className="px-3.5 py-1.5 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isSubmitting}
                onClick={promptAction.actionType === 'approve' ? handleApprove : handleReject}
                className={`px-4 py-1.5 rounded-xl text-white text-xs font-semibold cursor-pointer ${
                  promptAction.actionType === 'approve'
                    ? 'bg-blue-600 hover:bg-blue-500'
                    : 'bg-red-600 hover:bg-red-500'
                }`}
              >
                {isSubmitting ? 'Processing...' : `Confirm ${promptAction.actionType}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
