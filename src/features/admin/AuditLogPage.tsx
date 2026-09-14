import React, { useState, useEffect } from 'react';
import {
  ClipboardList,
  Search,
  Filter,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  User,
} from 'lucide-react';
import type { AuditLogEntry } from '../../types/auth';
import { siemService } from '../../services';

export const AuditLogPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actionQuery, setActionQuery] = useState('');
  const [resultFilter, setResultFilter] = useState<'all' | 'success' | 'failure'>('all');
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const fetchLogs = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await siemService.getAuditLogs({
        action: actionQuery || undefined,
        result: resultFilter === 'all' ? undefined : resultFilter,
        pageSize: 100,
      });
      setLogs(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load audit trail.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [resultFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchLogs();
  };

  const toggleExpand = (id: string) => {
    setExpandedRows((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getActionBadgeColor = (action: string) => {
    if (action.startsWith('login.failure') || action.includes('reject') || action.includes('failed')) {
      return 'bg-red-500/20 text-red-300 border-red-500/30';
    }
    if (action.startsWith('login.success') || action.includes('approve') || action.includes('executed')) {
      return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
    }
    if (action.includes('user.') || action.includes('role')) {
      return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
    }
    if (action.includes('response_action')) {
      return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    }
    return 'bg-slate-700/40 text-slate-300 border-slate-600/40';
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <ClipboardList className="w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">Security Audit Logs</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, append-only ledger tracking administrative actions, user logins, and response executions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchLogs}
            title="Refresh logs"
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Search className="w-3.5 h-3.5" />
            </div>
            <input
              type="text"
              value={actionQuery}
              onChange={(e) => setActionQuery(e.target.value)}
              placeholder="Search actions (e.g. login, response_action, user, rule)..."
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-purple-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-purple-600/80 hover:bg-purple-600 text-white rounded-lg text-xs font-medium transition-colors cursor-pointer"
          >
            Search
          </button>
        </form>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <div className="inline-flex rounded-lg bg-slate-950 p-0.5 border border-slate-800 text-xs">
            {(['all', 'success', 'failure'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => setResultFilter(mode)}
                className={`px-2.5 py-1 rounded-md capitalize text-[11px] font-medium transition-all cursor-pointer ${
                  resultFilter === mode
                    ? 'bg-purple-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Logs Table */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 overflow-hidden shadow-xl">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Recorded Audit Trail ({logs.length} entries)
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold text-[10px]">
                <th className="py-3 px-4 w-8"></th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Action Event</th>
                <th className="py-3 px-4">Operator / Subject</th>
                <th className="py-3 px-4">Resource Target</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Origin IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <div className="inline-block w-6 h-6 border-2 border-purple-500/30 border-t-purple-500 rounded-full animate-spin mb-2" />
                    <div>Loading audit ledger...</div>
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No matching audit entries found.
                  </td>
                </tr>
              ) : (
                logs.map((item) => {
                  const isExpanded = !!expandedRows[item.id];
                  const isSuccess = item.result === 'success';

                  return (
                    <React.Fragment key={item.id}>
                      <tr
                        onClick={() => toggleExpand(item.id)}
                        className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                      >
                        <td className="py-3 px-4 text-slate-500">
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>

                        <td className="py-3 px-4 text-slate-300 font-mono text-[11px] whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-slate-500" />
                            {new Date(item.timestamp).toLocaleString()}
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <span
                            className={`inline-block font-mono text-[10px] font-semibold px-2 py-0.5 rounded border ${getActionBadgeColor(
                              item.action
                            )}`}
                          >
                            {item.action}
                          </span>
                        </td>

                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5 text-slate-200">
                            <User className="w-3 h-3 text-slate-500" />
                            <span className="font-mono text-[11px]">{item.userEmail || item.userId || 'system'}</span>
                          </div>
                        </td>

                        <td className="py-3 px-4 text-slate-300 font-mono text-[11px]">
                          {item.resourceType ? (
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                              {item.resourceType}:{item.resourceId || '*'}
                            </span>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          <span
                            className={`inline-flex items-center gap-1 text-[11px] font-medium ${
                              isSuccess ? 'text-emerald-400' : 'text-red-400'
                            }`}
                          >
                            {isSuccess ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                            <span className="capitalize">{item.result}</span>
                          </span>
                        </td>

                        <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                          {item.sourceIp || '127.0.0.1'}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950/60">
                          <td colSpan={7} className="py-3 px-8">
                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
                              <div className="text-[10px] uppercase font-semibold text-slate-500 mb-1.5">
                                Audit Event Payload Details
                              </div>
                              <pre className="overflow-x-auto whitespace-pre-wrap text-cyan-300">
                                {JSON.stringify(item.details, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
