import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  TriangleAlert,
  Siren,
  CheckCircle,
  AlertCircle,
  MinusCircle,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  StatCard,
  SeverityBadge,
  StatusBadge,
  RiskScoreBar,
  Panel,
  PanelHeader,
  LoadingState,
  ErrorState,
} from '../../components/ui';
import { severityColor, formatIncidentTitle } from '../../lib/utils';
import type { TimeRange } from '../../app/TopBar';

interface DashboardPageProps {
  timeRange: TimeRange;
}

const CHART_COLORS = { events: '#388bfd', alerts: '#e3872d' };

// Custom dark tooltip for recharts
function DarkTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-bg-elevated border border-border-default rounded px-3 py-2 text-xs shadow-elevated">
      <p className="text-text-muted mb-1.5">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="font-medium" style={{ color: p.color }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

export function DashboardPage({ timeRange: _timeRange }: DashboardPageProps) {
  const navigate = useNavigate();

  const stats = useAsync(() => siemService.getDashboardStats(), []);
  const alerts = useAsync(() => siemService.getAlerts(undefined, 1, 8), []);
  const incidents = useAsync(() => siemService.getIncidents(1, 5), []);
  const analytics = useAsync(() => siemService.getAnalytics(7), []);
  const blocklist = useAsync(() => siemService.getBlocklist(), []);

  if (stats.status === 'error') return <ErrorState message="Failed to load dashboard" detail={stats.error.message} onRetry={stats.refetch} />;
  if (analytics.status === 'error') return <ErrorState message="Failed to load analytics" detail={analytics.error.message} onRetry={analytics.refetch} />;

  if (stats.status === 'loading' || analytics.status === 'loading' || !stats.data) {
    return <LoadingState message="Loading security overview…" className="py-24" />;
  }

  const d = stats.data;
  const highRiskCount = d.highRiskEvents > 0
    ? d.highRiskEvents
    : (analytics.data?.severityDistribution
        ?.filter((s) => s.severity === 'HIGH' || s.severity === 'CRITICAL')
        .reduce((acc, s) => acc + s.count, 0) ?? 0);

  const chartData = analytics.data?.eventsOverTime.map((p, i) => ({
    date: p.timestamp.slice(5),
    events: p.value,
    alerts: analytics.data?.alertsOverTime[i]?.value ?? 0,
  })) ?? [];

  const chartDateSubtitle = analytics.data?.eventsOverTime?.length
    ? `${analytics.data.eventsOverTime[0]?.timestamp} to ${analytics.data.eventsOverTime[analytics.data.eventsOverTime.length - 1]?.timestamp}`
    : undefined;

  const severityData = analytics.data?.severityDistribution.map((s) => ({
    name: s.severity,
    value: s.count,
    color: severityColor(s.severity),
  })) ?? [];

  function systemStatusIcon(status: string) {
    if (status === 'operational') return <CheckCircle size={13} className="text-low-DEFAULT" />;
    if (status === 'degraded') return <AlertCircle size={13} className="text-medium-DEFAULT" />;
    return <MinusCircle size={13} className="text-critical-DEFAULT" />;
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          label="Total Events"
          value={d.totalEvents.toLocaleString()}
          change={d.totalEventsChange}
          changeLabel="vs yesterday"
          icon={<Activity size={16} />}
          accentColor="#388bfd"
        />
        <StatCard
          label="Active Alerts"
          value={d.activeAlerts}
          change={d.activeAlertsChange}
          changeLabel="vs yesterday"
          icon={<ShieldAlert size={16} />}
          accentColor="#d29922"
          onClick={() => navigate('/alerts')}
        />
        <StatCard
          label="High Risk Events"
          value={highRiskCount.toLocaleString()}
          change={d.highRiskChange}
          changeLabel="vs yesterday"
          icon={<TriangleAlert size={16} />}
          accentColor="#e3872d"
        />
        <StatCard
          label="Critical Incidents"
          value={d.criticalIncidents}
          change={d.criticalIncidentsChange}
          changeLabel="vs yesterday"
          icon={<Siren size={16} />}
          accentColor="#f85149"
          onClick={() => navigate('/incidents')}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Events + Alerts time series */}
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Security Activity (Last 7 Days)"
            subtitle={chartDateSubtitle}
          />
          <div className="px-4 py-3 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="evGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={CHART_COLORS.events} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={CHART_COLORS.events} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="alGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={CHART_COLORS.alerts} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={CHART_COLORS.alerts} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: '#6e7681', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<DarkTooltip />} />
                <Area type="monotone" dataKey="events" name="Events" stroke={CHART_COLORS.events} strokeWidth={1.5} fill="url(#evGrad)" />
                <Area type="monotone" dataKey="alerts" name="Alerts" stroke={CHART_COLORS.alerts} strokeWidth={1.5} fill="url(#alGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        {/* Severity distribution pie */}
        <Panel>
          <PanelHeader title="Severity Distribution" />
          <div className="px-4 py-3 h-52 flex flex-col items-center justify-center">
            <ResponsiveContainer width="100%" height="70%">
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius="50%" outerRadius="80%" dataKey="value" paddingAngle={2}>
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) =>
                    active && payload?.length ? (
                      <div className="bg-bg-elevated border border-border-default rounded px-2 py-1 text-xs">
                        <span style={{ color: (payload[0] as { payload: { color: string } }).payload.color }}>
                          {(payload[0] as { name: string }).name}: {(payload[0] as { value: number }).value}
                        </span>
                      </div>
                    ) : null
                  }
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap justify-center gap-x-3 gap-y-1 mt-1">
              {severityData.map((s) => (
                <div key={s.name} className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
                  <span className="text-xs text-text-muted">{s.name} ({s.value})</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      {/* Alerts + Incidents + System Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Alerts */}
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Recent Security Alerts"
            actions={
              <button onClick={() => navigate('/alerts')} className="text-xs text-accent hover:text-accent-hover transition-colors">
                View all →
              </button>
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-default">
                  {['Severity', 'Alert', 'Source IP', 'Device', 'Status'].map((h) => (
                    <th key={h} className="px-3 py-2 text-left text-xs text-text-muted font-medium uppercase tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.status === 'loading' && (
                  <tr><td colSpan={5} className="py-6 text-center text-text-muted text-xs">Loading…</td></tr>
                )}
                {alerts.data?.items.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-border-subtle hover:bg-bg-elevated cursor-pointer transition-colors"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                  >
                    <td className="px-3 py-2.5"><SeverityBadge severity={alert.severity} size="sm" /></td>
                    <td className="px-3 py-2.5 text-text-primary font-medium max-w-[160px] truncate">{alert.title}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-secondary">{alert.sourceIp}</td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary">{alert.device}</td>
                    <td className="px-3 py-2.5"><StatusBadge status={alert.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* Active Incidents + System Health */}
        <div className="space-y-4">
          {/* Active Incidents */}
          <Panel>
            <PanelHeader
              title="Active Incidents"
              actions={
                <button onClick={() => navigate('/incidents')} className="text-xs text-accent hover:text-accent-hover transition-colors">
                  View all →
                </button>
              }
            />
            <div className="px-3 py-2 space-y-2">
              {incidents.status === 'loading' && <LoadingState size="sm" />}
              {incidents.data?.items.map((inc) => (
                <div
                  key={inc.id}
                  className="p-2.5 rounded bg-bg-elevated border border-border-subtle hover:border-border-default cursor-pointer transition-colors"
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                >
                  <div className="flex items-start gap-2 mb-1.5">
                    <SeverityBadge severity={inc.severity} size="sm" />
                    <span className="text-xs font-mono text-text-muted ml-auto">{inc.id}</span>
                  </div>
                  <p className="text-xs text-text-primary font-medium leading-snug mb-2 line-clamp-2">{formatIncidentTitle(inc)}</p>
                  <RiskScoreBar riskScore={inc.riskScore} />
                </div>
              ))}
            </div>
          </Panel>

          {/* System Health */}
          <Panel>
            <PanelHeader title="System Health" />
            <div className="px-3 py-2 space-y-1">
              {d.systemHealth.components.map((c) => (
                <div key={c.name} className="flex items-center gap-2 py-1.5 border-b border-border-subtle last:border-0">
                  {systemStatusIcon(c.status)}
                  <span className="text-xs text-text-secondary flex-1">{c.name}</span>
                  {c.latencyMs && (
                    <span className="text-2xs font-mono text-text-muted">{c.latencyMs}ms</span>
                  )}
                </div>
              ))}
            </div>
          </Panel>

          {/* Defensive Blocklist Panel */}
          <Panel>
            <PanelHeader
              title="Perimeter Blocklist"
              subtitle="Active simulated defenses"
            />
            <div className="px-3 py-2 space-y-1.5">
              {blocklist.status === 'loading' && <LoadingState size="sm" />}
              {(!blocklist.data || blocklist.data.length === 0) && (
                <p className="text-2xs text-text-muted py-2">No active IP blocks.</p>
              )}
              {blocklist.data?.slice(0, 4).map((b) => (
                <div key={b.id} className="flex items-center justify-between p-2 rounded bg-bg-elevated border border-border-subtle text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    <span className="font-mono text-text-primary text-[11px]">{b.ip}</span>
                  </div>
                  <span className="text-[10px] font-mono text-text-muted uppercase px-1.5 py-0.5 rounded bg-bg-app border border-border-subtle">
                    {b.status}
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
