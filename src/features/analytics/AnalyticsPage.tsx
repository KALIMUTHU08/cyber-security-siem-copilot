import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  PanelHeader,
  LoadingState,
  ErrorState,
} from '../../components/ui';
import { severityColor } from '../../lib/utils';
import type { TimeRange } from '../../app/TopBar';

interface AnalyticsPageProps {
  timeRange: TimeRange;
}

function dayCount(tr: TimeRange): number {
  if (tr === 'Last 7 days') return 7;
  if (tr === 'Last 30 days') return 30;
  return 1;
}

const DARK_TOOLTIP_STYLE = {
  contentStyle: {
    background: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '4px',
    fontSize: '11px',
    color: '#e6edf3',
  },
  labelStyle: { color: '#8b949e' },
  itemStyle: { color: '#e6edf3' },
};

const AXIS_STYLE = { fill: '#6e7681', fontSize: 10 };

export function AnalyticsPage({ timeRange }: AnalyticsPageProps) {
  const days = dayCount(timeRange);
  const { data, status, error, refetch } = useAsync(
    () => siemService.getAnalytics(Math.max(days, 1)),
    [days],
  );

  if (status === 'error') return <ErrorState message="Failed to load analytics" detail={error?.message} onRetry={refetch} />;
  if (status === 'loading' || !data) return <LoadingState message="Loading analytics…" className="py-24" />;

  const severityColors = data.severityDistribution.map((s) => severityColor(s.severity));

  const dateRangeStr = data?.eventsOverTime?.length
    ? ` (${data.eventsOverTime[0]?.timestamp} to ${data.eventsOverTime[data.eventsOverTime.length - 1]?.timestamp})`
    : '';

  const subtitle = days === 1
    ? `Showing data for the last 24 hours${dateRangeStr}`
    : `Showing data for the last ${days} days${dateRangeStr}`;

  return (
    <div className="space-y-5 animate-fade-in">
      <PageHeader
        title="Security Analytics"
        subtitle={subtitle}
      />

      {/* Row 1: Events + Alerts over time */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Security Events Over Time" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.eventsOverTime} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="evGrad2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#388bfd" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#388bfd" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="timestamp" tick={AXIS_STYLE} axisLine={false} tickLine={false} tickFormatter={(v: string) => v.slice(5)} />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="value" name="Events" stroke="#388bfd" strokeWidth={2} fill="url(#evGrad2)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Alerts Over Time" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.alertsOverTime} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="alGrad2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e3872d" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#e3872d" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="timestamp" tick={AXIS_STYLE} axisLine={false} tickLine={false} tickFormatter={(v: string) => v.slice(5)} />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="value" name="Alerts" stroke="#e3872d" strokeWidth={2} fill="url(#alGrad2)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      {/* Row 2: Severity + Top IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Alert Severity Distribution" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.severityDistribution} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="severity" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Count" radius={[3, 3, 0, 0]}>
                  {data.severityDistribution.map((_, i) => (
                    <Cell key={i} fill={severityColors[i]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Top Source IPs" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={data.topSourceIps}
                layout="vertical"
                margin={{ top: 4, right: 12, left: 8, bottom: 0 }}
              >
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="ip"
                  tick={{ fill: '#8b949e', fontSize: 10, fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                  width={110}
                />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Events" radius={[0, 3, 3, 0]}>
                  {data.topSourceIps.map((ip, i) => (
                    <Cell key={i} fill={severityColor(ip.severity)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      {/* Row 3: Top users + Detection types */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Most Targeted Users" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={data.topTargetUsers}
                layout="vertical"
                margin={{ top: 4, right: 12, left: 8, bottom: 0 }}
              >
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="username"
                  tick={{ fill: '#8b949e', fontSize: 10, fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                  width={80}
                />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Events" radius={[0, 3, 3, 0]}>
                  {data.topTargetUsers.map((u, i) => (
                    <Cell key={i} fill={severityColor(u.severity)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Most Common Detection Types" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.topDetectionTypes} margin={{ top: 4, right: 4, left: -28, bottom: 30 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="ruleName"
                  tick={{ fill: '#6e7681', fontSize: 9 }}
                  axisLine={false}
                  tickLine={false}
                  angle={-25}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Triggers" fill="#388bfd" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      {/* Row 4: Login stats + Incident trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Failed vs Successful Logins" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.loginStats} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="timestamp" tick={AXIS_STYLE} axisLine={false} tickLine={false} tickFormatter={(v: string) => v.slice(5)} />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Bar dataKey="successful" name="Successful" stackId="a" fill="#3fb950" radius={[0, 0, 0, 0]} />
                <Bar dataKey="failed" name="Failed" stackId="a" fill="#f85149" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Incident Trends" />
          <div className="p-4 h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.incidentTrends} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f85149" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f85149" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="timestamp" tick={AXIS_STYLE} axisLine={false} tickLine={false} tickFormatter={(v: string) => v.slice(5)} />
                <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                <Tooltip {...DARK_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="value" name="Incidents" stroke="#f85149" strokeWidth={2} fill="url(#incGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>
    </div>
  );
}
