import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
  RiskScoreBar,
  DataTable,
  LoadingState,
  ErrorState,
  Input,
  Select,
  Button,
} from '../../components/ui';
import { formatTimestamp } from '../../lib/utils';
import type { SecurityAlert, Severity, AlertStatus } from '../../types';
import type { Column } from '../../components/ui/DataTable';

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
];
const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'NEW', label: 'New' },
  { value: 'INVESTIGATING', label: 'Investigating' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'DISMISSED', label: 'Dismissed' },
];

export function AlertsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  const { data, status: loadStatus, error, refetch } = useAsync(
    () =>
      siemService.getAlerts(
        {
          search: search || undefined,
          severity: (severity as Severity) || undefined,
          status: (status as AlertStatus) || undefined,
          sourceIp: sourceIp || undefined,
        },
        1,
        50,
      ),
    [search, severity, status, sourceIp],
  );

  const columns: Column<SecurityAlert>[] = [
    {
      key: 'severity',
      header: 'Severity',
      width: '100px',
      render: (r) => <SeverityBadge severity={r.severity} size="sm" />,
    },
    {
      key: 'title',
      header: 'Alert',
      render: (r) => <span className="font-medium text-text-primary">{r.title}</span>,
    },
    {
      key: 'detectionRuleName',
      header: 'Detection Rule',
      className: 'text-xs text-text-secondary',
      render: (r) => r.detectionRuleName,
    },
    {
      key: 'sourceIp',
      header: 'Source IP',
      className: 'font-mono text-xs',
      render: (r) => r.sourceIp,
    },
    {
      key: 'username',
      header: 'Username',
      className: 'font-mono text-xs text-text-secondary',
      render: (r) => r.username,
    },
    {
      key: 'device',
      header: 'Device',
      className: 'text-xs text-text-secondary',
      render: (r) => r.device,
    },
    {
      key: 'riskScore',
      header: 'Risk',
      width: '100px',
      render: (r) => <RiskScoreBar riskScore={r.riskScore} />,
    },
    {
      key: 'firstSeen',
      header: 'First Seen',
      className: 'font-mono text-xs text-text-muted whitespace-nowrap',
      render: (r) => formatTimestamp(r.firstSeen, { relative: true }),
    },
    {
      key: 'status',
      header: 'Status',
      width: '110px',
      render: (r) => <StatusBadge status={r.status} />,
    },
  ];

  return (
    <div className="space-y-4 animate-fade-in">
      <PageHeader
        title="Security Alerts"
        subtitle={data ? `${data.total} alert${data.total !== 1 ? 's' : ''} matching current filters` : undefined}
        actions={
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<Filter size={13} />}
            onClick={() => setShowFilters((v) => !v)}
          >
            Filters
          </Button>
        }
      />

      {/* Filter bar */}
      <Panel>
        <div className="p-3 flex flex-wrap gap-2">
          <Input
            leftIcon={<Search size={13} />}
            placeholder="Search alerts, IPs, users…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            wrapperClassName="flex-1 min-w-[200px]"
          />
          {showFilters && (
            <>
              <Select
                options={SEVERITY_OPTIONS}
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                wrapperClassName="w-40"
              />
              <Select
                options={STATUS_OPTIONS}
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                wrapperClassName="w-40"
              />
              <Input
                placeholder="Source IP…"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                wrapperClassName="w-36"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => { setSearch(''); setSeverity(''); setStatus(''); setSourceIp(''); }}
              >
                Clear
              </Button>
            </>
          )}
        </div>
      </Panel>

      {/* Table */}
      <Panel>
        {loadStatus === 'loading' && <LoadingState message="Loading alerts…" />}
        {loadStatus === 'error' && <ErrorState message="Failed to load alerts" detail={error?.message} onRetry={refetch} />}
        {loadStatus === 'success' && (
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            getRowKey={(r) => r.id}
            onRowClick={(r) => navigate(`/alerts/${r.id}`)}
            emptyMessage="No alerts match the current filters."
          />
        )}
      </Panel>
    </div>
  );
}
