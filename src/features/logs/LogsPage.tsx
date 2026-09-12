import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { useAsync } from '../../hooks/useAsync';
import { siemService } from '../../services';
import {
  PageHeader,
  Panel,
  DataTable,
  Drawer,
  RawLogLine,
  LoadingState,
  ErrorState,
  Input,
  Select,
} from '../../components/ui';
import { formatTimestamp } from '../../lib/utils';
import type { SecurityLog, EventType, LogStatus } from '../../types';
import type { Column } from '../../components/ui/DataTable';

const EVENT_TYPE_OPTIONS = [
  { value: '', label: 'All Event Types' },
  { value: 'LOGIN', label: 'Login' },
  { value: 'LOGIN_FAILED', label: 'Login Failed' },
  { value: 'FILE_ACCESS', label: 'File Access' },
  { value: 'FILE_DELETE', label: 'File Delete' },
  { value: 'PROCESS_STARTED', label: 'Process Started' },
  { value: 'NETWORK_CONNECTION', label: 'Network Connection' },
  { value: 'CONNECTION_BLOCKED', label: 'Connection Blocked' },
  { value: 'PRIVILEGE_CHANGE', label: 'Privilege Change' },
];

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'SUCCESS', label: 'Success' },
  { value: 'FAILURE', label: 'Failure' },
  { value: 'BLOCKED', label: 'Blocked' },
];

export function LogsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [eventType, setEventType] = useState('');
  const [logStatus, setLogStatus] = useState('');
  const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(null);

  const { data, status, error, refetch } = useAsync(
    () =>
      siemService.getLogs(
        {
          search: search || undefined,
          sourceIp: sourceIp || undefined,
          username: username || undefined,
          eventType: (eventType as EventType) || undefined,
          status: (logStatus as LogStatus) || undefined,
        },
        1,
        50,
      ),
    [search, sourceIp, username, eventType, logStatus],
  );

  const columns: Column<SecurityLog>[] = [
    {
      key: 'timestamp',
      header: 'Timestamp',
      width: '160px',
      className: 'font-mono text-xs text-text-muted whitespace-nowrap',
      render: (r) => formatTimestamp(r.timestamp).slice(0, 17),
    },
    {
      key: 'sourceIp',
      header: 'Source IP',
      width: '130px',
      className: 'font-mono text-xs',
      render: (r) => r.sourceIp,
    },
    {
      key: 'destinationIp',
      header: 'Dest IP',
      width: '130px',
      className: 'font-mono text-xs text-text-secondary',
      render: (r) => r.destinationIp,
    },
    {
      key: 'username',
      header: 'User',
      width: '100px',
      className: 'font-mono text-xs',
      render: (r) => r.username,
    },
    {
      key: 'eventType',
      header: 'Event',
      render: (r) => (
        <span className="text-xs font-mono bg-bg-elevated border border-border-subtle px-1.5 py-0.5 rounded">
          {r.eventType}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '90px',
      render: (r) => (
        <span
          className={`text-xs font-medium ${
            r.status === 'SUCCESS'
              ? 'text-low-text'
              : r.status === 'FAILURE'
              ? 'text-critical-text'
              : r.status === 'BLOCKED'
              ? 'text-medium-text'
              : 'text-text-muted'
          }`}
        >
          {r.status}
        </span>
      ),
    },
    {
      key: 'destinationPort',
      header: 'Port',
      width: '60px',
      className: 'font-mono text-xs text-text-muted',
      render: (r) => r.destinationPort?.toString() ?? '—',
    },
    {
      key: 'device',
      header: 'Device',
      className: 'text-xs text-text-secondary',
      render: (r) => r.device,
    },
  ];

  return (
    <div className="space-y-4 animate-fade-in">
      <PageHeader
        title="Log Explorer"
        subtitle={data ? `${data.total} events — click a row for details` : undefined}
      />

      {/* Filters */}
      <Panel>
        <div className="p-3 flex flex-wrap gap-2">
          <Input
            leftIcon={<Search size={13} />}
            placeholder="Search logs…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            wrapperClassName="flex-1 min-w-[180px]"
          />
          <Input
            placeholder="Source IP…"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            wrapperClassName="w-36"
            className="font-mono text-xs"
          />
          <Input
            placeholder="Username…"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            wrapperClassName="w-32"
            className="font-mono text-xs"
          />
          <Select
            options={EVENT_TYPE_OPTIONS}
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            wrapperClassName="w-44"
          />
          <Select
            options={STATUS_OPTIONS}
            value={logStatus}
            onChange={(e) => setLogStatus(e.target.value)}
            wrapperClassName="w-36"
          />
        </div>
      </Panel>

      {/* Table */}
      <Panel>
        {status === 'loading' && <LoadingState message="Loading logs…" />}
        {status === 'error' && (
          <ErrorState message="Failed to load logs" detail={error?.message} onRetry={refetch} />
        )}
        {status === 'success' && (
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            getRowKey={(r) => r.id}
            onRowClick={(r) => setSelectedLog(r)}
            emptyMessage="No log events match the current filters."
            stickyHeader
          />
        )}
      </Panel>

      {/* Log Detail Drawer */}
      <Drawer
        open={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title={`Log Event — ${selectedLog?.eventType ?? ''}`}
        subtitle={selectedLog?.id}
      >
        {selectedLog && (
          <div className="space-y-5">
            {/* Parsed fields */}
            <div>
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Parsed Fields
              </h3>
              <div className="grid grid-cols-2 gap-px bg-border-subtle rounded overflow-hidden">
                {[
                  { label: 'Timestamp', value: formatTimestamp(selectedLog.timestamp) },
                  { label: 'Event Type', value: selectedLog.eventType },
                  { label: 'Source IP', value: selectedLog.sourceIp },
                  { label: 'Dest IP', value: selectedLog.destinationIp },
                  { label: 'Username', value: selectedLog.username },
                  { label: 'Status', value: selectedLog.status },
                  { label: 'Device', value: selectedLog.device },
                  { label: 'Dest Port', value: selectedLog.destinationPort?.toString() ?? '—' },
                  ...Object.entries(selectedLog.parsedFields).map(([k, v]) => ({ label: k, value: v })),
                ].map(({ label, value }) => (
                  <div key={label} className="bg-bg-elevated px-3 py-2">
                    <div className="text-2xs text-text-muted mb-0.5">{label}</div>
                    <div className="text-xs font-mono text-text-primary break-all">{value}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Raw log */}
            <div>
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Raw Log
              </h3>
              <RawLogLine log={selectedLog.rawLog} />
            </div>

            {/* Related alerts */}
            {selectedLog.relatedAlertIds.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                  Related Alerts
                </h3>
                <div className="space-y-1.5">
                  {selectedLog.relatedAlertIds.map((aid) => (
                    <button
                      key={aid}
                      onClick={() => { setSelectedLog(null); navigate(`/alerts/${aid}`); }}
                      className="w-full text-left px-3 py-2 rounded bg-bg-elevated border border-border-subtle hover:border-accent text-xs font-mono text-accent hover:underline transition-colors"
                    >
                      {aid} →
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Related incidents */}
            {selectedLog.relatedIncidentIds.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                  Related Incidents
                </h3>
                <div className="space-y-1.5">
                  {selectedLog.relatedIncidentIds.map((iid) => (
                    <button
                      key={iid}
                      onClick={() => { setSelectedLog(null); navigate(`/incidents/${iid}`); }}
                      className="w-full text-left px-3 py-2 rounded bg-bg-elevated border border-border-subtle hover:border-critical-border text-xs font-mono text-critical-text hover:underline transition-colors"
                    >
                      {iid} →
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}
