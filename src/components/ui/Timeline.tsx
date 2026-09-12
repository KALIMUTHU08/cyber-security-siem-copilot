import { cn, severityClasses, formatTime } from '../../lib/utils';
import type { TimelineEvent } from '../../types';

interface TimelineProps {
  events: TimelineEvent[];
  onEventClick?: (event: TimelineEvent) => void;
  className?: string;
}

const eventTypeIcon: Record<string, string> = {
  LOGIN_FAILED: '✕',
  LOGIN: '✓',
  PRIVILEGE_CHANGE: '↑',
  PROCESS_STARTED: '⚙',
  NETWORK_CONNECTION: '→',
  CONNECTION_BLOCKED: '⊘',
  ALERT: '⚠',
  INCIDENT_CREATED: '◆',
  STATUS_CHANGE: '◎',
  ANALYST_NOTE: '✎',
  FILE_ACCESS: '📄',
  FILE_DELETE: '✗',
  FILE_CREATE: '✚',
  PORT_SCAN: '⊡',
  DATA_EXFILTRATION: '⇪',
};

export function Timeline({ events, onEventClick, className }: TimelineProps) {
  return (
    <ol className={cn('relative', className)}>
      {events.map((event, idx) => {
        const classes = severityClasses(event.severity);
        const isLast = idx === events.length - 1;
        return (
          <li key={event.id} className="relative flex gap-4 pb-5">
            {/* Connector line */}
            {!isLast && (
              <div className="absolute left-[7px] top-4 bottom-0 w-px bg-border-default" />
            )}
            {/* Dot */}
            <div className="flex-shrink-0 mt-0.5">
              <div
                className={cn(
                  'w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center',
                  classes.border,
                  classes.bg,
                )}
              />
            </div>
            {/* Content */}
            <div
              className={cn(
                'flex-1 bg-bg-elevated border border-border-subtle rounded-md p-3 min-w-0',
                onEventClick && 'cursor-pointer hover:border-border-default transition-colors',
              )}
              onClick={onEventClick ? () => onEventClick(event) : undefined}
            >
              <div className="flex items-start justify-between gap-2 mb-1">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={cn('text-xs font-mono font-medium', classes.text)}>
                    {eventTypeIcon[event.eventType] ?? '•'}
                  </span>
                  <span className="text-sm font-medium text-text-primary truncate">{event.title}</span>
                </div>
                <span className="text-xs font-mono text-text-muted flex-shrink-0 mt-0.5">
                  {formatTime(event.timestamp)}
                </span>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">{event.description}</p>
              {event.metadata && Object.keys(event.metadata).length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(event.metadata).map(([k, v]) => (
                    <span key={k} className="text-2xs font-mono bg-bg-app px-1.5 py-0.5 rounded text-text-muted">
                      {k}: <span className="text-text-secondary">{v}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
