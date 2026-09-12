import type { AlertStatus, IncidentStatus } from '../../types';
import { cn, alertStatusConfig, incidentStatusConfig } from '../../lib/utils';

interface AlertStatusBadgeProps {
  status: AlertStatus;
  className?: string;
}

interface IncidentStatusBadgeProps {
  status: IncidentStatus;
  className?: string;
}

export function StatusBadge({ status, className }: AlertStatusBadgeProps | IncidentStatusBadgeProps) {
  const isAlert = ['NEW', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'].includes(status as string);
  const config = isAlert
    ? alertStatusConfig(status as AlertStatus)
    : incidentStatusConfig(status as IncidentStatus);

  return (
    <span
      className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', className)}
      style={{ color: config.color, backgroundColor: config.bg }}
    >
      {config.label}
    </span>
  );
}
