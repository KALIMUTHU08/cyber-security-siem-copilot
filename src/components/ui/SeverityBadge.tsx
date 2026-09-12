import type { Severity } from '../../types';
import { cn, severityClasses } from '../../lib/utils';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
  className?: string;
}

export function SeverityBadge({ severity, size = 'md', className }: SeverityBadgeProps) {
  const classes = severityClasses(severity);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-medium rounded',
        size === 'sm' ? 'px-1.5 py-0.5 text-2xs' : 'px-2 py-0.5 text-xs',
        classes.badge,
        className,
      )}
    >
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', classes.dot)} />
      {severity}
    </span>
  );
}
