import { Database } from 'lucide-react';
import { cn } from '../../lib/utils';

interface EmptyStateProps {
  message?: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({
  message = 'No data found',
  description,
  icon,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 py-16 text-center', className)}>
      <div className="text-text-disabled">
        {icon ?? <Database size={32} strokeWidth={1.5} />}
      </div>
      <div>
        <p className="text-sm font-medium text-text-secondary">{message}</p>
        {description && <p className="text-xs text-text-muted mt-1 max-w-sm">{description}</p>}
      </div>
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
