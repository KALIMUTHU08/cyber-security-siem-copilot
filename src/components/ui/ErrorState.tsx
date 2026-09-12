import { AlertTriangle } from 'lucide-react';
import { cn } from '../../lib/utils';

interface ErrorStateProps {
  message?: string;
  detail?: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  message = 'Failed to load data',
  detail,
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 py-16 text-center', className)}>
      <div className="text-critical-DEFAULT">
        <AlertTriangle size={32} strokeWidth={1.5} />
      </div>
      <div>
        <p className="text-sm font-medium text-text-secondary">{message}</p>
        {detail && <p className="text-xs text-text-muted mt-1 font-mono max-w-sm">{detail}</p>}
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 text-xs text-accent hover:text-accent-hover underline underline-offset-2"
        >
          Try again
        </button>
      )}
    </div>
  );
}
