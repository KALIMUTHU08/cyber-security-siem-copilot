import { Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

interface LoadingStateProps {
  message?: string;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export function LoadingState({ message = 'Loading…', className, size = 'md' }: LoadingStateProps) {
  const iconSize = size === 'sm' ? 16 : size === 'lg' ? 32 : 20;
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 py-12 text-text-muted', className)}>
      <Loader2 size={iconSize} className="animate-spin text-accent" />
      <span className={cn('text-text-secondary', size === 'sm' ? 'text-xs' : 'text-sm')}>{message}</span>
    </div>
  );
}
