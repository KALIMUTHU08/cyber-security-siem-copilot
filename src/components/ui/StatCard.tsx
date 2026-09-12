import { cn } from '../../lib/utils';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  icon?: React.ReactNode;
  accentColor?: string;
  className?: string;
  onClick?: () => void;
}

export function StatCard({
  label,
  value,
  change,
  changeLabel,
  icon,
  accentColor,
  className,
  onClick,
}: StatCardProps) {
  const hasChange = change !== undefined && change !== null;
  const isPositive = (change ?? 0) > 0;
  const isNeutral = (change ?? 0) === 0;

  return (
    <div
      className={cn(
        'bg-bg-panel border border-border-default rounded-md p-4 flex flex-col gap-3',
        onClick && 'cursor-pointer hover:border-border-strong hover:bg-bg-elevated transition-colors duration-150',
        className,
      )}
      onClick={onClick}
      style={accentColor ? { borderTopColor: accentColor, borderTopWidth: 2 } : undefined}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium text-text-secondary uppercase tracking-wide">{label}</span>
        {icon && (
          <span className="text-text-muted" style={accentColor ? { color: accentColor } : undefined}>
            {icon}
          </span>
        )}
      </div>
      <div className="flex items-end justify-between">
        <span className="text-2xl font-bold font-mono tabular-nums text-text-primary">{value}</span>
        {hasChange && (
          <span
            className={cn(
              'inline-flex items-center gap-1 text-xs font-medium',
              isNeutral ? 'text-text-muted' : isPositive ? 'text-high-text' : 'text-low-text',
            )}
          >
            {isNeutral ? (
              <Minus size={12} />
            ) : isPositive ? (
              <TrendingUp size={12} />
            ) : (
              <TrendingDown size={12} />
            )}
            {isPositive ? '+' : ''}{change} {changeLabel ?? 'vs prior period'}
          </span>
        )}
      </div>
    </div>
  );
}
