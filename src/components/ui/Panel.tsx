import { cn } from '../../lib/utils';

interface PanelProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

interface PanelHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  className?: string;
}

export function Panel({ children, className, onClick }: PanelProps) {
  return (
    <div className={cn('bg-bg-panel border border-border-default rounded-md', className)} onClick={onClick}>
      {children}
    </div>
  );
}

export function PanelHeader({ title, subtitle, actions, className }: PanelHeaderProps) {
  return (
    <div className={cn('flex items-center justify-between px-4 py-3 border-b border-border-default', className)}>
      <div>
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        {subtitle && <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
