import { cn } from '../../lib/utils';

interface RawLogLineProps {
  log: string;
  className?: string;
}

export function RawLogLine({ log, className }: RawLogLineProps) {
  return (
    <pre
      className={cn(
        'font-mono text-xs text-text-secondary bg-bg-app border border-border-subtle rounded px-3 py-2 leading-relaxed overflow-x-auto',
        className,
      )}
    >
      {log}
    </pre>
  );
}
