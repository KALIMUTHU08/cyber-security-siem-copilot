import { cn } from '../../lib/utils';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  wrapperClassName?: string;
}

export function Input({ leftIcon, rightIcon, wrapperClassName, className, ...props }: InputProps) {
  return (
    <div className={cn('relative flex items-center', wrapperClassName)}>
      {leftIcon && (
        <span className="absolute left-2.5 text-text-muted pointer-events-none">{leftIcon}</span>
      )}
      <input
        className={cn(
          'w-full bg-bg-elevated border border-border-default rounded text-sm text-text-primary placeholder:text-text-muted',
          'focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/40 transition-colors duration-150',
          leftIcon ? 'pl-8' : 'pl-3',
          rightIcon ? 'pr-8' : 'pr-3',
          'py-2',
          className,
        )}
        {...props}
      />
      {rightIcon && (
        <span className="absolute right-2.5 text-text-muted pointer-events-none">{rightIcon}</span>
      )}
    </div>
  );
}
