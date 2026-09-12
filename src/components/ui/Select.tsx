import { cn } from '../../lib/utils';

interface SelectOption {
  value: string;
  label: string;
}

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  options: SelectOption[];
  placeholder?: string;
  wrapperClassName?: string;
}

export function Select({ options, placeholder, wrapperClassName, className, ...props }: SelectProps) {
  return (
    <div className={cn('relative', wrapperClassName)}>
      <select
        className={cn(
          'w-full appearance-none bg-bg-elevated border border-border-default rounded text-sm text-text-primary',
          'focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/40 transition-colors duration-150',
          'pl-3 pr-8 py-2 cursor-pointer',
          className,
        )}
        {...props}
      >
        {placeholder && (
          <option value="" className="bg-bg-elevated">
            {placeholder}
          </option>
        )}
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-bg-elevated">
            {opt.label}
          </option>
        ))}
      </select>
      {/* Chevron icon */}
      <span className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-text-muted">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </span>
    </div>
  );
}
