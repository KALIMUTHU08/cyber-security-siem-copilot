import { useState } from 'react';
import { ChevronUp, ChevronDown } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  className?: string;
  headerClassName?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  getRowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  className?: string;
  emptyMessage?: string;
  stickyHeader?: boolean;
}

type SortDir = 'asc' | 'desc' | null;

export function DataTable<T>({
  columns,
  rows,
  getRowKey,
  onRowClick,
  className,
  emptyMessage = 'No results found.',
  stickyHeader = false,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>(null);

  function handleSort(key: string) {
    if (sortKey === key) {
      if (sortDir === 'asc') setSortDir('desc');
      else if (sortDir === 'desc') { setSortKey(null); setSortDir(null); }
      else setSortDir('asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  }

  return (
    <div className={cn('overflow-x-auto', className)}>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-border-default">
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  'px-3 py-2.5 text-left text-xs font-medium text-text-muted uppercase tracking-wide whitespace-nowrap',
                  stickyHeader && 'sticky top-0 bg-bg-panel z-10',
                  col.sortable && 'cursor-pointer select-none hover:text-text-secondary transition-colors',
                  col.headerClassName,
                )}
                style={col.width ? { width: col.width } : undefined}
                onClick={col.sortable ? () => handleSort(col.key) : undefined}
              >
                <span className="inline-flex items-center gap-1">
                  {col.header}
                  {col.sortable && (
                    <span className="flex flex-col -space-y-0.5">
                      <ChevronUp
                        size={10}
                        className={cn(sortKey === col.key && sortDir === 'asc' ? 'text-accent' : 'text-text-disabled')}
                      />
                      <ChevronDown
                        size={10}
                        className={cn(sortKey === col.key && sortDir === 'desc' ? 'text-accent' : 'text-text-disabled')}
                      />
                    </span>
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3 py-8 text-center text-text-muted text-sm"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr
                key={getRowKey(row)}
                className={cn(
                  'border-b border-border-subtle',
                  onRowClick && 'cursor-pointer hover:bg-bg-elevated transition-colors duration-100',
                )}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={cn('px-3 py-2.5 text-text-primary', col.className)}
                  >
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
