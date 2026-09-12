import { useLocation } from 'react-router-dom';
import { Search, Bell, Clock } from 'lucide-react';
import { useState } from 'react';
import { cn } from '../lib/utils';

const routeTitles: Record<string, string> = {
  '/': 'Security Overview',
  '/alerts': 'Security Alerts',
  '/incidents': 'Incidents',
  '/threat-hunting': 'Threat Hunting',
  '/copilot': 'SIEM Copilot',
  '/logs': 'Log Explorer',
  '/analytics': 'Security Analytics',
  '/settings': 'Settings',
};

function getPageTitle(pathname: string): string {
  if (pathname.startsWith('/alerts/')) return 'Alert Details';
  if (pathname.startsWith('/incidents/')) return 'Incident Investigation';
  return routeTitles[pathname] ?? 'SIEM Copilot';
}

const TIME_RANGES = ['Last 24 hours', 'Last 7 days', 'Last 30 days'] as const;
type TimeRange = (typeof TIME_RANGES)[number];

interface TopBarProps {
  timeRange: TimeRange;
  onTimeRangeChange: (tr: TimeRange) => void;
}

export function TopBar({ timeRange, onTimeRangeChange }: TopBarProps) {
  const location = useLocation();
  const title = getPageTitle(location.pathname);
  const [searchValue, setSearchValue] = useState('');

  return (
    <header className="fixed top-0 left-sidebar right-0 h-topbar bg-bg-panel border-b border-border-default z-20 flex items-center px-5 gap-4">
      {/* Page title */}
      <div className="flex-shrink-0 min-w-0">
        <h2 className="text-sm font-semibold text-text-primary truncate">{title}</h2>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Global search */}
      <div className="relative w-56">
        <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
        <input
          type="search"
          placeholder="Search events, IPs, users…"
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          className="w-full pl-7 pr-3 py-1.5 text-xs bg-bg-elevated border border-border-default rounded text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-colors"
        />
      </div>

      {/* Time range selector */}
      <div className="flex items-center gap-1 bg-bg-elevated border border-border-default rounded p-0.5 flex-shrink-0">
        <Clock size={12} className="text-text-muted ml-1.5" />
        {TIME_RANGES.map((tr) => (
          <button
            key={tr}
            onClick={() => onTimeRangeChange(tr)}
            className={cn(
              'px-2.5 py-1 text-xs rounded transition-colors duration-100 font-medium',
              tr === timeRange
                ? 'bg-bg-panel text-text-primary border border-border-default'
                : 'text-text-muted hover:text-text-secondary',
            )}
          >
            {tr.replace('Last ', '')}
          </button>
        ))}
      </div>

      {/* Notification bell */}
      <button
        className="relative text-text-muted hover:text-text-primary transition-colors p-1.5 rounded hover:bg-bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        aria-label="Notifications (5 unread)"
      >
        <Bell size={16} />
        <span className="absolute top-1 right-1 w-2 h-2 bg-critical-DEFAULT rounded-full" />
      </button>

      {/* User avatar */}
      <button
        className="w-7 h-7 rounded-full bg-accent-muted flex items-center justify-center text-accent text-xs font-bold flex-shrink-0 hover:bg-accent hover:text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        aria-label="User profile"
      >
        SA
      </button>
    </header>
  );
}

export type { TimeRange };
