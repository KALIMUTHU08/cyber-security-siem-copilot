import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  FileWarning,
  Search,
  Bot,
  ScrollText,
  BarChart3,
  Settings,
  Activity,
  Shield,
} from 'lucide-react';
import { cn } from '../lib/utils';

const mainNav = [
  { to: '/', icon: LayoutDashboard, label: 'Overview', end: true },
  { to: '/alerts', icon: ShieldAlert, label: 'Alerts' },
  { to: '/incidents', icon: FileWarning, label: 'Incidents' },
  { to: '/threat-hunting', icon: Search, label: 'Threat Hunting' },
  { to: '/copilot', icon: Bot, label: 'Copilot' },
  { to: '/logs', icon: ScrollText, label: 'Log Explorer' },
  { to: '/analytics', icon: BarChart3, label: 'Analytics' },
];

export function Sidebar() {
  const location = useLocation();

  return (
    <aside className="fixed left-0 top-0 h-full w-sidebar bg-bg-panel border-r border-border-default flex flex-col z-30">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-border-default flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-accent flex items-center justify-center flex-shrink-0">
            <Shield size={14} className="text-white" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-bold text-text-primary tracking-tight leading-tight">SIEM COPILOT</div>
            <div className="text-2xs text-text-muted leading-tight">Threat Hunting & Investigation</div>
          </div>
        </div>
      </div>

      {/* Main navigation */}
      <nav className="flex-1 overflow-y-auto py-2 px-2">
        <div className="mb-1">
          <div className="px-2 py-1.5 text-2xs font-medium text-text-disabled uppercase tracking-widest">Navigation</div>
          {mainNav.map(({ to, icon: Icon, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 px-2.5 py-2 rounded text-sm transition-colors duration-100 mb-0.5',
                  isActive
                    ? 'bg-accent-subtle text-accent font-medium'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-elevated',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    size={15}
                    className={cn(
                      'flex-shrink-0 transition-colors',
                      isActive ? 'text-accent' : 'text-text-muted',
                    )}
                  />
                  {label}
                  {/* Active indicator dot for copilot */}
                  {to === '/copilot' && (
                    <span className="ml-auto w-1.5 h-1.5 rounded-full bg-ai" />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Bottom section */}
      <div className="flex-shrink-0 border-t border-border-default">
        {/* Settings */}
        <div className="px-2 py-2">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2.5 px-2.5 py-2 rounded text-sm transition-colors duration-100',
                isActive
                  ? 'bg-accent-subtle text-accent font-medium'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-elevated',
              )
            }
          >
            {({ isActive }) => (
              <>
                <Settings
                  size={15}
                  className={cn('flex-shrink-0', isActive ? 'text-accent' : 'text-text-muted')}
                />
                Settings
              </>
            )}
          </NavLink>
        </div>

        {/* System status + profile */}
        <div className="px-3 py-3 border-t border-border-subtle space-y-2.5">
          <div className="flex items-center gap-2">
            <Activity size={12} className="text-low-DEFAULT flex-shrink-0" />
            <span className="text-xs text-text-secondary">System Operational</span>
            <span className="ml-auto w-2 h-2 rounded-full bg-low-DEFAULT animate-pulse-slow" />
          </div>
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-accent-muted flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-accent">SA</span>
            </div>
            <div className="min-w-0">
              <div className="text-xs font-medium text-text-primary truncate">SOC Analyst</div>
              <div className="text-2xs text-text-muted truncate">Tier 2 — Security Ops</div>
            </div>
          </div>
        </div>
      </div>

      {/* Active route highlight bar */}
      {location.pathname && (
        <div
          className="absolute right-0 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-accent/30 to-transparent pointer-events-none"
          aria-hidden="true"
        />
      )}
    </aside>
  );
}
