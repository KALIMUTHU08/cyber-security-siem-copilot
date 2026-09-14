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
  Users,
  ClipboardList,
  LogOut,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useAuth } from '../contexts/AuthContext';

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
  const { user, logout, hasPermission } = useAuth();

  const getInitials = (name?: string) => {
    if (!name) return 'U';
    const parts = name.split(' ');
    if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    return name.slice(0, 2).toUpperCase();
  };

  const getRoleBadgeStyle = (role?: string) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
      case 'SECURITY_ANALYST':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'SOC_OPERATOR':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'VIEWER':
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

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
        <div className="mb-2">
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
                  {to === '/copilot' && (
                    <span className="ml-auto w-1.5 h-1.5 rounded-full bg-ai" />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </div>

        {/* Administration navigation */}
        {(hasPermission('users.view') || hasPermission('audit.view')) && (
          <div className="mt-3 pt-2 border-t border-border-subtle">
            <div className="px-2 py-1 text-2xs font-medium text-text-disabled uppercase tracking-widest">Administration</div>
            {hasPermission('users.view') && (
              <NavLink
                to="/admin/users"
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
                    <Users
                      size={15}
                      className={cn(
                        'flex-shrink-0 transition-colors',
                        isActive ? 'text-accent' : 'text-text-muted',
                      )}
                    />
                    Users
                  </>
                )}
              </NavLink>
            )}

            {hasPermission('audit.view') && (
              <NavLink
                to="/admin/audit"
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
                    <ClipboardList
                      size={15}
                      className={cn(
                        'flex-shrink-0 transition-colors',
                        isActive ? 'text-accent' : 'text-text-muted',
                      )}
                    />
                    Audit Logs
                  </>
                )}
              </NavLink>
            )}
          </div>
        )}
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

        {/* System status + User profile + Logout */}
        <div className="px-3 py-3 border-t border-border-subtle space-y-2.5">
          <div className="flex items-center gap-2">
            <Activity size={12} className="text-low-DEFAULT flex-shrink-0" />
            <span className="text-xs text-text-secondary">System Operational</span>
            <span className="ml-auto w-2 h-2 rounded-full bg-low-DEFAULT animate-pulse-slow" />
          </div>

          <div className="flex items-center justify-between gap-2 pt-1">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-7 h-7 rounded-full bg-accent/20 border border-accent/40 flex items-center justify-center flex-shrink-0">
                <span className="text-xs font-bold text-accent">{getInitials(user?.fullName)}</span>
              </div>
              <div className="min-w-0">
                <div className="text-xs font-medium text-text-primary truncate">{user?.fullName || 'SOC User'}</div>
                <div className="flex items-center gap-1 mt-0.5">
                  <span
                    className={cn(
                      'text-[9px] font-mono px-1.5 py-0.2 rounded border uppercase leading-tight',
                      getRoleBadgeStyle(user?.role)
                    )}
                  >
                    {user?.role || 'VIEWER'}
                  </span>
                </div>
              </div>
            </div>

            <button
              onClick={() => logout()}
              title="Sign out"
              className="p-1.5 rounded-lg text-text-muted hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
            >
              <LogOut size={14} />
            </button>
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
