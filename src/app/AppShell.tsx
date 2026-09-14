import { useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar, type TimeRange } from './TopBar';

// Lazy-loaded page components
import { DashboardPage } from '../features/dashboard/DashboardPage';
import { AlertsPage } from '../features/alerts/AlertsPage';
import { AlertDetailPage } from '../features/alerts/AlertDetailPage';
import { IncidentsPage } from '../features/incidents/IncidentsPage';
import { IncidentDetailPage } from '../features/incidents/IncidentDetailPage';
import { ThreatHuntingPage } from '../features/threat-hunting/ThreatHuntingPage';
import { CopilotPage } from '../features/copilot/CopilotPage';
import { LogsPage } from '../features/logs/LogsPage';
import { AnalyticsPage } from '../features/analytics/AnalyticsPage';
import { SettingsPage } from '../features/settings/SettingsPage';
import { UserManagementPage } from '../features/admin/UserManagementPage';
import { AuditLogPage } from '../features/admin/AuditLogPage';
import { LoginPage } from '../features/auth/LoginPage';
import { ErrorBoundary } from '../components/ui';
import { useAuth } from '../contexts/AuthContext';

export function AppShell() {
  const [timeRange, setTimeRange] = useState<TimeRange>('Last 24 hours');
  const { isAuthenticated, isLoading, hasPermission } = useAuth();

  if (isLoading) {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center bg-[#080B11] text-slate-300">
        <div className="w-10 h-10 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mb-4" />
        <p className="text-xs font-mono text-cyan-400">Verifying security session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <div className="flex h-screen min-h-screen bg-bg-app">
      <Sidebar />
      <div className="flex-1 flex flex-col min-h-0 pl-sidebar">
        <TopBar timeRange={timeRange} onTimeRangeChange={setTimeRange} />
        <main className="flex-1 overflow-y-auto pt-topbar">
          <div className="min-h-full p-5">
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<DashboardPage timeRange={timeRange} />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
                <Route path="/threat-hunting" element={<ThreatHuntingPage />} />
                <Route path="/copilot" element={<CopilotPage />} />
                <Route path="/logs" element={<LogsPage />} />
                <Route path="/analytics" element={<AnalyticsPage timeRange={timeRange} />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route
                  path="/admin/users"
                  element={hasPermission('users.view') ? <UserManagementPage /> : <Navigate to="/" replace />}
                />
                <Route
                  path="/admin/audit"
                  element={hasPermission('audit.view') ? <AuditLogPage /> : <Navigate to="/" replace />}
                />
              </Routes>
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
}
