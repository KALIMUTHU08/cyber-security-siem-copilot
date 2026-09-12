// ============================================================
// SiemService — the single service contract the UI depends on.
//
// This interface is the SWAP POINT.
// Currently wired to: src/services/mock/MockSiemService.ts
// Future backend: replace with src/services/api/HttpSiemService.ts
//   that calls the FastAPI endpoints, implementing this same interface.
// No UI component imports from services/mock directly.
// ============================================================

import type {
  SecurityLog,
  SecurityAlert,
  Incident,
  DetectionRule,
  CopilotMessage,
  ThreatHuntQuery,
  DashboardStats,
  AnalyticsData,
  AlertFilter,
  LogFilter,
  PaginatedResult,
} from '../types';

export interface SiemService {
  // Dashboard
  getDashboardStats(): Promise<DashboardStats>;

  // Logs
  getLogs(filter?: LogFilter, page?: number, pageSize?: number): Promise<PaginatedResult<SecurityLog>>;
  getLogById(id: string): Promise<SecurityLog | null>;
  getLogsByIds(ids: string[]): Promise<SecurityLog[]>;

  // Alerts
  getAlerts(filter?: AlertFilter, page?: number, pageSize?: number): Promise<PaginatedResult<SecurityAlert>>;
  getAlertById(id: string): Promise<SecurityAlert | null>;
  getAlertsByIds(ids: string[]): Promise<SecurityAlert[]>;

  // Incidents
  getIncidents(page?: number, pageSize?: number): Promise<PaginatedResult<Incident>>;
  getIncidentById(id: string): Promise<Incident | null>;

  // Detection Rules
  getDetectionRules(): Promise<DetectionRule[]>;
  toggleDetectionRule(id: string, enabled: boolean): Promise<DetectionRule>;

  // Threat Hunting
  runThreatHunt(queryText: string): Promise<ThreatHuntQuery>;

  // Copilot
  sendCopilotMessage(message: string, incidentId?: string): Promise<CopilotMessage>;
  getCopilotHistory(incidentId?: string): Promise<CopilotMessage[]>;

  // Analytics
  getAnalytics(days: number): Promise<AnalyticsData>;
}
