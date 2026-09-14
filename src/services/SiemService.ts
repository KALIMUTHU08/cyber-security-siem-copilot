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
  ResponseAction,
  ResponseActionType,
  AuthUser,
  TokenResponse,
  UserCreateData,
  UserUpdateData,
  AuditLogEntry,
  BlocklistEntry,
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

  // Auth & Profile
  login(email: string, password: string): Promise<TokenResponse>;
  getMe(): Promise<TokenResponse>;
  logout(): Promise<void>;

  // Response Actions
  getResponseActions(incidentId: string): Promise<ResponseAction[]>;
  createResponseAction(
    incidentId: string,
    action: {
      actionType: ResponseActionType;
      parameters: Record<string, any>;
      notes?: string;
      copilotReasoning?: string;
    }
  ): Promise<ResponseAction>;
  approveResponseAction(incidentId: string, actionId: string, notes?: string): Promise<ResponseAction>;
  rejectResponseAction(incidentId: string, actionId: string, notes?: string): Promise<ResponseAction>;
  executeResponseAction(incidentId: string, actionId: string): Promise<ResponseAction>;

  // Admin: User Management
  getUsers(): Promise<AuthUser[]>;
  createUser(data: UserCreateData): Promise<AuthUser>;
  updateUser(id: string, data: UserUpdateData): Promise<AuthUser>;

  // Admin: Audit Logs
  getAuditLogs(params?: {
    action?: string;
    userId?: string;
    result?: string;
    page?: number;
    pageSize?: number;
  }): Promise<AuditLogEntry[]>;

  // Blocklist
  getBlocklist(): Promise<BlocklistEntry[]>;
}
