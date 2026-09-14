// ============================================================
// HttpSiemService — real HTTP client implementing SiemService.
// Connects to the FastAPI backend at baseUrl (default: http://localhost:8000).
// ============================================================

import type { SiemService } from '../SiemService';
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
} from '../../types';

export class HttpSiemService implements SiemService {
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:8000') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}/api${path}`;
    const token = typeof window !== 'undefined' ? localStorage.getItem('siem_auth_token') : null;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options?.headers as Record<string, string> | undefined),
    };

    const res = await fetch(url, { ...options, headers });
    if (!res.ok) {
      if (res.status === 404) {
        return null as unknown as T;
      }
      let errDetail = `HTTP ${res.status} ${res.statusText}`;
      try {
        const json = await res.json();
        if (json.detail) errDetail = typeof json.detail === 'string' ? json.detail : JSON.stringify(json.detail);
      } catch {
        // ignore json decode error
      }
      throw new Error(errDetail);
    }
    return res.json();
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    return this.request<DashboardStats>('/dashboard');
  }

  // Logs
  async getLogs(filter?: LogFilter, page: number = 1, pageSize: number = 25): Promise<PaginatedResult<SecurityLog>> {
    const params = new URLSearchParams();
    params.set('page', String(page));
    params.set('pageSize', String(pageSize));

    if (filter) {
      if (filter.search) params.set('search', filter.search);
      if (filter.sourceIp) params.set('sourceIp', filter.sourceIp);
      if (filter.destinationIp) params.set('destinationIp', filter.destinationIp);
      if (filter.username) params.set('username', filter.username);
      if (filter.eventType) params.set('eventType', filter.eventType);
      if (filter.status) params.set('status', filter.status);
      if (filter.device) params.set('device', filter.device);
    }

    return this.request<PaginatedResult<SecurityLog>>(`/logs?${params.toString()}`);
  }

  async getLogById(id: string): Promise<SecurityLog | null> {
    return this.request<SecurityLog | null>(`/logs/${encodeURIComponent(id)}`);
  }

  async getLogsByIds(ids: string[]): Promise<SecurityLog[]> {
    if (!ids || ids.length === 0) return [];
    return this.request<SecurityLog[]>('/logs/batch', {
      method: 'POST',
      body: JSON.stringify({ ids }),
    });
  }

  // Alerts
  async getAlerts(filter?: AlertFilter, page: number = 1, pageSize: number = 25): Promise<PaginatedResult<SecurityAlert>> {
    const params = new URLSearchParams();
    params.set('page', String(page));
    params.set('pageSize', String(pageSize));

    if (filter) {
      if (filter.search) params.set('search', filter.search);
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.status) params.set('status', filter.status);
      if (filter.sourceIp) params.set('sourceIp', filter.sourceIp);
      if (filter.username) params.set('username', filter.username);
      if (filter.detectionType) params.set('detectionType', filter.detectionType);
    }

    return this.request<PaginatedResult<SecurityAlert>>(`/alerts?${params.toString()}`);
  }

  async getAlertById(id: string): Promise<SecurityAlert | null> {
    return this.request<SecurityAlert | null>(`/alerts/${encodeURIComponent(id)}`);
  }

  async getAlertsByIds(ids: string[]): Promise<SecurityAlert[]> {
    if (!ids || ids.length === 0) return [];
    return this.request<SecurityAlert[]>('/alerts/batch', {
      method: 'POST',
      body: JSON.stringify({ ids }),
    });
  }

  // Incidents
  async getIncidents(page: number = 1, pageSize: number = 20): Promise<PaginatedResult<Incident>> {
    const params = new URLSearchParams({
      page: String(page),
      pageSize: String(pageSize),
    });
    return this.request<PaginatedResult<Incident>>(`/incidents?${params.toString()}`);
  }

  async getIncidentById(id: string): Promise<Incident | null> {
    return this.request<Incident | null>(`/incidents/${encodeURIComponent(id)}`);
  }

  // Detection Rules
  async getDetectionRules(): Promise<DetectionRule[]> {
    return this.request<DetectionRule[]>('/settings/detection-rules');
  }

  async toggleDetectionRule(id: string, enabled: boolean): Promise<DetectionRule> {
    return this.request<DetectionRule>(`/settings/detection-rules/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
  }

  // Threat Hunting
  async runThreatHunt(queryText: string): Promise<ThreatHuntQuery> {
    return this.request<ThreatHuntQuery>('/threat-hunting/query', {
      method: 'POST',
      body: JSON.stringify({ queryText }),
    });
  }

  // Copilot
  async sendCopilotMessage(message: string, incidentId?: string): Promise<CopilotMessage> {
    return this.request<CopilotMessage>('/copilot/chat', {
      method: 'POST',
      body: JSON.stringify({ message, incidentId }),
    });
  }

  async getCopilotHistory(incidentId?: string): Promise<CopilotMessage[]> {
    const params = incidentId ? `?incidentId=${encodeURIComponent(incidentId)}` : '';
    return this.request<CopilotMessage[]>(`/copilot/history${params}`);
  }

  // Analytics
  async getAnalytics(days: number): Promise<AnalyticsData> {
    return this.request<AnalyticsData>(`/analytics?days=${days}`);
  }

  // Auth & Profile
  async login(email: string, password: string): Promise<TokenResponse> {
    return this.request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async getMe(): Promise<TokenResponse> {
    return this.request<TokenResponse>('/auth/me');
  }

  async logout(): Promise<void> {
    try {
      await this.request<void>('/auth/logout', { method: 'POST' });
    } catch {
      // ignore
    }
  }

  // Response Actions
  async getResponseActions(incidentId: string): Promise<ResponseAction[]> {
    const res = await this.request<ResponseAction[]>(`/incidents/${encodeURIComponent(incidentId)}/response-actions`);
    return res || [];
  }

  async createResponseAction(
    incidentId: string,
    action: {
      actionType: ResponseActionType;
      parameters: Record<string, any>;
      notes?: string;
      copilotReasoning?: string;
    }
  ): Promise<ResponseAction> {
    return this.request<ResponseAction>(`/incidents/${encodeURIComponent(incidentId)}/response-actions`, {
      method: 'POST',
      body: JSON.stringify(action),
    });
  }

  async approveResponseAction(incidentId: string, actionId: string, notes?: string): Promise<ResponseAction> {
    return this.request<ResponseAction>(
      `/incidents/${encodeURIComponent(incidentId)}/response-actions/${encodeURIComponent(actionId)}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({ notes: notes || '' }),
      }
    );
  }

  async rejectResponseAction(incidentId: string, actionId: string, notes?: string): Promise<ResponseAction> {
    return this.request<ResponseAction>(
      `/incidents/${encodeURIComponent(incidentId)}/response-actions/${encodeURIComponent(actionId)}/reject`,
      {
        method: 'POST',
        body: JSON.stringify({ notes: notes || '' }),
      }
    );
  }

  async executeResponseAction(incidentId: string, actionId: string): Promise<ResponseAction> {
    return this.request<ResponseAction>(
      `/incidents/${encodeURIComponent(incidentId)}/response-actions/${encodeURIComponent(actionId)}/execute`,
      {
        method: 'POST',
      }
    );
  }

  // Admin: User Management
  async getUsers(): Promise<AuthUser[]> {
    const res = await this.request<AuthUser[]>('/auth/users');
    return res || [];
  }

  async createUser(data: UserCreateData): Promise<AuthUser> {
    return this.request<AuthUser>('/auth/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateUser(id: string, data: UserUpdateData): Promise<AuthUser> {
    return this.request<AuthUser>(`/auth/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  // Admin: Audit Logs
  async getAuditLogs(params?: {
    action?: string;
    userId?: string;
    result?: string;
    page?: number;
    pageSize?: number;
  }): Promise<AuditLogEntry[]> {
    const q = new URLSearchParams();
    if (params?.action) q.set('action', params.action);
    if (params?.userId) q.set('userId', params.userId);
    if (params?.result) q.set('result', params.result);
    if (params?.page) q.set('page', String(params.page));
    if (params?.pageSize) q.set('pageSize', String(params.pageSize));
    const qs = q.toString() ? `?${q.toString()}` : '';
    const res = await this.request<AuditLogEntry[]>(`/audit-logs${qs}`);
    return res || [];
  }

  // Blocklist
  async getBlocklist(): Promise<BlocklistEntry[]> {
    const res = await this.request<BlocklistEntry[]>('/blocklist');
    return res || [];
  }
}
