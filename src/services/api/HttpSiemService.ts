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
} from '../../types';

export class HttpSiemService implements SiemService {
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:8000') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}/api${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
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
}
