// ============================================================
// Core Domain Types for SIEM Copilot
// ============================================================

// ---- Enumerations ----

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
export type EventType =
  | 'LOGIN'
  | 'LOGIN_FAILED'
  | 'LOGOUT'
  | 'FILE_ACCESS'
  | 'FILE_DELETE'
  | 'FILE_CREATE'
  | 'PROCESS_STARTED'
  | 'NETWORK_CONNECTION'
  | 'CONNECTION_BLOCKED'
  | 'PRIVILEGE_CHANGE'
  | 'USER_CREATED'
  | 'PASSWORD_CHANGED'
  | 'PORT_SCAN'
  | 'DATA_EXFILTRATION';

export type LogStatus = 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'TIMEOUT' | 'UNKNOWN';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// ---- Risk Scoring ----

export interface RiskScore {
  score: number;       // 0–100
  level: RiskLevel;
  factors: string[];   // contributing factors
}

export function calculateRiskLevel(score: number): RiskLevel {
  if (score <= 25) return 'LOW';
  if (score <= 50) return 'MEDIUM';
  if (score <= 75) return 'HIGH';
  return 'CRITICAL';
}

// ---- Security Log ----

export interface SecurityLog {
  id: string;
  timestamp: string;       // ISO 8601
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  username: string;
  eventType: EventType;
  status: LogStatus;
  device: string;
  rawLog: string;
  parsedFields: Record<string, string>;
  relatedAlertIds: string[];
  relatedIncidentIds: string[];
}

// ---- Detection Rule ----

export interface DetectionRule {
  id: string;
  name: string;
  category: string;
  condition: string;        // human-readable description of the rule
  conditionRaw?: string;    // pseudocode / query expression
  severity: Severity;
  enabled: boolean;
  triggerCount: number;     // how many times it fired in mock data
  description: string;
}

// ---- Security Alert ----

export interface SecurityAlert {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  riskScore: RiskScore;
  detectionRuleId: string;
  detectionRuleName: string;
  detectionCondition: string;  // plain-language description of what triggered
  sourceIp: string;
  destinationIp?: string;
  username: string;
  device: string;
  firstSeen: string;           // ISO 8601
  lastSeen: string;            // ISO 8601
  matchCount: number;          // number of matching log events
  matchingSummary: string;     // e.g. "25 failed attempts within 55 seconds"
  matchingLogIds: string[];
  relatedIncidentId?: string;
  tags: string[];
}

// ---- Incident Timeline Event ----

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  eventType: EventType | 'ALERT' | 'INCIDENT_CREATED' | 'STATUS_CHANGE' | 'ANALYST_NOTE';
  severity: Severity;
  relatedLogIds: string[];
  relatedAlertIds: string[];
  metadata?: Record<string, string>;
}

// ---- Incident ----

export interface Incident {
  id: string;                  // e.g. "INC-00142"
  title: string;
  severity: Severity;
  status: IncidentStatus;
  riskScore: RiskScore;
  sourceIp: string;
  destinationIp?: string;
  targetUser: string;
  affectedDevice: string;
  firstSeen: string;
  lastSeen: string;
  summary: string;
  attackVector: string;        // brief description
  timeline: TimelineEvent[];
  relatedAlertIds: string[];
  relatedLogIds: string[];
  // Three-block assessment
  observedEvidence: string[];
  aiAssessment: string;
  recommendedNextSteps: string[];
  tags: string[];
}

// ---- Copilot ----

export interface CopilotMessage {
  id: string;
  role: 'analyst' | 'copilot';
  content: string;
  timestamp: string;
  incidentId?: string;
  // Structured fields for Copilot responses (populated when role === 'copilot')
  response?: CopilotResponse;
}

export interface CopilotResponse {
  leadIn: string;              // e.g. "Analysis based on 47 related security events"
  eventCount?: number;
  observedEvidence: string[];
  aiAssessment: string;
  recommendedNextSteps: string[];
}

export type ThreatHuntStatus = 'idle' | 'running' | 'done' | 'error';

export interface ThreatHuntQuery {
  id: string;
  queryText: string;
  timestamp: string;
  status: ThreatHuntStatus;
  interpretation?: string;     // plain-language restatement of what was searched
  matchingLogIds?: string[];
  relatedAlertIds?: string[];
  riskIndicators?: string[];
}

// ---- Dashboard Stats ----

export interface DashboardStats {
  totalEvents: number;
  totalEventsChange: number;   // delta vs previous period
  activeAlerts: number;
  activeAlertsChange: number;
  highRiskEvents: number;
  highRiskChange: number;
  criticalIncidents: number;
  criticalIncidentsChange: number;
  systemHealth: SystemHealth;
}

export interface SystemHealthComponent {
  name: string;
  status: 'operational' | 'degraded' | 'offline';
  latencyMs?: number;
  detail?: string;
}

export interface SystemHealth {
  overall: 'operational' | 'degraded' | 'offline';
  components: SystemHealthComponent[];
}

// ---- Analytics ----

export interface TimeSeriesPoint {
  timestamp: string;   // ISO date string (date part only for daily)
  value: number;
  label?: string;
}

export interface SeverityDistribution {
  severity: Severity;
  count: number;
}

export interface TopSourceIp {
  ip: string;
  count: number;
  severity: Severity;
}

export interface TopTargetUser {
  username: string;
  count: number;
  severity: Severity;
}

export interface DetectionTypeStat {
  ruleName: string;
  count: number;
}

export interface LoginStats {
  timestamp: string;
  failed: number;
  successful: number;
}

export interface AnalyticsData {
  eventsOverTime: TimeSeriesPoint[];
  alertsOverTime: TimeSeriesPoint[];
  severityDistribution: SeverityDistribution[];
  topSourceIps: TopSourceIp[];
  topTargetUsers: TopTargetUser[];
  topDetectionTypes: DetectionTypeStat[];
  loginStats: LoginStats[];
  incidentTrends: TimeSeriesPoint[];
}

// ---- Pagination / List responses ----

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

// ---- Filters ----

export interface AlertFilter {
  search?: string;
  severity?: Severity;
  status?: AlertStatus;
  sourceIp?: string;
  username?: string;
  detectionType?: string;
  startDate?: string;
  endDate?: string;
}

export interface LogFilter {
  search?: string;
  sourceIp?: string;
  destinationIp?: string;
  username?: string;
  eventType?: EventType;
  status?: LogStatus;
  device?: string;
  startDate?: string;
  endDate?: string;
}
