import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Severity, AlertStatus, IncidentStatus, RiskLevel } from '../types';

/** Merge Tailwind classes safely */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Format an ISO timestamp for display */
export function formatTimestamp(iso: string, opts?: { dateOnly?: boolean; relative?: boolean }): string {
  const date = new Date(iso);
  if (opts?.relative) {
    const diffMs = Date.now() - date.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
  }
  if (opts?.dateOnly) {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  }
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Format a short timestamp (time only) */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

/** Format date only */
export function formatDate(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

/** Get Tailwind classes for a severity level */
export function severityClasses(severity: Severity): {
  badge: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
} {
  switch (severity) {
    case 'CRITICAL':
      return {
        badge: 'bg-critical-bg border border-critical-border text-critical-text',
        text: 'text-critical-DEFAULT',
        bg: 'bg-critical-bg',
        border: 'border-critical-border',
        dot: 'bg-critical-DEFAULT',
      };
    case 'HIGH':
      return {
        badge: 'bg-high-bg border border-high-border text-high-text',
        text: 'text-high-DEFAULT',
        bg: 'bg-high-bg',
        border: 'border-high-border',
        dot: 'bg-high-DEFAULT',
      };
    case 'MEDIUM':
      return {
        badge: 'bg-medium-bg border border-medium-border text-medium-text',
        text: 'text-medium-DEFAULT',
        bg: 'bg-medium-bg',
        border: 'border-medium-border',
        dot: 'bg-medium-DEFAULT',
      };
    case 'LOW':
      return {
        badge: 'bg-low-bg border border-low-border text-low-text',
        text: 'text-low-DEFAULT',
        bg: 'bg-low-bg',
        border: 'border-low-border',
        dot: 'bg-low-DEFAULT',
      };
  }
}

/** Get the hex color value for a severity (for charts) */
export function severityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '#f85149';
    case 'HIGH': return '#e3872d';
    case 'MEDIUM': return '#d29922';
    case 'LOW': return '#3fb950';
  }
}

export function riskLevelColor(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL': return '#f85149';
    case 'HIGH': return '#e3872d';
    case 'MEDIUM': return '#d29922';
    case 'LOW': return '#3fb950';
  }
}

/** Alert status display config */
export function alertStatusConfig(status: AlertStatus): { label: string; color: string; bg: string } {
  switch (status) {
    case 'NEW': return { label: 'New', color: '#388bfd', bg: 'rgba(56,139,253,0.12)' };
    case 'INVESTIGATING': return { label: 'Investigating', color: '#d29922', bg: 'rgba(210,153,34,0.12)' };
    case 'RESOLVED': return { label: 'Resolved', color: '#3fb950', bg: 'rgba(63,185,80,0.12)' };
    case 'DISMISSED': return { label: 'Dismissed', color: '#6e7681', bg: 'rgba(110,118,129,0.12)' };
  }
}

/** Incident status display config */
export function incidentStatusConfig(status: IncidentStatus): { label: string; color: string; bg: string } {
  switch (status) {
    case 'OPEN': return { label: 'Open', color: '#f85149', bg: 'rgba(248,81,73,0.12)' };
    case 'INVESTIGATING': return { label: 'Investigating', color: '#d29922', bg: 'rgba(210,153,34,0.12)' };
    case 'CONTAINED': return { label: 'Contained', color: '#e3872d', bg: 'rgba(227,135,45,0.12)' };
    case 'CLOSED': return { label: 'Closed', color: '#6e7681', bg: 'rgba(110,118,129,0.12)' };
  }
}

/** Truncate a string with ellipsis */
export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

/** Format a number with commas */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/** Compute risk score ring stroke values for SVG */
export function ringStrokeDasharray(score: number, radius: number): string {
  const circumference = 2 * Math.PI * radius;
  const filled = (score / 100) * circumference;
  return `${filled} ${circumference - filled}`;
}

export function ringStrokeDasharrayValues(score: number, radius: number): { filled: number; total: number } {
  const circumference = 2 * Math.PI * radius;
  return { filled: (score / 100) * circumference, total: circumference };
}

/** Pluralize a word based on count */
export function pluralize(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Dynamically format incident title based on alert count */
export function formatIncidentTitle(incident: { title?: string; affectedDevice?: string; relatedAlertIds?: string[] }): string {
  const alertCount = incident.relatedAlertIds?.length ?? 0;
  const device = incident.affectedDevice || 'Unknown-Host';
  if (alertCount <= 1) {
    return `Security Incident on ${device}`;
  }
  return `Correlated Security Incident on ${device}`;
}

