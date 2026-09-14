export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'SOC_OPERATOR' | 'VIEWER';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  isActive: boolean;
  lastLogin?: string;
  createdAt?: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  user: AuthUser;
  permissions: string[];
}

export interface UserCreateData {
  email: string;
  fullName: string;
  password: string;
  role: UserRole;
}

export interface UserUpdateData {
  fullName?: string;
  role?: UserRole;
  isActive?: boolean;
  newPassword?: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId?: string;
  userEmail?: string;
  action: string;
  resourceType?: string;
  resourceId?: string;
  result: 'success' | 'failure' | string;
  sourceIp?: string;
  details: Record<string, any>;
}

export interface BlocklistEntry {
  id: string;
  ip: string;
  status: string;
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt?: string;
  responseActionId: string;
}
