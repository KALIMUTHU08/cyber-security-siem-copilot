import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { AuthUser, UserRole } from '../types/auth';
import { siemService } from '../services';

interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  permissions: string[];
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasRole: (...roles: UserRole[]) => boolean;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = 'siem_auth_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(() => {
    return typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null;
  });
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const logout = useCallback(async () => {
    try {
      if (token) {
        await siemService.logout();
      }
    } catch {
      // ignore
    } finally {
      localStorage.removeItem(TOKEN_KEY);
      setToken(null);
      setUser(null);
      setPermissions([]);
    }
  }, [token]);

  // Validate session on mount or token change
  useEffect(() => {
    let isMounted = true;

    async function initAuth() {
      const storedToken = localStorage.getItem(TOKEN_KEY);
      if (!storedToken) {
        if (isMounted) {
          setIsLoading(false);
          setUser(null);
          setPermissions([]);
        }
        return;
      }

      try {
        const me = await siemService.getMe();
        if (isMounted && me && me.user) {
          setUser(me.user);
          setPermissions(me.permissions || []);
        }
      } catch (err) {
        console.warn('Authentication token invalid or expired:', err);
        if (isMounted) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
          setUser(null);
          setPermissions([]);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    initAuth();

    return () => {
      isMounted = false;
    };
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await siemService.login(email, password);
      localStorage.setItem(TOKEN_KEY, res.accessToken);
      setToken(res.accessToken);
      setUser(res.user);
      setPermissions(res.permissions || []);
    } finally {
      setIsLoading(false);
    }
  };

  const hasPermission = useCallback(
    (permission: string): boolean => {
      if (!user) return false;
      if (user.role === 'ADMIN') return true;
      return permissions.includes(permission);
    },
    [user, permissions]
  );

  const hasRole = useCallback(
    (...roles: UserRole[]): boolean => {
      if (!user) return false;
      return roles.includes(user.role);
    },
    [user]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        permissions,
        isLoading,
        login,
        logout,
        hasPermission,
        hasRole,
        isAuthenticated: !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
