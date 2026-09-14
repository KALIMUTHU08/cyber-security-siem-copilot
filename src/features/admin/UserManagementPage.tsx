import React, { useState, useEffect } from 'react';
import {
  Users,
  UserPlus,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  RefreshCw,
  Clock,
  X,
} from 'lucide-react';
import type { AuthUser, UserRole, UserCreateData } from '../../types/auth';
import { siemService } from '../../services';
import { useAuth } from '../../contexts/AuthContext';

const ROLES: { value: UserRole; label: string; desc: string }[] = [
  { value: 'ADMIN', label: 'Admin', desc: 'Full system & user access, detection rules, and incident actions' },
  { value: 'SECURITY_ANALYST', label: 'Security Analyst', desc: 'Alert triage, threat hunting, copilot, recommend & approve response actions' },
  { value: 'SOC_OPERATOR', label: 'SOC Operator', desc: 'Execute approved response actions, monitor dashboard, and view alerts' },
  { value: 'VIEWER', label: 'Viewer', desc: 'Read-only access to dashboard, alerts, logs, and analytics' },
];

export const UserManagementPage: React.FC = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Add User Modal State
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUser, setNewUser] = useState<UserCreateData>({
    email: '',
    fullName: '',
    password: '',
    role: 'SECURITY_ANALYST',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Password Reset Modal State
  const [resetUser, setResetUser] = useState<AuthUser | null>(null);
  const [newPassword, setNewPassword] = useState('');

  const fetchUsers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await siemService.getUsers();
      setUsers(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load user directory.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUser.email || !newUser.fullName || !newUser.password) {
      setError('Please fill in all required fields.');
      return;
    }
    if (newUser.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await siemService.createUser(newUser);
      setSuccessMessage(`User ${newUser.email} created successfully.`);
      setShowAddModal(false);
      setNewUser({ email: '', fullName: '', password: '', role: 'SECURITY_ANALYST' });
      fetchUsers();
    } catch (err: any) {
      setError(err?.message || 'Failed to create user.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleActive = async (targetUser: AuthUser) => {
    setError(null);
    setSuccessMessage(null);
    try {
      const updated = await siemService.updateUser(targetUser.id, {
        isActive: !targetUser.isActive,
      });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
      setSuccessMessage(`User ${updated.email} ${updated.isActive ? 'activated' : 'deactivated'}.`);
    } catch (err: any) {
      setError(err?.message || 'Failed to update user status.');
    }
  };

  const handleRoleChange = async (targetUser: AuthUser, newRole: UserRole) => {
    if (targetUser.role === newRole) return;
    setError(null);
    setSuccessMessage(null);
    try {
      const updated = await siemService.updateUser(targetUser.id, { role: newRole });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
      setSuccessMessage(`Updated ${updated.email} role to ${newRole}.`);
    } catch (err: any) {
      setError(err?.message || 'Failed to change role.');
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetUser || !newPassword) return;
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await siemService.updateUser(resetUser.id, { newPassword });
      setSuccessMessage(`Password updated successfully for ${resetUser.email}.`);
      setResetUser(null);
      setNewPassword('');
    } catch (err: any) {
      setError(err?.message || 'Failed to reset password.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const getRoleBadgeStyle = (role: string) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
      case 'SECURITY_ANALYST':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'SOC_OPERATOR':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'VIEWER':
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Users className="w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">User Management &amp; RBAC</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Administer security personnel accounts, assign role permissions, and manage SOC access.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchUsers}
            title="Refresh list"
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 flex items-center gap-2 transition-all cursor-pointer"
          >
            <UserPlus className="w-4 h-4" />
            <span>Add Account</span>
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {successMessage && (
        <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-200 text-xs flex items-center gap-2.5">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="flex-1">{successMessage}</span>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Role Summary Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {ROLES.map((r) => {
          const count = users.filter((u) => u.role === r.value).length;
          return (
            <div key={r.value} className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
              <div className="flex items-center justify-between">
                <span className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border uppercase ${getRoleBadgeStyle(r.value)}`}>
                  {r.label}
                </span>
                <span className="text-sm font-bold text-slate-100">{count}</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">{r.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Users Table Card */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800/80 overflow-hidden shadow-xl">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Active Accounts Directory ({users.length})
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold text-[10px]">
                <th className="py-3 px-4">Personnel</th>
                <th className="py-3 px-4">Role &amp; Permissions</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Authentication</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-slate-500">
                    <div className="inline-block w-6 h-6 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mb-2" />
                    <div>Loading user records...</div>
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    No users registered in directory.
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const isSelf = u.id === currentUser?.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-xs">
                            {u.fullName.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-medium text-slate-200 flex items-center gap-1.5">
                              {u.fullName}
                              {isSelf && (
                                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                                  You
                                </span>
                              )}
                            </div>
                            <div className="text-slate-400 text-[11px] font-mono">{u.email}</div>
                          </div>
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        {isSelf ? (
                          <span className={`text-xs font-mono font-medium px-2 py-0.5 rounded border uppercase ${getRoleBadgeStyle(u.role)}`}>
                            {u.role}
                          </span>
                        ) : (
                          <select
                            value={u.role}
                            onChange={(e) => handleRoleChange(u, e.target.value as UserRole)}
                            className="px-2 py-1 bg-slate-950 border border-slate-700/80 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
                          >
                            {ROLES.map((r) => (
                              <option key={r.value} value={r.value}>
                                {r.label} ({r.value})
                              </option>
                            ))}
                          </select>
                        )}
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                            u.isActive
                              ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/40'
                              : 'bg-red-950/40 text-red-300 border-red-500/40'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${u.isActive ? 'bg-emerald-400' : 'bg-red-400'}`} />
                          {u.isActive ? 'Active' : 'Disabled'}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {u.lastLogin ? (
                          <div className="flex items-center gap-1.5 text-slate-300">
                            <Clock className="w-3.5 h-3.5 text-slate-500" />
                            {new Date(u.lastLogin).toLocaleString()}
                          </div>
                        ) : (
                          <span className="text-slate-600">Never logged in</span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setResetUser(u)}
                            title="Reset password"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 border border-transparent hover:border-cyan-500/20 transition-all cursor-pointer"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                          </button>

                          {!isSelf && (
                            <button
                              onClick={() => handleToggleActive(u)}
                              className={`px-2.5 py-1 rounded-lg text-[11px] font-medium border transition-colors cursor-pointer ${
                                u.isActive
                                  ? 'text-red-400 hover:bg-red-500/10 border-red-500/30'
                                  : 'text-emerald-400 hover:bg-emerald-500/10 border-emerald-500/30'
                              }`}
                            >
                              {u.isActive ? 'Deactivate' : 'Activate'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add User Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-cyan-400" />
                Provision SOC Account
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Maya Lin"
                  value={newUser.fullName}
                  onChange={(e) => setNewUser({ ...newUser, fullName: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. analyst@siem.local"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Role &amp; Permissions</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value as UserRole })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
                >
                  {ROLES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label} ({r.value})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Temporary Password</label>
                <input
                  type="password"
                  required
                  placeholder="Min 8 characters"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition-all cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Creating...' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetUser && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-cyan-400" />
                Reset Password
              </h2>
              <button
                onClick={() => setResetUser(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400 mb-4">
              Set a new password for <span className="text-slate-200 font-mono font-medium">{resetUser.email}</span>.
            </p>

            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">New Password</label>
                <input
                  type="password"
                  required
                  placeholder="Min 8 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setResetUser(null)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition-all cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Updating...' : 'Update Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
