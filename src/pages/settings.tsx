import { useState } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Dialog } from '../components/ui/dialog';
import { useTheme } from '../context/theme-context';
import { useAuth } from '../hooks/use-auth';
import { useProfile } from '../hooks/use-profile';
import { useStaffManagement } from '../hooks/use-staff-management';
import { Cpu, ShieldAlert, UserPlus, Trash2, Loader2 } from 'lucide-react';

export default function Settings() {
  const { theme, toggleTheme } = useTheme();
  const { user: authUser } = useAuth();
  const { data: profile } = useProfile(authUser?.id);
  const { staff, isLoading, createStaff, updateStaffRole, deleteStaff } = useStaffManagement();
  
  const [isAddStaffModalOpen, setIsAddStaffModalOpen] = useState(false);
  const [newStaff, setNewStaff] = useState({ email: '', password: '', username: '', role: 'staff' as 'admin' | 'manager' | 'staff' });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isAdmin = profile?.role === 'admin';

  const handleAddStaff = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await createStaff.mutateAsync(newStaff);
      setIsAddStaffModalOpen(false);
      setNewStaff({ email: '', password: '', username: '', role: 'staff' });
    } catch (error) {
      console.error('Error creating staff:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: 'admin' | 'manager' | 'staff') => {
    try {
      await updateStaffRole.mutateAsync({ userId, role: newRole });
    } catch (error) {
      console.error('Error updating role:', error);
    }
  };

  const handleDeleteStaff = async (userId: string) => {
    if (confirm('Are you sure you want to remove this staff member?')) {
      try {
        await deleteStaff.mutateAsync(userId);
      } catch (error) {
        console.error('Error deleting staff:', error);
      }
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">System Settings</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">Manage team members, display preferences, and system configurations.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Staff Management - Admin Only */}
        {isAdmin && (
          <Card className="p-6 space-y-4 md:col-span-2">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <UserPlus className="w-5 h-5 text-blue-500" />
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Staff Management</h3>
                  <p className="text-[11px] text-slate-500">Add and manage team members</p>
                </div>
              </div>
              <Button size="sm" onClick={() => setIsAddStaffModalOpen(true)} className="flex items-center gap-2">
                <UserPlus className="w-4 h-4" /> Add Staff
              </Button>
            </div>

            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
              </div>
            ) : (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {staff.map((member) => (
                  <div key={member.id} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-blue-100 dark:bg-blue-950/40 rounded-full flex items-center justify-center">
                        <span className="text-sm font-bold text-blue-600 dark:text-blue-400">
                          {member.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-slate-900 dark:text-white text-sm">{member.username}</p>
                        <p className="text-xs text-slate-500">{member.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={member.role}
                        onChange={(e) => handleRoleChange(member.id, e.target.value as any)}
                        className="text-xs px-2 py-1 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300"
                        disabled={member.id === authUser?.id}
                      >
                        <option value="staff">Staff</option>
                        <option value="manager">Manager</option>
                        <option value="admin">Admin</option>
                      </select>
                      {member.id !== authUser?.id && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDeleteStaff(member.id)}
                          className="text-red-500 hover:text-red-600"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {/* Theme Settings */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
            <Cpu className="w-5 h-5 text-purple-500" />
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Display Properties</h3>
              <p className="text-[11px] text-slate-500">Configure theme variables</p>
            </div>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-600 dark:text-slate-400">Dark Mode</span>
            <Button variant="secondary" size="sm" onClick={toggleTheme} className="capitalize">
              {theme === 'dark' ? 'Enabled' : 'Disabled'}
            </Button>
          </div>
        </Card>

        {/* User Info */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
            <ShieldAlert className="w-5 h-5 text-green-500" />
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Your Profile</h3>
              <p className="text-[11px] text-slate-500">Current user information</p>
            </div>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-600 dark:text-slate-400">Username</span>
              <span className="font-medium text-slate-900 dark:text-white">{profile?.username || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-600 dark:text-slate-400">Email</span>
              <span className="font-medium text-slate-900 dark:text-white">{authUser?.email || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-600 dark:text-slate-400">Role</span>
              <span className="font-medium text-slate-900 dark:text-white capitalize">{profile?.role || 'N/A'}</span>
            </div>
          </div>
        </Card>

        {/* Security Info */}
        <Card className="p-6 space-y-4 md:col-span-2 bg-blue-500/5 border-blue-500/20 dark:border-blue-500/10">
          <div className="flex items-center gap-3 text-blue-600 dark:text-blue-400">
            <ShieldAlert className="w-5 h-5" />
            <h3 className="text-sm font-bold">Row Level Security (RLS)</h3>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed max-w-2xl">
            This application uses Supabase Row Level Security to protect your data. All database operations are secured by policies that ensure users can only access data appropriate to their role. Admins have full access, managers can modify inventory, and staff have read-only access.
          </p>
        </Card>
      </div>

      {/* Add Staff Modal */}
      <Dialog isOpen={isAddStaffModalOpen} onClose={() => setIsAddStaffModalOpen(false)} title="Add New Staff Member">
        <form onSubmit={handleAddStaff} className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Username</label>
            <Input
              value={newStaff.username}
              onChange={(e) => setNewStaff({ ...newStaff, username: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Email</label>
            <Input
              type="email"
              value={newStaff.email}
              onChange={(e) => setNewStaff({ ...newStaff, email: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Password</label>
            <Input
              type="password"
              value={newStaff.password}
              onChange={(e) => setNewStaff({ ...newStaff, password: e.target.value })}
              required
              minLength={6}
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Role</label>
            <select
              value={newStaff.role}
              onChange={(e) => setNewStaff({ ...newStaff, role: e.target.value as any })}
              className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white"
              required
            >
              <option value="staff">Staff</option>
              <option value="manager">Manager</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="flex gap-2 pt-2">
            <Button type="submit" disabled={isSubmitting} className="flex-1">
              {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Add Staff Member
            </Button>
            <Button type="button" variant="secondary" onClick={() => setIsAddStaffModalOpen(false)}>
              Cancel
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
