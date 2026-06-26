import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { supabase } from '../lib/supabase';

interface StaffMember {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'manager' | 'staff';
  created_at: string;
}

export function useStaffManagement() {
  const queryClient = useQueryClient();

  // Fetch all staff members (profiles)
  const staffQuery = useQuery({
    queryKey: ['staff'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as StaffMember[];
    },
  });

  // Create new staff member (admin only)
  const createStaff = useMutation({
    mutationFn: async ({ email, password, username, role }: {
      email: string;
      password: string;
      username: string;
      role: 'admin' | 'manager' | 'staff';
    }) => {
      // Create user in Supabase Auth
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            username,
            role,
          },
        },
      });

      if (authError) throw authError;
      return authData;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['staff'] });
    },
  });

  // Update staff role (admin only)
  const updateStaffRole = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: 'admin' | 'manager' | 'staff' }) => {
      const { data, error } = await supabase
        .from('profiles')
        .update({ role })
        .eq('id', userId)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['staff'] });
    },
  });

  // Delete staff member (admin only)
  const deleteStaff = useMutation({
    mutationFn: async (userId: string) => {
      // Delete from Supabase Auth (requires service role key, so we'll delete profile only)
      // In production, you'd need a server-side function to delete the auth user
      const { error } = await supabase
        .from('profiles')
        .delete()
        .eq('id', userId);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['staff'] });
    },
  });

  return {
    staff: staffQuery.data || [],
    isLoading: staffQuery.isLoading,
    error: staffQuery.error,
    createStaff,
    updateStaffRole,
    deleteStaff,
  };
}
