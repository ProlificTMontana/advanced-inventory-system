import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';

type Task = Database['public']['Tables']['tasks']['Row'];
type TaskInsert = Database['public']['Tables']['tasks']['Insert'];
type TaskUpdate = Database['public']['Tables']['tasks']['Update'];

export function useTasks() {
  const queryClient = useQueryClient();

  const tasksQuery = useQuery({
    queryKey: ['tasks'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('tasks')
        .select(`
          *,
          task_types:task_type_id(name, color, icon),
          assigned_to_profile:assigned_to(username, role),
          created_by_profile:created_by(username, role),
          vehicles:vehicle_id(registration_number, type)
        `)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as (Task & {
        task_types: { name: string; color: string; icon: string | null } | null;
        assigned_to_profile: { username: string; role: string } | null;
        created_by_profile: { username: string; role: string } | null;
        vehicles: { registration_number: string; type: string | null } | null;
      })[];
    },
  });

  const createTask = useMutation({
    mutationFn: async (task: TaskInsert) => {
      const { data, error } = await supabase
        .from('tasks')
        .insert(task)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const updateTask = useMutation({
    mutationFn: async ({ id, ...update }: TaskUpdate & { id: string }) => {
      const { data, error } = await supabase
        .from('tasks')
        .update(update)
        .eq('id', id)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const deleteTask = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase
        .from('tasks')
        .delete()
        .eq('id', id);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  return {
    tasks: tasksQuery.data || [],
    isLoading: tasksQuery.isLoading,
    error: tasksQuery.error,
    createTask,
    updateTask,
    deleteTask,
  };
}

export function useTaskRealtime() {
  const queryClient = useQueryClient();

  useEffect(() => {
    const channel = supabase
      .channel('tasks_changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'tasks',
        },
        (payload) => {
          console.log('Realtime task change:', payload);
          queryClient.invalidateQueries({ queryKey: ['tasks'] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [queryClient]);
}

import { useEffect } from 'react';
