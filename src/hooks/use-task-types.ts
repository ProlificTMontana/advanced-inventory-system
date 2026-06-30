import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';

type TaskType = Database['public']['Tables']['task_types']['Row'];
type TaskTypeInsert = Database['public']['Tables']['task_types']['Insert'];
type TaskTypeUpdate = Database['public']['Tables']['task_types']['Update'];

export function useTaskTypes() {
  const queryClient = useQueryClient();

  const taskTypesQuery = useQuery({
    queryKey: ['task_types'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('task_types')
        .select('*')
        .order('name');
      
      if (error) throw error;
      return data as TaskType[];
    },
  });

  const createTaskType = useMutation({
    mutationFn: async (taskType: TaskTypeInsert) => {
      const { data, error } = await supabase
        .from('task_types')
        .insert(taskType)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['task_types'] });
    },
  });

  const updateTaskType = useMutation({
    mutationFn: async ({ id, ...update }: TaskTypeUpdate & { id: string }) => {
      const { data, error } = await supabase
        .from('task_types')
        .update(update)
        .eq('id', id)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['task_types'] });
    },
  });

  const deleteTaskType = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase
        .from('task_types')
        .delete()
        .eq('id', id);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['task_types'] });
    },
  });

  return {
    taskTypes: taskTypesQuery.data || [],
    isLoading: taskTypesQuery.isLoading,
    error: taskTypesQuery.error,
    createTaskType,
    updateTaskType,
    deleteTaskType,
  };
}
