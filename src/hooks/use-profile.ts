import { useQuery } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';

type Profile = Database['public']['Tables']['profiles']['Row'];

export function useProfile(userId?: string) {
  return useQuery({
    queryKey: ['profile', userId],
    queryFn: async () => {
      if (!userId) return null;
      
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .single();
      
      if (error) throw error;
      return data as Profile;
    },
    enabled: !!userId,
  });
}
