import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';

type Item = Database['public']['Tables']['items']['Row'];
type ItemInsert = Database['public']['Tables']['items']['Insert'];
type ItemUpdate = Database['public']['Tables']['items']['Update'];

export function useItems() {
  const queryClient = useQueryClient();

  const itemsQuery = useQuery({
    queryKey: ['items'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('items')
        .select(`
          *,
          categories:category_id(name),
          suppliers:supplier_id(name)
        `)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as (Item & { categories: { name: string } | null; suppliers: { name: string } | null })[];
    },
  });

  const createItem = useMutation({
    mutationFn: async (item: ItemInsert) => {
      const { data, error } = await supabase.from('items').insert(item).select().single();
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  const updateItem = useMutation({
    mutationFn: async ({ id, ...update }: ItemUpdate & { id: string }) => {
      const { data, error } = await supabase.from('items').update(update).eq('id', id).select().single();
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  const deleteItem = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from('items').delete().eq('id', id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  return {
    items: itemsQuery.data || [],
    isLoading: itemsQuery.isLoading,
    error: itemsQuery.error,
    createItem,
    updateItem,
    deleteItem,
  };
}
