import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';
import { indexedDB } from '../lib/indexeddb';

type Item = Database['public']['Tables']['items']['Row'];
type ItemInsert = Database['public']['Tables']['items']['Insert'];
type ItemUpdate = Database['public']['Tables']['items']['Update'];

export function useOfflineItems() {
  const queryClient = useQueryClient();

  const itemsQuery = useQuery({
    queryKey: ['items'],
    queryFn: async () => {
      // Try to fetch from Supabase first
      try {
        const { data, error } = await supabase
          .from('items')
          .select(`
            *,
            categories:category_id(name),
            suppliers:supplier_id(name)
          `)
          .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        // Cache in IndexedDB
        if (data) {
          await indexedDB.init();
          for (const item of data) {
            await indexedDB.put('items', item);
          }
        }
        
        return data as (Item & { categories: { name: string } | null; suppliers: { name: string } | null })[];
      } catch (error) {
        // Fallback to IndexedDB if offline
        console.log('Using offline cache for items');
        await indexedDB.init();
        const cachedItems = await indexedDB.getAll<any>('items');
        return cachedItems as (Item & { categories: { name: string } | null; suppliers: { name: string } | null })[];
      }
    },
  });

  const createItem = useMutation({
    mutationFn: async (item: ItemInsert) => {
      try {
        const { data, error } = await supabase.from('items').insert(item).select().single();
        if (error) throw error;
        
        // Cache in IndexedDB
        await indexedDB.init();
        await indexedDB.put('items', data);
        
        return data;
      } catch (error) {
        // Queue for sync if offline
        console.log('Queuing item creation for sync');
        await indexedDB.init();
        await indexedDB.addPendingChange({
          type: 'create',
          store: 'items',
          data: item,
          timestamp: Date.now(),
        });
        throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  const updateItem = useMutation({
    mutationFn: async ({ id, ...update }: ItemUpdate & { id: string }) => {
      try {
        const { data, error } = await supabase.from('items').update(update).eq('id', id).select().single();
        if (error) throw error;
        
        // Update cache in IndexedDB
        await indexedDB.init();
        await indexedDB.put('items', data);
        
        return data;
      } catch (error) {
        // Queue for sync if offline
        console.log('Queuing item update for sync');
        await indexedDB.init();
        await indexedDB.addPendingChange({
          type: 'update',
          store: 'items',
          data: { id, ...update },
          timestamp: Date.now(),
        });
        throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  const deleteItem = useMutation({
    mutationFn: async (id: string) => {
      try {
        const { error } = await supabase.from('items').delete().eq('id', id);
        if (error) throw error;
        
        // Remove from IndexedDB cache
        await indexedDB.init();
        await indexedDB.delete('items', id);
        
      } catch (error) {
        // Queue for sync if offline
        console.log('Queuing item deletion for sync');
        await indexedDB.init();
        await indexedDB.addPendingChange({
          type: 'delete',
          store: 'items',
          data: { id },
          timestamp: Date.now(),
        });
        throw error;
      }
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
