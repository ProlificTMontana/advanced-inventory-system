import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';
import { useAuth } from './use-auth';

type ReorderRequest = Database['public']['Tables']['reorder_requests']['Row'];
type ReorderRequestInsert = Database['public']['Tables']['reorder_requests']['Insert'];
type ReorderRequestUpdate = Database['public']['Tables']['reorder_requests']['Update'];

export function useReorderRequests() {
  const queryClient = useQueryClient();

  const requestsQuery = useQuery({
    queryKey: ['reorder-requests'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('reorder_requests')
        .select(`
          *,
          items:item_id(name, sku, quantity, min_stock, price),
          suppliers:supplier_id(name, contact_email, contact_phone),
          requested_by_profile:requested_by(username, email)
        `)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as (ReorderRequest & { 
        items: { 
          name: string; 
          sku: string; 
          quantity: number; 
          min_stock: number; 
          price: number;
        } | null;
        suppliers: { 
          name: string; 
          contact_email: string | null; 
          contact_phone: string | null 
        } | null;
        requested_by_profile: {
          username: string;
          email: string;
        } | null;
      })[];
    },
  });

  const createReorderRequest = useMutation({
    mutationFn: async (request: ReorderRequestInsert) => {
      const { data, error } = await supabase
        .from('reorder_requests')
        .insert(request)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reorder-requests'] });
    },
  });

  const updateReorderRequest = useMutation({
    mutationFn: async ({ id, ...update }: ReorderRequestUpdate & { id: string }) => {
      const { data, error } = await supabase
        .from('reorder_requests')
        .update(update)
        .eq('id', id)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reorder-requests'] });
    },
  });

  const deleteReorderRequest = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase
        .from('reorder_requests')
        .delete()
        .eq('id', id);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reorder-requests'] });
    },
  });

  return {
    requests: requestsQuery.data || [],
    isLoading: requestsQuery.isLoading,
    error: requestsQuery.error,
    createReorderRequest,
    updateReorderRequest,
    deleteReorderRequest,
  };
}

export function useCreateReorderRequest() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const createReorderFromAlert = useMutation({
    mutationFn: async ({ 
      itemId, 
      supplierId, 
      suggestedQuantity,
      notes 
    }: { 
      itemId: string; 
      supplierId: string | null; 
      suggestedQuantity: number;
      notes?: string;
    }) => {
      if (!user?.id) throw new Error('User not authenticated');

      const { data, error } = await supabase
        .from('reorder_requests')
        .insert({
          item_id: itemId,
          supplier_id: supplierId,
          requested_by: user.id,
          requested_quantity: suggestedQuantity,
          status: 'pending',
          notes: notes || `Auto-generated from stock alert. Suggested quantity based on demand forecast.`,
        })
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reorder-requests'] });
      queryClient.invalidateQueries({ queryKey: ['stock-alerts'] });
    },
  });

  return {
    createReorderFromAlert,
  };
}
