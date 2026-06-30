import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';
import { useAuth } from './use-auth';

type StockAlert = Database['public']['Tables']['stock_alerts']['Row'];

export function useStockAlerts() {
  const queryClient = useQueryClient();

  const alertsQuery = useQuery({
    queryKey: ['stock-alerts'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('stock_alerts')
        .select(`
          *,
          items:item_id(name, sku, quantity, min_stock, supplier_id, suppliers:supplier_id(name, contact_email))
        `)
        .is('resolved_at', null)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      return data as (StockAlert & { 
        items: { 
          name: string; 
          sku: string; 
          quantity: number; 
          min_stock: number; 
          supplier_id: string | null;
          suppliers: { name: string; contact_email: string | null } | null 
        } | null 
      })[];
    },
  });

  const acknowledgeAlert = useMutation({
    mutationFn: async ({ alertId, userId }: { alertId: string; userId: string }) => {
      const { data, error } = await supabase
        .from('stock_alerts')
        .update({ 
          acknowledged_by: userId, 
          acknowledged_at: new Date().toISOString() 
        })
        .eq('id', alertId)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stock-alerts'] });
    },
  });

  const resolveAlert = useMutation({
    mutationFn: async (alertId: string) => {
      const { data, error } = await supabase
        .from('stock_alerts')
        .update({ resolved_at: new Date().toISOString() })
        .eq('id', alertId)
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stock-alerts'] });
    },
  });

  // Function to manually trigger alert evaluation
  const evaluateAlerts = useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase
        .rpc('evaluate_and_create_alerts');
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stock-alerts'] });
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  return {
    alerts: alertsQuery.data || [],
    isLoading: alertsQuery.isLoading,
    error: alertsQuery.error,
    acknowledgeAlert,
    resolveAlert,
    evaluateAlerts,
  };
}

export function useAlertPreferences() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const preferencesQuery = useQuery({
    queryKey: ['alert-preferences', user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      
      const { data, error } = await supabase
        .from('alert_preferences')
        .select('*')
        .eq('user_id', user.id);
      
      if (error) throw error;
      return data;
    },
    enabled: !!user?.id,
  });

  const snoozeAlert = useMutation({
    mutationFn: async ({ 
      itemId, 
      alertTier, 
      snoozeMinutes = 60 
    }: { 
      itemId: string; 
      alertTier: 'warning' | 'critical' | 'emergency'; 
      snoozeMinutes?: number;
    }) => {
      if (!user?.id) throw new Error('User not authenticated');

      const snoozedUntil = new Date(Date.now() + snoozeMinutes * 60 * 1000).toISOString();
      
      const { data, error } = await supabase
        .from('alert_preferences')
        .upsert({
          user_id: user.id,
          item_id: itemId,
          alert_tier: alertTier,
          is_snoozed: true,
          snoozed_until: snoozedUntil,
          is_dismissed: false,
          dismissed_at: null,
        })
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-preferences', user?.id] });
    },
  });

  const dismissAlert = useMutation({
    mutationFn: async ({ 
      itemId, 
      alertTier 
    }: { 
      itemId: string; 
      alertTier: 'warning' | 'critical' | 'emergency'; 
    }) => {
      if (!user?.id) throw new Error('User not authenticated');

      const { data, error } = await supabase
        .from('alert_preferences')
        .upsert({
          user_id: user.id,
          item_id: itemId,
          alert_tier: alertTier,
          is_snoozed: false,
          snoozed_until: null,
          is_dismissed: true,
          dismissed_at: new Date().toISOString(),
        })
        .select()
        .single();
      
      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-preferences', user?.id] });
    },
  });

  const clearPreference = useMutation({
    mutationFn: async (preferenceId: string) => {
      const { error } = await supabase
        .from('alert_preferences')
        .delete()
        .eq('id', preferenceId);
      
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-preferences', user?.id] });
    },
  });

  return {
    preferences: preferencesQuery.data || [],
    isLoading: preferencesQuery.isLoading,
    error: preferencesQuery.error,
    snoozeAlert,
    dismissAlert,
    clearPreference,
  };
}
