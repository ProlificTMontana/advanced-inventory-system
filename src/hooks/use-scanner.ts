import { useState, useCallback } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase, Database } from '../lib/supabase';
import { indexedDB } from '../lib/indexeddb';
import { useAuth } from './use-auth';
import { useInventoryStore } from '../store/inventory-store';

type Item = Database['public']['Tables']['items']['Row'];
type TransactionInsert = Database['public']['Tables']['inventory_transactions']['Insert'];

export function useScanner() {
  const queryClient = useQueryClient();
  const { user: authUser } = useAuth();
  const { isOffline } = useInventoryStore();
  const [scannedBarcode, setScannedBarcode] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<string[]>([]);

  // Find item by barcode
  const findItemByBarcode = useCallback(async (barcode: string) => {
    try {
      const { data, error } = await supabase
        .from('items')
        .select(`
          *,
          categories:category_id(name),
          suppliers:supplier_id(name)
        `)
        .eq('barcode', barcode)
        .single();

      if (error) {
        if (error.code === 'PGRST116') {
          // No rows returned - item not found
          return null;
        }
        throw error;
      }

      return data as Item & { categories: { name: string } | null; suppliers: { name: string } | null };
    } catch (error) {
      console.error('Error finding item by barcode:', error);
      throw error;
    }
  }, []);

  // Update item with barcode
  const updateItemBarcode = useMutation({
    mutationFn: async ({ itemId, barcode }: { itemId: string; barcode: string }) => {
      const { data, error } = await supabase
        .from('items')
        .update({ 
          barcode,
          last_scanned_at: new Date().toISOString(),
        })
        .eq('id', itemId)
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  // Create transaction for scan
  const createScanTransaction = useMutation({
    mutationFn: async (transaction: TransactionInsert) => {
      const { data, error } = await supabase
        .from('inventory_transactions')
        .insert({
          ...transaction,
          scan_source: 'scanner',
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['transactions'] });
      queryClient.invalidateQueries({ queryKey: ['items'] });
    },
  });

  // Handle scan result
  const handleScan = useCallback(async (barcode: string) => {
    setScannedBarcode(barcode);
    setScanHistory(prev => [barcode, ...prev.slice(0, 9)]); // Keep last 10 scans

    try {
      const item = await findItemByBarcode(barcode);

      if (item) {
        // Update last_scanned_at
        await supabase
          .from('items')
          .update({ last_scanned_at: new Date().toISOString() })
          .eq('id', item.id);

        // Queue scan for offline sync
        await indexedDB.addScanEntry({
          barcode,
          action: 'view',
          timestamp: Date.now(),
          synced: !isOffline,
        });

        return { item, barcode };
      } else {
        // Unknown barcode
        await indexedDB.addScanEntry({
          barcode,
          action: 'view',
          timestamp: Date.now(),
          synced: !isOffline,
        });

        return { item: null, barcode };
      }
    } catch (error) {
      console.error('Error handling scan:', error);
      
      // Queue for sync even on error
      await indexedDB.addScanEntry({
        barcode,
        action: 'view',
        timestamp: Date.now(),
        synced: false,
      });

      throw error;
    }
  }, [findItemByBarcode, isOffline]);

  // Handle stock adjustment from scan
  const handleStockAdjustment = useCallback(async (
    itemId: string,
    quantity: number,
    type: 'add' | 'remove'
  ) => {
    if (!authUser?.id) {
      throw new Error('User not authenticated');
    }

    try {
      // Get current item quantity
      const { data: item } = await supabase
        .from('items')
        .select('quantity')
        .eq('id', itemId)
        .single();

      if (!item) throw new Error('Item not found');

      const newQuantity = type === 'add' 
        ? item.quantity + quantity 
        : item.quantity - quantity;

      if (newQuantity < 0) {
        throw new Error('Insufficient stock for removal');
      }

      // Update item quantity
      const { error: updateError } = await supabase
        .from('items')
        .update({ 
          quantity: newQuantity,
          last_scanned_at: new Date().toISOString(),
        })
        .eq('id', itemId);

      if (updateError) throw updateError;

      // Create transaction log
      await createScanTransaction.mutateAsync({
        item_id: itemId,
        type,
        quantity_change: type === 'add' ? quantity : -quantity,
        notes: `Stock adjustment via scanner`,
        created_by: authUser.id,
      });

      // Queue for offline sync
      await indexedDB.addScanEntry({
        barcode: scannedBarcode || '',
        action: type,
        quantity,
        timestamp: Date.now(),
        synced: !isOffline,
      });

      queryClient.invalidateQueries({ queryKey: ['items'] });
    } catch (error) {
      console.error('Error handling stock adjustment:', error);
      throw error;
    }
  }, [authUser?.id, scannedBarcode, createScanTransaction, isOffline, queryClient]);

  // Link barcode to existing item
  const linkBarcodeToItem = useCallback(async (barcode: string, itemId: string) => {
    try {
      await updateItemBarcode.mutateAsync({ itemId, barcode });
      
      // Queue for offline sync
      await indexedDB.addScanEntry({
        barcode,
        action: 'view',
        timestamp: Date.now(),
        synced: !isOffline,
      });

      return true;
    } catch (error) {
      console.error('Error linking barcode to item:', error);
      throw error;
    }
  }, [updateItemBarcode, isOffline]);

  // Create new item with barcode
  const createItemWithBarcode = useCallback(async (
    barcode: string,
    itemData: Omit<Database['public']['Tables']['items']['Insert'], 'id'>
  ) => {
    try {
      const { data, error } = await supabase
        .from('items')
        .insert({
          ...itemData,
          barcode,
          last_scanned_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) throw error;

      // Create initial transaction
      if (authUser?.id) {
        await createScanTransaction.mutateAsync({
          item_id: data.id,
          type: 'add',
          quantity_change: itemData.quantity,
          notes: 'Item created via scanner',
          created_by: authUser.id,
        });
      }

      // Queue for offline sync
      await indexedDB.addScanEntry({
        barcode,
        action: 'view',
        timestamp: Date.now(),
        synced: !isOffline,
      });

      queryClient.invalidateQueries({ queryKey: ['items'] });
      return data;
    } catch (error) {
      console.error('Error creating item with barcode:', error);
      throw error;
    }
  }, [authUser?.id, createScanTransaction, isOffline, queryClient]);

  return {
    scannedBarcode,
    scanHistory,
    handleScan,
    handleStockAdjustment,
    linkBarcodeToItem,
    createItemWithBarcode,
    updateItemBarcode,
    isLoading: updateItemBarcode.isPending || createScanTransaction.isPending,
  };
}
