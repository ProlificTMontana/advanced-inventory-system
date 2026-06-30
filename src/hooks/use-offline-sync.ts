import { useEffect, useState } from 'react';
import { indexedDB } from '../lib/indexeddb';
import { supabase } from '../lib/supabase';
import { useInventoryStore } from '../store/inventory-store';

export function useOfflineSync() {
  const { isOffline } = useInventoryStore();
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'error'>('idle');
  const [pendingCount, setPendingCount] = useState(0);

  // Sync pending scan operations when coming back online
  useEffect(() => {
    const syncPendingScans = async () => {
      if (isOffline) return;

      setSyncStatus('syncing');

      try {
        const unsyncedScans = await indexedDB.getUnsyncedScans();

        if (unsyncedScans.length === 0) {
          setSyncStatus('idle');
          return;
        }

        console.log(`Syncing ${unsyncedScans.length} pending scans...`);

        for (const scan of unsyncedScans) {
          try {
            // Find item by barcode
            const { data: item } = await supabase
              .from('items')
              .select('id, quantity')
              .eq('barcode', scan.barcode)
              .single();

            if (item && scan.action === 'add') {
              // Update item quantity
              const newQuantity = item.quantity + (scan.quantity || 0);
              await supabase
                .from('items')
                .update({ 
                  quantity: newQuantity,
                  last_scanned_at: new Date().toISOString(),
                })
                .eq('id', item.id);

              // Create transaction
              await supabase
                .from('inventory_transactions')
                .insert({
                  item_id: item.id,
                  type: 'add',
                  quantity_change: scan.quantity || 0,
                  notes: 'Stock adjustment via scanner (offline sync)',
                  created_by: (await supabase.auth.getUser()).data.user?.id,
                  scan_source: 'scanner',
                });
            } else if (item && scan.action === 'remove') {
              // Update item quantity
              const newQuantity = item.quantity - (scan.quantity || 0);
              if (newQuantity >= 0) {
                await supabase
                  .from('items')
                  .update({ 
                    quantity: newQuantity,
                    last_scanned_at: new Date().toISOString(),
                  })
                  .eq('id', item.id);

                // Create transaction
                await supabase
                  .from('inventory_transactions')
                  .insert({
                    item_id: item.id,
                    type: 'remove',
                    quantity_change: -(scan.quantity || 0),
                    notes: 'Stock adjustment via scanner (offline sync)',
                    created_by: (await supabase.auth.getUser()).data.user?.id,
                    scan_source: 'scanner',
                  });
              }
            }

            // Mark as synced
            await indexedDB.markScanSynced(scan.id);
          } catch (error) {
            console.error('Error syncing scan:', scan, error);
          }
        }

        // Clear synced scans
        await indexedDB.clearSyncedScans();

        setSyncStatus('idle');
      } catch (error) {
        console.error('Error syncing pending scans:', error);
        setSyncStatus('error');
      }
    };

    syncPendingScans();
  }, [isOffline]);

  // Update pending count
  useEffect(() => {
    const updatePendingCount = async () => {
      const unsyncedScans = await indexedDB.getUnsyncedScans();
      setPendingCount(unsyncedScans.length);
    };

    updatePendingCount();

    // Update count periodically
    const interval = setInterval(updatePendingCount, 5000);

    return () => clearInterval(interval);
  }, []);

  return {
    syncStatus,
    pendingCount,
    isOffline,
  };
}
