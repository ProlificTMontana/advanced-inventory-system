import React, { useEffect } from 'react';
import { WifiOff } from 'lucide-react';
import { useInventoryStore } from '../store/inventory-store';

export default function OfflineBanner() {
  const { isOffline, setOfflineStatus } = useInventoryStore();

  useEffect(() => {
    const handleOnline = () => setOfflineStatus(false);
    const handleOffline = () => setOfflineStatus(true);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [setOfflineStatus]);

  if (!isOffline) return null;

  return (
    <div className="bg-amber-500 text-white text-xs font-medium py-1.5 px-4 text-center flex items-center justify-center gap-2 animate-slide-down sticky top-0 z-50">
      <WifiOff className="w-3.5 h-3.5" />
      <span>Working Offline. Local entries will sync automatically upon reconnection.</span>
    </div>
  );
}
