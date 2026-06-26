import { useEffect, useState } from 'react';
import { Download, X } from 'lucide-react';
import { Button } from './ui/button';

export default function PWAPrompt() {
  const [deferredPrompt, setDeferredPrompt] = useState<any>(null);
  const [showPrompt, setShowPrompt] = useState(false);

  useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e);
      // Show prompt if user hasn't explicitly dismissed it this session
      if (!sessionStorage.getItem('aims-pwa-dismissed')) {
        setShowPrompt(true);
      }
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
  }, []);

  const handleInstall = async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      setDeferredPrompt(null);
    }
    setShowPrompt(false);
  };

  if (!showPrompt) return null;

  return (
    <div className="fixed bottom-4 right-4 max-w-sm bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-xl z-50 flex items-start gap-3 animate-in fade-in slide-in-from-bottom-5">
      <div className="p-2 bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 rounded-lg">
        <Download className="w-5 h-5" />
      </div>
      <div className="flex-1">
        <h4 className="text-sm font-semibold text-slate-900 dark:text-white">Install AIMS Engine</h4>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Add to home screen for native execution, persistence, and low-latency offline workflows.</p>
        <div className="flex items-center gap-2 mt-3">
          <Button size="sm" onClick={handleInstall}>Install Now</Button>
          <Button size="sm" variant="ghost" onClick={() => {
            setShowPrompt(false);
            sessionStorage.setItem('aims-pwa-dismissed', 'true');
          }}>Dismiss</Button>
        </div>
      </div>
      <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200" onClick={() => setShowPrompt(false)}>
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}
