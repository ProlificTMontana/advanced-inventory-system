import { useState, useEffect } from 'react';
import { useScanner } from '../hooks/use-scanner';
import { Scanner } from '../components/scanner';
import { ScanResultCard } from '../components/scan-result-card';
import { Card } from '../components/ui/card';
import { Clock, Package, AlertCircle } from 'lucide-react';

export default function Scan() {
  const {
    handleScan,
    handleStockAdjustment,
    scannedBarcode,
    scanHistory,
  } = useScanner();

  const [showScanner, setShowScanner] = useState(true);
  const [scannedItem, setScannedItem] = useState<any>(null);
  const [batchMode, setBatchMode] = useState(false);
  const [handsFreeMode, setHandsFreeMode] = useState(false);

  // Load preferences from localStorage
  useEffect(() => {
    const savedBatchMode = localStorage.getItem('scan_batch_mode');
    const savedHandsFreeMode = localStorage.getItem('scan_hands_free_mode');
    
    if (savedBatchMode) setBatchMode(savedBatchMode === 'true');
    if (savedHandsFreeMode) setHandsFreeMode(savedHandsFreeMode === 'true');
  }, []);

  // Save preferences to localStorage
  useEffect(() => {
    localStorage.setItem('scan_batch_mode', batchMode.toString());
  }, [batchMode]);

  useEffect(() => {
    localStorage.setItem('scan_hands_free_mode', handsFreeMode.toString());
  }, [handsFreeMode]);

  const handleScanResult = async (barcode: string) => {
    try {
      const result = await handleScan(barcode);
      setScannedItem(result.item);
      setShowScanner(false);
    } catch (error) {
      console.error('Error handling scan:', error);
    }
  };

  const handleAdd = async (quantity: number) => {
    if (scannedItem) {
      try {
        await handleStockAdjustment(scannedItem.id, quantity, 'add');
        setScannedItem(null);
        if (handsFreeMode) {
          setShowScanner(true);
        }
      } catch (error) {
        console.error('Error adding stock:', error);
      }
    }
  };

  const handleRemove = async (quantity: number) => {
    if (scannedItem) {
      try {
        await handleStockAdjustment(scannedItem.id, quantity, 'remove');
        setScannedItem(null);
        if (handsFreeMode) {
          setShowScanner(true);
        }
      } catch (error) {
        console.error('Error removing stock:', error);
      }
    }
  };

  const handleCreateNew = (barcode: string) => {
    // For now, just close - would need to implement item creation form
    console.log('Create new item with barcode:', barcode);
    setScannedItem(null);
    setShowScanner(true);
  };

  const handleDismiss = () => {
    setScannedItem(null);
    setShowScanner(true);
  };

  const handleCloseResult = () => {
    setScannedItem(null);
    setShowScanner(true);
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      {showScanner ? (
        <Scanner
          onScan={handleScanResult}
          onClose={() => setShowScanner(false)}
          batchMode={batchMode}
          handsFreeMode={handsFreeMode}
          onBatchModeToggle={setBatchMode}
          onHandsFreeModeToggle={setHandsFreeMode}
        />
      ) : (
        <div className="p-4 md:p-8 max-w-4xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
                Barcode Scanner
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Scan items to view details and adjust inventory
              </p>
            </div>
            <button
              onClick={() => setShowScanner(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Open Scanner
            </button>
          </div>

          {/* Scan History */}
          <Card className="p-4 mb-6">
            <div className="flex items-center gap-2 mb-3">
              <Clock className="w-4 h-4 text-slate-500" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Recent Scans
              </h3>
            </div>
            {scanHistory.length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No scans yet. Start scanning items to build history.
              </p>
            ) : (
              <div className="space-y-2">
                {scanHistory.map((barcode, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-2 bg-slate-50 dark:bg-slate-800 rounded-lg"
                  >
                    <div className="flex items-center gap-2">
                      <Package className="w-4 h-4 text-slate-400" />
                      <span className="text-sm font-mono text-slate-700 dark:text-slate-300">
                        {barcode}
                      </span>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {index === 0 ? 'Just now' : `${index * 5}s ago`}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Scanner Settings */}
          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertCircle className="w-4 h-4 text-slate-500" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Scanner Settings
              </h3>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">
                    Batch Mode
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Scan multiple items continuously
                  </p>
                </div>
                <button
                  onClick={() => setBatchMode(!batchMode)}
                  className={`w-12 h-6 rounded-full transition-colors ${
                    batchMode ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-700'
                  }`}
                >
                  <div
                    className={`w-4 h-4 bg-white rounded-full transition-transform ${
                      batchMode ? 'translate-x-6' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>

              {batchMode && (
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">
                      Hands-Free Mode
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Auto-continue after each scan
                    </p>
                  </div>
                  <button
                    onClick={() => setHandsFreeMode(!handsFreeMode)}
                    className={`w-12 h-6 rounded-full transition-colors ${
                      handsFreeMode ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-700'
                    }`}
                  >
                    <div
                      className={`w-4 h-4 bg-white rounded-full transition-transform ${
                        handsFreeMode ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Scan Result Card */}
      {scannedItem !== null && scannedBarcode && (
        <ScanResultCard
          item={scannedItem}
          barcode={scannedBarcode}
          onAdd={handleAdd}
          onRemove={handleRemove}
          onCreateNew={handleCreateNew}
          onDismiss={handleDismiss}
          onClose={handleCloseResult}
        />
      )}
    </div>
  );
}
