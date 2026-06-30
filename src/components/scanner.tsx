import { useEffect, useRef, useState } from 'react';
import { BrowserMultiFormatReader, NotFoundException } from '@zxing/library';
import { CameraOff, Flashlight, FlashlightOff, X, Loader2 } from 'lucide-react';
import { Button } from './ui/button';

interface ScannerProps {
  onScan: (barcode: string) => void;
  onClose: () => void;
  batchMode?: boolean;
  handsFreeMode?: boolean;
  onBatchModeToggle?: (enabled: boolean) => void;
  onHandsFreeModeToggle?: (enabled: boolean) => void;
}

export function Scanner({
  onScan,
  onClose,
  batchMode = false,
  handsFreeMode = false,
  onBatchModeToggle,
  onHandsFreeModeToggle,
}: ScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const readerRef = useRef<BrowserMultiFormatReader | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [hasCamera, setHasCamera] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [torchEnabled, setTorchEnabled] = useState(false);
  const [lastScannedBarcode, setLastScannedBarcode] = useState<string | null>(null);
  const [scanCooldown, setScanCooldown] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);

  // Sound effect for successful scan
  const playScanSound = () => {
    try {
      const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.frequency.value = 1000;
      oscillator.type = 'sine';
      gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
      
      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + 0.1);
    } catch (error) {
      console.error('Error playing scan sound:', error);
    }
  };

  // Haptic feedback for successful scan
  const triggerHaptic = () => {
    if ('vibrate' in navigator) {
      navigator.vibrate(50);
    }
  };

  // Initialize camera
  useEffect(() => {
    const initCamera = async () => {
      setIsInitializing(true);
      try {
        // Check if camera is available
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoDevices = devices.filter(device => device.kind === 'videoinput');
        
        if (videoDevices.length === 0) {
          setCameraError('No camera found on this device');
          setHasCamera(false);
          setIsInitializing(false);
          return;
        }

        setHasCamera(true);

        // Initialize ZXing reader
        const reader = new BrowserMultiFormatReader();
        readerRef.current = reader;

        // Get video element
        const videoElement = videoRef.current;
        if (!videoElement) {
          setCameraError('Video element not found');
          setIsInitializing(false);
          return;
        }

        // Request camera access
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: 'environment',
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
        });

        videoElement.srcObject = stream;
        await videoElement.play();

        // Start decoding
        reader.decodeFromVideoDevice(null, videoElement, (result, error) => {
          if (result) {
            const barcode = result.getText();
            
            // Prevent duplicate scans in single mode
            if (!batchMode && barcode === lastScannedBarcode && scanCooldown) {
              return;
            }

            // Trigger scan callback
            onScan(barcode);
            setLastScannedBarcode(barcode);
            
            // Feedback
            playScanSound();
            triggerHaptic();

            // Set cooldown for single mode
            if (!batchMode) {
              setScanCooldown(true);
              setTimeout(() => {
                setScanCooldown(false);
                setLastScannedBarcode(null);
              }, 2000);
            } else if (handsFreeMode) {
              // Shorter cooldown for hands-free batch mode
              setScanCooldown(true);
              setTimeout(() => setScanCooldown(false), 500);
            }
          }

          if (error && !(error instanceof NotFoundException)) {
            console.error('Decode error:', error);
          }
        });

        setIsScanning(true);
        setIsInitializing(false);
      } catch (error) {
        console.error('Camera initialization error:', error);
        setCameraError('Failed to access camera. Please grant camera permissions.');
        setHasCamera(false);
        setIsInitializing(false);
      }
    };

    initCamera();

    return () => {
      if (readerRef.current) {
        readerRef.current.reset();
      }
      if (videoRef.current && videoRef.current.srcObject) {
        const stream = videoRef.current.srcObject as MediaStream;
        stream.getTracks().forEach(track => track.stop());
      }
    };
  }, [onScan, batchMode, handsFreeMode, lastScannedBarcode]);

  // Toggle torch (flashlight)
  const toggleTorch = async () => {
    if (!videoRef.current || !videoRef.current.srcObject) return;

    try {
      const stream = videoRef.current.srcObject as MediaStream;
      const videoTrack = stream.getVideoTracks()[0];
      
      const capabilities = videoTrack.getCapabilities() as any;
      if (capabilities?.torch) {
        const settings = videoTrack.getSettings();
        const newTorchState = !settings.torch;
        
        await videoTrack.applyConstraints({
          advanced: [{ torch: newTorchState }],
        } as any);
        
        setTorchEnabled(newTorchState);
      } else {
        console.warn('Torch not supported on this device');
      }
    } catch (error) {
      console.error('Error toggling torch:', error);
    }
  };

  if (cameraError) {
    return (
      <div className="fixed inset-0 bg-black flex items-center justify-center z-50">
        <div className="text-center p-6 max-w-sm">
          <CameraOff className="w-16 h-16 text-slate-500 mx-auto mb-4" />
          <h3 className="text-white text-lg font-semibold mb-2">Camera Error</h3>
          <p className="text-slate-400 text-sm mb-4">{cameraError}</p>
          <Button onClick={onClose} variant="secondary">
            Close
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col">
      {/* Header */}
      <div className="absolute top-0 left-0 right-0 z-10 bg-gradient-to-b from-black/80 to-transparent p-4">
        <div className="flex items-center justify-between">
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="text-white hover:bg-white/10"
          >
            <X className="w-6 h-6" />
          </Button>
          
          <div className="flex items-center gap-2">
            {hasCamera && (
              <Button
                variant="ghost"
                size="sm"
                onClick={toggleTorch}
                className="text-white hover:bg-white/10"
                title="Toggle Flashlight"
              >
                {torchEnabled ? (
                  <FlashlightOff className="w-6 h-6" />
                ) : (
                  <Flashlight className="w-6 h-6" />
                )}
              </Button>
            )}
            
            {onBatchModeToggle && (
              <Button
                variant={batchMode ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => onBatchModeToggle(!batchMode)}
                className={batchMode ? 'bg-blue-600 text-white' : 'text-white hover:bg-white/10'}
              >
                {batchMode ? 'Batch Mode' : 'Single Mode'}
              </Button>
            )}
            
            {onHandsFreeModeToggle && batchMode && (
              <Button
                variant={handsFreeMode ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => onHandsFreeModeToggle(!handsFreeMode)}
                className={handsFreeMode ? 'bg-blue-600 text-white' : 'text-white hover:bg-white/10'}
              >
                {handsFreeMode ? 'Hands-Free' : 'Manual'}
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Camera View */}
      <div className="flex-1 relative">
        {isInitializing && (
          <div className="absolute inset-0 flex items-center justify-center bg-black">
            <Loader2 className="w-8 h-8 text-white animate-spin" />
          </div>
        )}
        
        <video
          ref={videoRef}
          className="w-full h-full object-cover"
          playsInline
          muted
        />
        
        {/* Scan Overlay */}
        {isScanning && !isInitializing && (
          <div className="absolute inset-0 pointer-events-none">
            {/* Scan Frame */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-64 h-64 border-2 border-white/50 rounded-lg relative">
                {/* Corner accents */}
                <div className="absolute top-0 left-0 w-8 h-8 border-t-4 border-l-4 border-blue-500 rounded-tl-lg" />
                <div className="absolute top-0 right-0 w-8 h-8 border-t-4 border-r-4 border-blue-500 rounded-tr-lg" />
                <div className="absolute bottom-0 left-0 w-8 h-8 border-b-4 border-l-4 border-blue-500 rounded-bl-lg" />
                <div className="absolute bottom-0 right-0 w-8 h-8 border-b-4 border-r-4 border-blue-500 rounded-br-lg" />
                
                {/* Scan line animation */}
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-blue-500 animate-[scan_2s_ease-in-out_infinite]" />
              </div>
            </div>
            
            {/* Instructions */}
            <div className="absolute bottom-24 left-0 right-0 text-center">
              <p className="text-white/80 text-sm font-medium">
                {batchMode ? 'Scan multiple items continuously' : 'Align barcode within frame'}
              </p>
              {handsFreeMode && (
                <p className="text-white/60 text-xs mt-1">Auto-continue after each scan</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="absolute bottom-0 left-0 right-0 z-10 bg-gradient-to-t from-black/80 to-transparent p-4">
        <div className="flex items-center justify-center gap-4">
          <div className="text-white/60 text-xs">
            {scanCooldown && !batchMode ? 'Wait 2s before next scan...' : 'Ready to scan'}
          </div>
        </div>
      </div>
    </div>
  );
}
