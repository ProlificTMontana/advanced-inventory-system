import { useState } from 'react';
import { Plus, Minus, Edit, Eye, X, Package, AlertCircle } from 'lucide-react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Input } from './ui/input';
import { Dialog } from './ui/dialog';

interface ScanResultCardProps {
  item: {
    id: string;
    name: string;
    sku: string;
    quantity: number;
    min_stock: number;
    location: string;
    barcode: string | null;
    category_name?: string;
    supplier_name?: string;
  } | null;
  barcode: string;
  onAdd?: (quantity: number) => void;
  onRemove?: (quantity: number) => void;
  onEdit?: () => void;
  onCreateNew?: (barcode: string) => void;
  onDismiss?: () => void;
  onClose?: () => void;
}

export function ScanResultCard({
  item,
  barcode,
  onAdd,
  onRemove,
  onEdit,
  onCreateNew,
  onDismiss,
  onClose,
}: ScanResultCardProps) {
  const [quantity, setQuantity] = useState(1);
  const [showLinkDialog, setShowLinkDialog] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isLowStock, setIsLowStock] = useState(false);

  useState(() => {
    if (item) {
      setIsLowStock(item.quantity <= item.min_stock);
    }
  });

  const handleAdd = () => {
    if (onAdd) {
      onAdd(quantity);
      setQuantity(1);
    }
  };

  const handleRemove = () => {
    if (onRemove) {
      onRemove(quantity);
      setQuantity(1);
    }
  };

  const handleCreateNew = () => {
    if (onCreateNew) {
      onCreateNew(barcode);
    }
  };


  if (!item) {
    // Unknown barcode - show options
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
        <Card className="w-full max-w-md p-6 bg-white dark:bg-slate-900">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                Unknown Barcode
              </h3>
              <p className="text-sm text-slate-500 dark:text-slate-400 font-mono mt-1">
                {barcode}
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="w-5 h-5" />
            </Button>
          </div>

          <div className="space-y-3">
            <Button
              onClick={handleCreateNew}
              className="w-full flex items-center gap-2"
              variant="primary"
            >
              <Plus className="w-4 h-4" />
              Create New Item
            </Button>

            <Button
              onClick={() => setShowLinkDialog(true)}
              className="w-full flex items-center gap-2"
              variant="secondary"
            >
              <Package className="w-4 h-4" />
              Link to Existing Item
            </Button>

            <Button
              onClick={onDismiss}
              className="w-full flex items-center gap-2"
              variant="ghost"
            >
              <X className="w-4 h-4" />
              Dismiss
            </Button>
          </div>

          {showLinkDialog && (
            <Dialog
              isOpen={showLinkDialog}
              onClose={() => setShowLinkDialog(false)}
              title="Link to Existing Item"
            >
              <div className="space-y-4">
                <Input
                  placeholder="Search by name or SKU..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                {/* This would need a search component - for now showing placeholder */}
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Search functionality to be implemented with item lookup
                </p>
                <div className="flex justify-end gap-2">
                  <Button variant="ghost" onClick={() => setShowLinkDialog(false)}>
                    Cancel
                  </Button>
                </div>
              </div>
            </Dialog>
          )}
        </Card>
      </div>
    );
  }

  // Known item - show item info card
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-md p-6 bg-white dark:bg-slate-900 animate-in fade-in slide-in-from-bottom-5">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                {item.name}
              </h3>
              {isLowStock && (
                <AlertCircle className="w-5 h-5 text-amber-500" />
              )}
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400 font-mono mt-1">
              SKU: {item.sku}
            </p>
            {item.barcode && (
              <p className="text-xs text-slate-400 dark:text-slate-500 font-mono">
                Barcode: {item.barcode}
              </p>
            )}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="w-5 h-5" />
          </Button>
        </div>

        {/* Item Details */}
        <div className="grid grid-cols-2 gap-3 mb-4 p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Quantity
            </p>
            <p className="text-lg font-semibold text-slate-900 dark:text-white">
              {item.quantity}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Min Stock
            </p>
            <p className="text-lg font-semibold text-slate-900 dark:text-white">
              {item.min_stock}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Location
            </p>
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {item.location}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Category
            </p>
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {item.category_name || 'N/A'}
            </p>
          </div>
        </div>

        {/* Quantity Adjustment */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex items-center border border-slate-200 dark:border-slate-800 rounded-lg">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setQuantity(Math.max(1, quantity - 1))}
              className="h-10 w-10"
            >
              <Minus className="w-4 h-4" />
            </Button>
            <Input
              type="number"
              value={quantity}
              onChange={(e) => setQuantity(Math.max(1, parseInt(e.target.value) || 1))}
              className="w-16 h-10 text-center border-0 rounded-none"
              min={1}
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setQuantity(quantity + 1)}
              className="h-10 w-10"
            >
              <Plus className="w-4 h-4" />
            </Button>
          </div>
          <span className="text-sm text-slate-500 dark:text-slate-400">
            units to adjust
          </span>
        </div>

        {/* Action Buttons */}
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <Button
              onClick={handleAdd}
              className="flex items-center gap-2"
              variant="primary"
            >
              <Plus className="w-4 h-4" />
              Add {quantity}
            </Button>
            <Button
              onClick={handleRemove}
              className="flex items-center gap-2"
              variant="danger"
            >
              <Minus className="w-4 h-4" />
              Remove {quantity}
            </Button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Button
              onClick={onEdit}
              className="flex items-center gap-2"
              variant="secondary"
            >
              <Edit className="w-4 h-4" />
              Edit Item
            </Button>
            <Button
              onClick={onClose}
              className="flex items-center gap-2"
              variant="ghost"
            >
              <Eye className="w-4 h-4" />
              View Details
            </Button>
          </div>
        </div>

        {/* Success indicator */}
        {isLowStock && (
          <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-lg flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5" />
            <p className="text-xs text-amber-800 dark:text-amber-200">
              This item is below minimum stock level. Consider reordering.
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}
