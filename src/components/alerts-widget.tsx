import { useState } from 'react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { useStockAlerts } from '../hooks/use-stock-alerts';
import { useCreateReorderRequest } from '../hooks/use-reorder-requests';
import { AlertTriangle, Clock, ShoppingCart, Bell, BellOff, X } from 'lucide-react';

interface AlertTierConfig {
  label: string;
  color: string;
  bgColor: string;
  icon: React.ReactNode;
}

const alertTierConfig: Record<string, AlertTierConfig> = {
  warning: {
    label: 'Warning',
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-100 dark:bg-amber-950/40',
    icon: <Bell className="w-4 h-4" />,
  },
  critical: {
    label: 'Critical',
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-100 dark:bg-orange-950/40',
    icon: <AlertTriangle className="w-4 h-4" />,
  },
  emergency: {
    label: 'Emergency',
    color: 'text-red-600 dark:text-red-400',
    bgColor: 'bg-red-100 dark:bg-red-950/40',
    icon: <AlertTriangle className="w-4 h-4" />,
  },
};

export function AlertsWidget() {
  const { alerts, isLoading, evaluateAlerts } = useStockAlerts();
  const { createReorderFromAlert } = useCreateReorderRequest();
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);

  const handleReorder = async (alert: any) => {
    const suggestedQuantity = Math.ceil(
      (alert.items?.min_stock || 10) * 2 - (alert.items?.quantity || 0)
    );

    try {
      await createReorderFromAlert.mutateAsync({
        itemId: alert.item_id,
        supplierId: alert.items?.supplier_id || null,
        suggestedQuantity,
        notes: `Reorder for ${alert.items?.name} - Stock at ${alert.current_stock} (min: ${alert.min_stock})`,
      });
      setExpandedAlert(null);
    } catch (error) {
      console.error('Failed to create reorder request:', error);
    }
  };

  const handleRefresh = async () => {
    await evaluateAlerts.mutateAsync();
  };

  if (isLoading) {
    return (
      <Card className="p-4">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
        </div>
      </Card>
    );
  }

  const activeAlerts = alerts.filter(alert => !alert.resolved_at);

  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
          Stock Alerts
        </h4>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">{activeAlerts.length} active</span>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleRefresh}
            disabled={evaluateAlerts.isPending}
            className="h-7 px-2"
          >
            <Clock className="w-3 h-3" />
          </Button>
        </div>
      </div>

      {activeAlerts.length === 0 ? (
        <div className="text-center py-8 text-slate-400 dark:text-slate-500">
          <BellOff className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No active stock alerts</p>
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {activeAlerts.map((alert) => {
            const config = alertTierConfig[alert.alert_tier];
            const isExpanded = expandedAlert === alert.id;

            return (
              <div
                key={alert.id}
                className={`border rounded-lg transition-all ${
                  isExpanded 
                    ? 'border-slate-300 dark:border-slate-700 p-4' 
                    : 'border-slate-200 dark:border-slate-800 p-3'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color}`}>
                        {config.icon}
                        {config.label}
                      </span>
                      {alert.acknowledged_at && (
                        <span className="text-[10px] text-slate-400">Acknowledged</span>
                      )}
                    </div>
                    <h5 className="font-medium text-slate-900 dark:text-white text-sm truncate">
                      {alert.items?.name}
                    </h5>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {alert.items?.sku}
                    </p>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-lg font-bold text-slate-900 dark:text-white">
                      {alert.current_stock}
                    </div>
                    <div className="text-[10px] text-slate-400">/ {alert.min_stock} min</div>
                  </div>
                </div>

                {isExpanded && (
                  <div className="mt-4 space-y-3">
                    {/* Days to stockout */}
                    {alert.days_until_stockout !== null && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-600 dark:text-slate-400">
                          Est. days until stockout:
                        </span>
                        <span className={`font-semibold ${
                          alert.days_until_stockout <= 3 
                            ? 'text-red-600 dark:text-red-400' 
                            : alert.days_until_stockout <= 7 
                            ? 'text-amber-600 dark:text-amber-400'
                            : 'text-slate-900 dark:text-white'
                        }`}>
                          {Math.floor(alert.days_until_stockout)} days
                        </span>
                      </div>
                    )}

                    {/* Forecast info */}
                    {alert.forecasted_daily_usage !== null && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-600 dark:text-slate-400">
                          Avg. daily usage:
                        </span>
                        <span className="font-semibold text-slate-900 dark:text-white">
                          {alert.forecasted_daily_usage.toFixed(1)}/day
                        </span>
                      </div>
                    )}

                    {/* Supplier info */}
                    {alert.items?.suppliers && (
                      <div className="text-xs">
                        <span className="text-slate-600 dark:text-slate-400">Supplier: </span>
                        <span className="font-medium text-slate-900 dark:text-white">
                          {alert.items.suppliers.name}
                        </span>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex gap-2 pt-2">
                      <Button
                        size="sm"
                        onClick={() => handleReorder(alert)}
                        disabled={createReorderFromAlert.isPending}
                        className="flex-1"
                      >
                        <ShoppingCart className="w-3 h-3 mr-1" />
                        Reorder
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setExpandedAlert(null)}
                      >
                        <X className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                )}

                {!isExpanded && (
                  <button
                    onClick={() => setExpandedAlert(alert.id)}
                    className="mt-2 text-xs text-blue-600 dark:text-blue-400 hover:underline"
                  >
                    View details →
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Disclaimer */}
      <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800">
        <p className="text-[10px] text-slate-400 dark:text-slate-500">
          * Stockout projections are estimates based on historical usage patterns
        </p>
      </div>
    </Card>
  );
}
