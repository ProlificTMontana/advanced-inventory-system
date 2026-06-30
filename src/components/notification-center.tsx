import { useState } from 'react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { useStockAlerts } from '../hooks/use-stock-alerts';
import { Bell, X, Check, Clock } from 'lucide-react';

interface Notification {
  id: string;
  type: 'alert' | 'reorder' | 'info';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

export function NotificationCenter() {
  const { alerts } = useStockAlerts();
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  // Convert alerts to notifications
  const alertNotifications: Notification[] = alerts.map(alert => ({
    id: alert.id,
    type: 'alert' as const,
    title: `${alert.alert_tier.charAt(0).toUpperCase() + alert.alert_tier.slice(1)}: ${alert.items?.name}`,
    message: `Stock at ${alert.current_stock} (min: ${alert.min_stock})${alert.days_until_stockout ? `. Est. ${Math.floor(alert.days_until_stockout)} days until stockout` : ''}`,
    timestamp: alert.created_at,
    read: !!alert.acknowledged_at,
  }));

  const allNotifications = [...alertNotifications, ...notifications];
  const unreadCount = allNotifications.filter(n => !n.read).length;

  const markAsRead = (id: string) => {
    setNotifications(prev => 
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
  };

  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  return (
    <div className="relative">
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setIsOpen(!isOpen)}
        className="relative"
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
            {unreadCount}
          </span>
        )}
      </Button>

      {isOpen && (
        <>
          <div 
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />
          <Card className="absolute right-0 top-12 w-80 max-h-96 overflow-hidden z-50 shadow-xl">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h3 className="font-semibold text-slate-900 dark:text-white text-sm">
                Notifications
              </h3>
              {unreadCount > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={markAllAsRead}
                  className="text-xs"
                >
                  Mark all read
                </Button>
              )}
            </div>

            <div className="overflow-y-auto max-h-80">
              {allNotifications.length === 0 ? (
                <div className="p-8 text-center text-slate-400 dark:text-slate-500">
                  <Bell className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No notifications</p>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                  {allNotifications.map((notification) => (
                    <div
                      key={notification.id}
                      className={`p-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors ${
                        !notification.read ? 'bg-blue-50/50 dark:bg-blue-950/20' : ''
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="shrink-0">
                          {notification.type === 'alert' && (
                            <Clock className="w-4 h-4 text-amber-500" />
                          )}
                          {notification.type === 'reorder' && (
                            <Check className="w-4 h-4 text-blue-500" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            {notification.title}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            {notification.message}
                          </p>
                          <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">
                            {new Date(notification.timestamp).toLocaleString()}
                          </p>
                        </div>
                        {!notification.read && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => markAsRead(notification.id)}
                            className="shrink-0 h-6 w-6 p-0"
                          >
                            <X className="w-3 h-3" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
