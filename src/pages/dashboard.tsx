import { useItems } from '../hooks/use-items';
import { useTransactions } from '../hooks/use-transactions';
import { Card } from '../components/ui/card';
import { AlertsWidget } from '../components/alerts-widget';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Boxes, AlertTriangle, Activity, Layers } from 'lucide-react';

export default function Dashboard() {
  const { items } = useItems();
  const { transactions } = useTransactions();

  // Compute telemetry primitives
  const totalItems = items.reduce((acc, curr) => acc + curr.quantity, 0);
  const lowStockAlerts = items.filter(item => item.quantity <= item.min_stock).length;
  const totalValuation = items.reduce((acc, curr) => acc + (curr.quantity * curr.price), 0);
  
  const categoryMap = items.reduce((acc: Record<string, number>, item) => {
    const categoryName = item.categories?.name || 'Uncategorized';
    acc[categoryName] = (acc[categoryName] || 0) + item.quantity;
    return acc;
  }, {});

  const pieData = Object.keys(categoryMap).map(key => ({ name: key, value: categoryMap[key] }));
  const barData = items.map(item => ({ name: item.name.substring(0, 12) + '...', Stock: item.quantity, Min: item.min_stock }));

  const COLORS = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">System Telemetry</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">Real-time telemetry overview of stock, fulfillment velocity, and thresholds.</p>
      </div>

      {/* Grid KPI Dashboard */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { title: "Aggregate Units", val: totalItems, icon: Boxes, color: "text-blue-600 bg-blue-50 dark:bg-blue-950/40" },
          { title: "Threshold Breaches", val: lowStockAlerts, icon: AlertTriangle, color: lowStockAlerts > 0 ? "text-amber-500 bg-amber-50 dark:bg-amber-950/40" : "text-slate-400 bg-slate-50" },
          { title: "Asset Valuation", val: `$${totalValuation.toLocaleString(undefined, { minimumFractionDigits: 2 })}`, icon: Activity, color: "text-emerald-500 bg-emerald-50 dark:bg-emerald-950/40" },
          { title: "Class Specifications", val: pieData.length, icon: Layers, color: "text-purple-500 bg-purple-50 dark:bg-purple-950/40" },
        ].map((kpi, idx) => (
          <Card key={idx} className="p-4 flex items-center justify-between">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">{kpi.title}</p>
              <h3 className="text-lg sm:text-2xl font-bold text-slate-900 dark:text-white mt-1">{kpi.val}</h3>
            </div>
            <div className={`p-2.5 rounded-xl ${kpi.color}`}>
              <kpi.icon className="w-5 h-5" />
            </div>
          </Card>
        ))}
      </div>

      {/* Data Visualization Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-4 lg:col-span-2">
          <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-4">Stock Disparity Evaluation</h4>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#E2E8F0" />
                <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="#94A3B8" />
                <YAxis tick={{ fontSize: 10 }} stroke="#94A3B8" />
                <Tooltip />
                <Bar dataKey="Stock" fill="#2563EB" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <AlertsWidget />
      </div>

      {/* Category Dispersion */}
      <Card className="p-4">
        <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-4">Category Dispersion</h4>
        <div className="flex flex-col md:flex-row gap-6">
          <div className="h-48 w-full md:w-48 relative flex items-center justify-center shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} innerRadius={50} outerRadius={70} paddingAngle={3} dataKey="value">
                  {pieData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex-1 space-y-1.5 max-h-48 overflow-y-auto">
            {pieData.map((d, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 truncate">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                  <span className="text-slate-600 dark:text-slate-400 truncate">{d.name}</span>
                </div>
                <span className="font-semibold text-slate-800 dark:text-slate-200">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* System Transaction Logs */}
      <Card className="p-4">
        <h4 className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-4">System Transaction Ledger</h4>
        <div className="space-y-3">
          {transactions.slice(0, 4).map((tx) => (
            <div key={tx.id} className="flex items-start justify-between p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/40 dark:bg-slate-900/40 text-xs">
              <div className="space-y-0.5">
                <p className="font-medium text-slate-900 dark:text-white">{tx.items?.name || 'Unknown Item'}</p>
                <p className="text-slate-500 dark:text-slate-400">{tx.notes || 'No notes'}</p>
              </div>
              <div className="text-right shrink-0">
                <span className={`inline-block font-semibold px-2 py-0.5 rounded ${
                  tx.type === 'add' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-400' : 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-400'
                }`}>
                  {tx.quantity_change > 0 ? `+${tx.quantity_change}` : tx.quantity_change}
                </span>
                <p className="text-[10px] text-slate-400 mt-1">{new Date(tx.created_at).toLocaleTimeString()}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
