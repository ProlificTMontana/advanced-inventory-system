import { Link } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { BarChart3, Zap, ArrowRight, LayoutDashboard, Package, FileText, Settings, Truck, Warehouse, Star, Clock } from 'lucide-react';

export default function Landing() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-950 dark:to-slate-900">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16 md:py-24">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 text-sm font-medium">
            <Zap className="w-4 h-4" />
            Operations Management Platform
          </div>
          
          <h1 className="text-4xl md:text-6xl font-bold text-slate-900 dark:text-white tracking-tight">
            Unified Operations Management for
            <span className="block bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Warehouses & Fleet
            </span>
          </h1>
          
          <p className="text-lg md:text-xl text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
            One platform to manage inventory intelligence, dispatch operations, and fleet logistics. Scale your warehouse operations with real-time visibility and control.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
            <Link to="/login">
              <Button size="lg" className="text-base px-8 flex items-center gap-2">
                Request Demo <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link to="/login">
              <Button size="lg" variant="secondary" className="text-base px-8">
                Get Started Free
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Core Pillars Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">
              Three Pillars of Operations Excellence
            </h2>
            <p className="text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
              Built for warehouse operators who need complete visibility across inventory, dispatch, and fleet operations.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-blue-100 dark:bg-blue-950/40 rounded-lg flex items-center justify-center mb-4">
                <Warehouse className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Inventory Intelligence
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Real-time stock visibility, automated reorder points, and predictive analytics to keep your warehouse optimized.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-purple-100 dark:bg-purple-950/40 rounded-lg flex items-center justify-center mb-4">
                <BarChart3 className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Dispatch & Operations
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Streamline order fulfillment, track shipments, and coordinate warehouse operations from a single dashboard.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-green-100 dark:bg-green-950/40 rounded-lg flex items-center justify-center mb-4">
                <Truck className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Fleet Management
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Coming soon: Track vehicles, optimize routes, and manage driver logistics integrated with your warehouse data.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Social Proof Placeholder */}
      <div className="container mx-auto px-4 py-16 bg-white dark:bg-slate-900/50">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">
              Trusted by Operations Teams
            </h2>
            <p className="text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
              Join warehouses and distribution centers transforming their operations with AIMS.
            </p>
          </div>

          <div className="flex flex-wrap justify-center items-center gap-8 md:gap-12 opacity-60">
            <div className="flex items-center gap-2 text-slate-400">
              <Star className="w-6 h-6 fill-current" />
              <span className="font-semibold">Customer logos coming soon</span>
            </div>
          </div>
        </div>
      </div>

      {/* Platform Overview */}
      <div className="container mx-auto px-4 py-16">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">
              Platform Capabilities
            </h2>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="flex items-start gap-4 p-4 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
              <div className="w-10 h-10 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-center justify-center shrink-0">
                <LayoutDashboard className="w-5 h-5 text-slate-600 dark:text-slate-400" />
              </div>
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-white">Dashboard</h4>
                <p className="text-sm text-slate-600 dark:text-slate-400">Real-time overview</p>
              </div>
            </div>

            <div className="flex items-start gap-4 p-4 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
              <div className="w-10 h-10 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-center justify-center shrink-0">
                <Package className="w-5 h-5 text-slate-600 dark:text-slate-400" />
              </div>
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-white">Items</h4>
                <p className="text-sm text-slate-600 dark:text-slate-400">Full inventory control</p>
              </div>
            </div>

            <div className="flex items-start gap-4 p-4 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
              <div className="w-10 h-10 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-center justify-center shrink-0">
                <FileText className="w-5 h-5 text-slate-600 dark:text-slate-400" />
              </div>
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-white">Reports</h4>
                <p className="text-sm text-slate-600 dark:text-slate-400">Export & analytics</p>
              </div>
            </div>

            <div className="flex items-start gap-4 p-4 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
              <div className="w-10 h-10 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-center justify-center shrink-0">
                <Settings className="w-5 h-5 text-slate-600 dark:text-slate-400" />
              </div>
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-white">Settings</h4>
                <p className="text-sm text-slate-600 dark:text-slate-400">Team & configuration</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Roadmap Preview */}
      <div className="container mx-auto px-4 py-16 bg-white dark:bg-slate-900/50">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">
              Roadmap Preview
            </h2>
            <p className="text-slate-600 dark:text-slate-400">
              AIMS is evolving into a complete operations platform. Here's what's coming next.
            </p>
          </div>

          <div className="bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-800 dark:to-slate-900 rounded-xl p-8 border border-slate-300 dark:border-slate-700">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-blue-100 dark:bg-blue-950/40 rounded-lg flex items-center justify-center shrink-0">
                <Clock className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="text-xl font-bold text-slate-900 dark:text-white">Fleet Management</h3>
                  <span className="inline-flex items-center px-2 py-1 rounded-full bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 text-xs font-medium">
                    Coming Soon
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-400 mb-4">
                  Complete vehicle tracking, route optimization, and driver management integrated with your warehouse inventory and dispatch operations.
                </p>
                <div className="flex flex-wrap gap-2">
                  <span className="inline-flex items-center px-3 py-1 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm">
                    GPS Tracking
                  </span>
                  <span className="inline-flex items-center px-3 py-1 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm">
                    Route Optimization
                  </span>
                  <span className="inline-flex items-center px-3 py-1 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm">
                    Driver Management
                  </span>
                  <span className="inline-flex items-center px-3 py-1 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm">
                    Maintenance Scheduling
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="max-w-4xl mx-auto text-center">
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl p-8 md:p-12 text-white">
            <h2 className="text-3xl font-bold mb-4">
              Ready to Transform Your Operations?
            </h2>
            <p className="text-blue-100 mb-8 text-lg">
              Join warehouse operators scaling their business with unified inventory, dispatch, and fleet management.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/login">
                <Button size="lg" variant="secondary" className="text-base px-8 flex items-center gap-2">
                  Request Demo <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
              <Link to="/login">
                <Button size="lg" variant="secondary" className="text-base px-8 bg-white/10 hover:bg-white/20 text-white border-white/20">
                  Start Free Trial
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="container mx-auto px-4 py-8 border-t border-slate-200 dark:border-slate-800">
        <div className="max-w-6xl mx-auto text-center text-sm text-slate-600 dark:text-slate-400">
          <p>&copy; 2024 AIMS - Operations Management Platform for Warehousing & Fleet. Built for efficiency.</p>
        </div>
      </div>
    </div>
  );
}
