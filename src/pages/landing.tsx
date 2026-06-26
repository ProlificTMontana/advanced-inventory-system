import { Link } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { BarChart3, Zap, ArrowRight, LayoutDashboard, Package, FileText, Settings } from 'lucide-react';

export default function Landing() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-950 dark:to-slate-900">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16 md:py-24">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 text-sm font-medium">
            <Zap className="w-4 h-4" />
            Advanced Inventory Management System
          </div>
          
          <h1 className="text-4xl md:text-6xl font-bold text-slate-900 dark:text-white tracking-tight">
            Scale Your Business with
            <span className="block bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Intelligent Inventory Control
            </span>
          </h1>
          
          <p className="text-lg md:text-xl text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Navigate your inventory with ease. Access concise, insightful analytics that drive decision-making and improve team efficiency.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
            <Link to="/login">
              <Button size="lg" className="text-base px-8 flex items-center gap-2">
                Get Started <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link to="/login">
              <Button size="lg" variant="secondary" className="text-base px-8">
                View Demo
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">
              Why Choose AIMS?
            </h2>
            <p className="text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
              Built for businesses that need reliable, real-time inventory insights without the complexity.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-blue-100 dark:bg-blue-950/40 rounded-lg flex items-center justify-center mb-4">
                <LayoutDashboard className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Easy to Navigate
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Intuitive interface designed for quick access to all inventory data. No training required.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-purple-100 dark:bg-purple-950/40 rounded-lg flex items-center justify-center mb-4">
                <BarChart3 className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Concise Analytics
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Actionable insights at your fingertips. Make data-driven decisions instantly.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-xl p-6 shadow-lg border border-slate-200 dark:border-slate-800">
              <div className="w-12 h-12 bg-green-100 dark:bg-green-950/40 rounded-lg flex items-center justify-center mb-4">
                <Zap className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                Drive Efficiency
              </h3>
              <p className="text-slate-600 dark:text-slate-400">
                Streamline operations and empower your team with real-time inventory visibility.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Platform Overview */}
      <div className="container mx-auto px-4 py-16 bg-white dark:bg-slate-900/50">
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

      {/* CTA Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="max-w-4xl mx-auto text-center">
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl p-8 md:p-12 text-white">
            <h2 className="text-3xl font-bold mb-4">
              Ready to Transform Your Inventory Management?
            </h2>
            <p className="text-blue-100 mb-8 text-lg">
              Join businesses already scaling with AIMS. Start your journey today.
            </p>
            <Link to="/login">
              <Button size="lg" variant="secondary" className="text-base px-8 flex items-center gap-2 mx-auto">
                Start Free Trial <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="container mx-auto px-4 py-8 border-t border-slate-200 dark:border-slate-800">
        <div className="max-w-6xl mx-auto text-center text-sm text-slate-600 dark:text-slate-400">
          <p>&copy; 2024 AIMS - Advanced Inventory Management System. Built for efficiency.</p>
        </div>
      </div>
    </div>
  );
}
