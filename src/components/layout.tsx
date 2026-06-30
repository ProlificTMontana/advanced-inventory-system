import React from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Boxes, FileBarChart, Settings as SettingsIcon, ShoppingCart, Truck, LogOut, Sun, Moon } from 'lucide-react';
import { useAuth } from '../hooks/use-auth';
import { useProfile } from '../hooks/use-profile';
import { useInventoryStore } from '../store/inventory-store';
import { useTheme } from '../context/theme-context';
import { NotificationCenter } from './notification-center';

export default function Layout() {
  const { user: authUser, signOut } = useAuth();
  const { data: profile } = useProfile(authUser?.id);
  const { setUser } = useInventoryStore();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut();
    setUser(null);
    navigate('/login');
  };

  // Sync profile data with local store
  React.useEffect(() => {
    if (profile) {
      setUser({
        username: profile.username,
        role: profile.role,
        email: profile.email,
      });
    }
  }, [profile, setUser]);

  if (!authUser) {
    return <Link to="/login" replace />;
  }

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/items', label: 'Inventory', icon: Boxes },
    { path: '/dispatch', label: 'Dispatch', icon: Truck },
    { path: '/reorder-requests', label: 'Reorders', icon: ShoppingCart },
    { path: '/reports', label: 'Analytics', icon: FileBarChart },
    { path: '/settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col md:flex-row">
      {/* Structural Navigation Sidebar */}
      <aside className="w-full md:w-64 bg-white dark:bg-slate-900 border-b md:border-b-0 md:border-r border-slate-200 dark:border-slate-800 flex flex-col justify-between shrink-0">
        <div className="p-4">
          <div className="flex items-center justify-between mb-6 px-2">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white text-sm tracking-wider">A</div>
              <span className="font-bold text-lg text-slate-900 dark:text-white tracking-tight">AIMS PWA</span>
            </div>
            <div className="flex items-center gap-2">
              <NotificationCenter />
              <button onClick={toggleTheme} className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800">
                {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-lg transition-colors ${
                    isActive 
                      ? 'bg-blue-50 text-blue-600 dark:bg-blue-950/40 dark:text-blue-400' 
                      : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm font-medium text-slate-900 dark:text-white truncate">{profile?.username || 'User'}</p>
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 mt-0.5">
              {profile?.role || 'staff'}
            </span>
          </div>
          <button onClick={handleLogout} className="p-2 text-slate-400 hover:text-red-500 dark:hover:text-red-400 rounded-lg transition-colors">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Primary Context Viewport */}
      <main className="flex-1 p-4 md:p-8 max-w-7xl mx-auto w-full overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
