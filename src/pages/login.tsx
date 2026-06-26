import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/use-auth';
import { useProfile } from '../hooks/use-profile';
import { useInventoryStore } from '../store/inventory-store';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { ShieldCheck, Loader2 } from 'lucide-react';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { signIn, user: authUser } = useAuth();
  const { data: profile } = useProfile(authUser?.id);
  const navigate = useNavigate();
  const setUser = useInventoryStore(state => state.setUser);

  // Sync profile data with local store when profile loads
  React.useEffect(() => {
    if (profile) {
      setUser({
        username: profile.username,
        role: profile.role,
        email: profile.email,
      });
      navigate('/dashboard');
    }
  }, [profile, setUser, navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { error: signInError } = await signIn(email, password);
      
      if (signInError) {
        setError(signInError.message);
        setLoading(false);
        return;
      }
    } catch (err) {
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-slate-50 dark:bg-slate-950">
      <Card className="w-full max-w-md p-6 sm:p-8 border border-slate-200/80 dark:border-slate-800/80 shadow-md">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-500/20 text-white font-extrabold text-xl tracking-wider mb-3">A</div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">Sign In to AIMS</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Enterprise Asset Infrastructure Management</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          {error && (
            <div className="p-3 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-red-800 dark:text-red-400 text-xs rounded-lg">
              {error}
            </div>
          )}
          
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">Email Address</label>
            <Input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="your@email.com" required />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">Password</label>
            <Input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" required />
          </div>
          
          <Button type="submit" className="w-full py-2.5 mt-2" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Authenticating...
              </>
            ) : (
              'Sign In'
            )}
          </Button>
        </form>

        <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800 flex gap-2 items-start text-xs text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/40 p-3 rounded-lg">
          <ShieldCheck className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-700 dark:text-slate-300">Supabase Auth:</span> Sign in with your Supabase account credentials. First-time users will be automatically assigned the 'staff' role.
          </div>
        </div>
      </Card>
    </div>
  );
}
