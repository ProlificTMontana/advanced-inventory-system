import { Database } from '../../lib/supabase';

type BoardPresence = Database['public']['Tables']['board_presence']['Row'];

interface PresenceIndicatorProps {
  presence: BoardPresence[];
  currentUserId: string | null;
}

export function PresenceIndicator({ presence, currentUserId }: PresenceIndicatorProps) {
  const getInitials = (userId: string) => {
    // In a real app, you'd fetch the username from profiles
    return userId.slice(0, 2).toUpperCase();
  };

  const activeUsers = presence.filter((p) => {
    const lastSeen = new Date(p.last_seen);
    const now = new Date();
    const diffMs = now.getTime() - lastSeen.getTime();
    const diffMins = diffMs / 60000;
    return diffMins < 5; // Consider active if seen within 5 minutes
  });

  return (
    <div className="flex items-center gap-2">
      <div className="flex -space-x-2">
        {activeUsers.map((p) => (
          <div
            key={p.user_id}
            className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium border-2 border-white dark:border-slate-900 ${
              p.user_id === currentUserId
                ? 'bg-blue-500 text-white'
                : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
            }`}
            title={p.user_id === currentUserId ? 'You' : `User ${getInitials(p.user_id)}`}
          >
            {getInitials(p.user_id)}
          </div>
        ))}
      </div>
      {activeUsers.length > 0 && (
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {activeUsers.length} {activeUsers.length === 1 ? 'person' : 'people'} viewing
        </span>
      )}
    </div>
  );
}
