import { useEffect, useState } from 'react';
import { supabase, Database } from '../lib/supabase';
import { useAuth } from './use-auth';

type BoardPresence = Database['public']['Tables']['board_presence']['Row'];

export function useBoardPresence(boardId: string = 'default') {
  const { user } = useAuth();
  const [presence, setPresence] = useState<BoardPresence[]>([]);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);

  useEffect(() => {
    if (!user) return;

    setCurrentUserId(user.id);

    // Join presence channel
    const channel = supabase
      .channel(`board_presence:${boardId}`)
      .on('presence', { event: 'sync' }, () => {
        const state = channel.presenceState();
        const users = Object.values(state).flat() as any[];
        setPresence(users.map((u: any) => ({
          id: u.user_id,
          user_id: u.user_id,
          board_id: u.board_id,
          last_seen: u.last_seen,
        })));
      })
      .on('presence', { event: 'join' }, ({ newPresences }) => {
        console.log('User joined:', newPresences);
      })
      .on('presence', { event: 'leave' }, ({ leftPresences }) => {
        console.log('User left:', leftPresences);
      })
      .subscribe(async (status) => {
        if (status === 'SUBSCRIBED') {
          // Track own presence
          await supabase
            .from('board_presence')
            .upsert({
              user_id: user.id,
              board_id: boardId,
              last_seen: new Date().toISOString(),
            }, {
              onConflict: 'user_id,board_id'
            });

          // Track presence in channel
          await channel.track({
            user_id: user.id,
            board_id: boardId,
            last_seen: new Date().toISOString(),
          });
        }
      });

    // Cleanup on unmount
    return () => {
      supabase
        .from('board_presence')
        .delete()
        .eq('user_id', user.id)
        .eq('board_id', boardId)
        .then(() => {
          supabase.removeChannel(channel);
        });
    };
  }, [user, boardId]);

  // Update last_seen periodically
  useEffect(() => {
    if (!user || !boardId) return;

    const interval = setInterval(async () => {
      await supabase
        .from('board_presence')
        .update({ last_seen: new Date().toISOString() })
        .eq('user_id', user.id)
        .eq('board_id', boardId);
    }, 30000); // Every 30 seconds

    return () => clearInterval(interval);
  }, [user, boardId]);

  return {
    presence,
    currentUserId,
  };
}
