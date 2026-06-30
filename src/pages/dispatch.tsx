import { useState, useEffect } from 'react';
import { KanbanBoard } from '../components/dispatch/KanbanBoard';
import { PresenceIndicator } from '../components/dispatch/PresenceIndicator';
import { MobileTaskList } from '../components/dispatch/MobileTaskList';
import { useBoardPresence } from '../hooks/use-board-presence';
import { useTasks } from '../hooks/use-tasks';
import { useProfile } from '../hooks/use-profile';
import { useAuth } from '../hooks/use-auth';

export default function Dispatch() {
  const { presence, currentUserId } = useBoardPresence('default');
  const { tasks, updateTask } = useTasks();
  const { user } = useAuth();
  const { data: profile } = useProfile(user?.id);
  const [isMobile, setIsMobile] = useState(false);

  // Detect mobile screen size
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Filter tasks based on role
  const filteredTasks = tasks.filter((task) => {
    if (profile?.role === 'driver') {
      // Drivers only see assigned tasks
      return task.assigned_to === user?.id;
    }
    if (profile?.role === 'staff') {
      // Staff see own tasks and all tasks (for visibility)
      return task.created_by === user?.id || task.assigned_to === user?.id;
    }
    // Admin/dispatcher see all tasks
    return true;
  });

  const handleStatusUpdate = async (taskId: string, newStatus: any) => {
    try {
      await updateTask.mutateAsync({ id: taskId, status: newStatus });
    } catch (error) {
      console.error('Failed to update task status:', error);
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header with presence indicator */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Dispatch Board</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {isMobile ? 'Your assigned tasks' : 'Manage tasks, shipments, and assignments'}
          </p>
        </div>
        <PresenceIndicator presence={presence} currentUserId={currentUserId} />
      </div>

      {/* Mobile View */}
      {isMobile ? (
        <div className="flex-1 overflow-y-auto">
          <MobileTaskList
            tasks={filteredTasks}
            onStatusUpdate={handleStatusUpdate}
          />
        </div>
      ) : (
        /* Desktop Kanban Board */
        <div className="flex-1 overflow-hidden">
          <KanbanBoard />
        </div>
      )}
    </div>
  );
}
