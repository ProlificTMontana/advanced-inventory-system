import { useDroppable } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { Plus, MoreHorizontal } from 'lucide-react';
import { Button } from '../ui/button';
import { TaskCard } from './TaskCard';
import { Database } from '../../lib/supabase';

type Task = Database['public']['Tables']['tasks']['Row'] & {
  task_types: { name: string; color: string; icon: string | null } | null;
  assigned_to_profile: { username: string; role: string } | null;
  vehicles: { registration_number: string; type: string | null } | null;
};

interface KanbanColumnProps {
  id: string;
  title: string;
  tasks: Task[];
  onAddTask?: () => void;
  onTaskClick?: (task: Task) => void;
}

const columnColors = {
  pending: 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-600',
  assigned: 'bg-blue-50 dark:bg-blue-950 border-blue-300 dark:border-blue-700',
  in_progress: 'bg-yellow-50 dark:bg-yellow-950 border-yellow-300 dark:border-yellow-700',
  blocked: 'bg-red-50 dark:bg-red-950 border-red-300 dark:border-red-700',
  completed: 'bg-green-50 dark:bg-green-950 border-green-300 dark:border-green-700',
};

export function KanbanColumn({ id, title, tasks, onAddTask, onTaskClick }: KanbanColumnProps) {
  const { setNodeRef } = useDroppable({ id });

  return (
    <div className="flex flex-col min-w-[280px] max-w-[320px] h-full">
      {/* Column Header */}
      <div className={`flex items-center justify-between px-3 py-2 rounded-t-lg border-b-2 ${columnColors[id as keyof typeof columnColors]}`}>
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
          <span className="text-xs font-medium text-slate-600 dark:text-slate-400 bg-white dark:bg-slate-700 px-2 py-0.5 rounded-full">
            {tasks.length}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant="ghost"
            className="h-6 w-6 p-0"
            onClick={onAddTask}
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-6 w-6 p-0"
          >
            <MoreHorizontal className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Column Body */}
      <div
        ref={setNodeRef}
        className={`flex-1 overflow-y-auto p-3 space-y-3 rounded-b-lg border border-t-0 ${columnColors[id as keyof typeof columnColors].replace('border-b-2', 'border')} min-h-[200px]`}
      >
        <SortableContext items={tasks.map(t => t.id)} strategy={verticalListSortingStrategy}>
          {tasks.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              onClick={() => onTaskClick?.(task)}
            />
          ))}
        </SortableContext>
        
        {tasks.length === 0 && (
          <div className="flex items-center justify-center h-24 text-sm text-slate-400 dark:text-slate-500 border-2 border-dashed border-slate-300 dark:border-slate-600 rounded-lg">
            No tasks
          </div>
        )}
      </div>
    </div>
  );
}
