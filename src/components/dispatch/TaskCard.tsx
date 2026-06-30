import React from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { User, Clock, AlertCircle, Package, Truck } from 'lucide-react';
import { Database } from '../../lib/supabase';

type Task = Database['public']['Tables']['tasks']['Row'] & {
  task_types: { name: string; color: string; icon: string | null } | null;
  assigned_to_profile: { username: string; role: string } | null;
  vehicles: { registration_number: string; type: string | null } | null;
};

interface TaskCardProps {
  task: Task;
  onClick?: () => void;
}

const priorityColors = {
  low: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  medium: 'bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300',
  urgent: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
};

const statusColors = {
  pending: 'bg-slate-500',
  assigned: 'bg-blue-500',
  in_progress: 'bg-yellow-500',
  blocked: 'bg-red-500',
  completed: 'bg-green-500',
};

export function TaskCard({ task, onClick }: TaskCardProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: task.id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };

  const getInitials = (username: string) => {
    return username
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const isOverdue = task.due_date && new Date(task.due_date) < new Date() && task.status !== 'completed';

  return (
    <div
      ref={setNodeRef}
      style={style}
      {...attributes}
      {...listeners}
      onClick={onClick}
      className="cursor-grab active:cursor-grabbing"
    >
      <Card className="p-3 hover:shadow-md transition-shadow bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700">
        <div className="space-y-2">
          {/* Header with type and priority */}
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 flex-1 min-w-0">
              {task.task_types?.icon && (
                <div 
                  className="w-6 h-6 rounded flex items-center justify-center text-xs"
                  style={{ backgroundColor: task.task_types.color + '20', color: task.task_types.color }}
                >
                  {task.task_types.icon === 'package' && <Package className="w-3 h-3" />}
                  {task.task_types.icon === 'truck' && <Truck className="w-3 h-3" />}
                  {task.task_types.icon === 'box' && <Package className="w-3 h-3" />}
                </div>
              )}
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400 truncate">
                {task.task_types?.name || 'General Task'}
              </span>
            </div>
            <Badge className={`text-[10px] px-1.5 py-0.5 ${priorityColors[task.priority]}`}>
              {task.priority}
            </Badge>
          </div>

          {/* Title */}
          <h4 className="text-sm font-medium text-slate-900 dark:text-white line-clamp-2">
            {task.title}
          </h4>

          {/* Description preview */}
          {task.description && (
            <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2">
              {task.description}
            </p>
          )}

          {/* Footer with assignee and vehicle */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-100 dark:border-slate-700">
            <div className="flex items-center gap-2">
              {task.assigned_to_profile ? (
                <div className="flex items-center gap-1.5">
                  <div className="w-5 h-5 rounded-full bg-blue-500 flex items-center justify-center text-[10px] font-medium text-white">
                    {getInitials(task.assigned_to_profile.username)}
                  </div>
                  <span className="text-xs text-slate-600 dark:text-slate-400 truncate max-w-[80px]">
                    {task.assigned_to_profile.username}
                  </span>
                </div>
              ) : (
                <div className="flex items-center gap-1.5 text-slate-400">
                  <User className="w-3.5 h-3.5" />
                  <span className="text-xs">Unassigned</span>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2">
              {task.vehicles && (
                <div className="flex items-center gap-1 text-slate-500 dark:text-slate-400">
                  <Truck className="w-3 h-3" />
                  <span className="text-[10px]">{task.vehicles.registration_number}</span>
                </div>
              )}
              
              {task.due_date && (
                <div className={`flex items-center gap-1 ${isOverdue ? 'text-red-500' : 'text-slate-500 dark:text-slate-400'}`}>
                  <Clock className="w-3 h-3" />
                  <span className="text-[10px]">
                    {new Date(task.due_date).toLocaleDateString()}
                  </span>
                  {isOverdue && <AlertCircle className="w-3 h-3" />}
                </div>
              )}
            </div>
          </div>

          {/* Status indicator bar */}
          <div className="h-1 rounded-full mt-2" style={{ backgroundColor: statusColors[task.status] }} />
        </div>
      </Card>
    </div>
  );
}
