import { useState } from 'react';
import { ChevronRight, Clock, User, Truck, AlertCircle } from 'lucide-react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Database } from '../../lib/supabase';

type Task = Database['public']['Tables']['tasks']['Row'] & {
  task_types: { name: string; color: string; icon: string | null } | null;
  assigned_to_profile: { username: string; role: string } | null;
  vehicles: { registration_number: string; type: string | null } | null;
};

interface MobileTaskListProps {
  tasks: Task[];
  onTaskClick?: (task: Task) => void;
  onStatusUpdate?: (taskId: string, newStatus: Task['status']) => void;
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

export function MobileTaskList({ tasks, onTaskClick, onStatusUpdate }: MobileTaskListProps) {
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);

  const getInitials = (username: string) => {
    return username
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const isOverdue = (task: Task) => {
    return task.due_date && new Date(task.due_date) < new Date() && task.status !== 'completed';
  };

  return (
    <div className="space-y-3">
      {tasks.map((task) => (
        <Card
          key={task.id}
          className="p-4 bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700"
        >
          {/* Task Header */}
          <div
            className="flex items-start justify-between cursor-pointer"
            onClick={() => {
              setExpandedTaskId(expandedTaskId === task.id ? null : task.id);
              onTaskClick?.(task);
            }}
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Badge className={`text-[10px] ${priorityColors[task.priority]}`}>
                  {task.priority}
                </Badge>
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  {task.task_types?.name || 'General Task'}
                </span>
              </div>
              <h4 className="text-sm font-medium text-slate-900 dark:text-white truncate">
                {task.title}
              </h4>
            </div>
            <ChevronRight
              className={`w-5 h-5 text-slate-400 transition-transform ${
                expandedTaskId === task.id ? 'rotate-90' : ''
              }`}
            />
          </div>

          {/* Expanded Details */}
          {expandedTaskId === task.id && (
            <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-700 space-y-2">
              {/* Description */}
              {task.description && (
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  {task.description}
                </p>
              )}

              {/* Assignee */}
              <div className="flex items-center gap-2">
                {task.assigned_to_profile ? (
                  <div className="flex items-center gap-2">
                    <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-[10px] font-medium text-white">
                      {getInitials(task.assigned_to_profile.username)}
                    </div>
                    <span className="text-xs text-slate-600 dark:text-slate-400">
                      {task.assigned_to_profile.username}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1 text-slate-400">
                    <User className="w-3.5 h-3.5" />
                    <span className="text-xs">Unassigned</span>
                  </div>
                )}
              </div>

              {/* Vehicle */}
              {task.vehicles && (
                <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                  <Truck className="w-3.5 h-3.5" />
                  <span className="text-xs">{task.vehicles.registration_number}</span>
                </div>
              )}

              {/* Due Date */}
              {task.due_date && (
                <div className={`flex items-center gap-2 text-xs ${isOverdue(task) ? 'text-red-500' : 'text-slate-500 dark:text-slate-400'}`}>
                  <Clock className="w-3.5 h-3.5" />
                  <span>
                    Due: {new Date(task.due_date).toLocaleDateString()}
                  </span>
                  {isOverdue(task) && <AlertCircle className="w-3.5 h-3.5" />}
                </div>
              )}

              {/* Status Update Buttons (for drivers/staff) */}
              {onStatusUpdate && (
                <div className="flex gap-2 pt-2">
                  {task.status === 'pending' && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="flex-1 text-xs"
                      onClick={() => onStatusUpdate(task.id, 'in_progress')}
                    >
                      Start
                    </Button>
                  )}
                  {task.status === 'in_progress' && (
                    <>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="flex-1 text-xs"
                        onClick={() => onStatusUpdate(task.id, 'blocked')}
                      >
                        Block
                      </Button>
                      <Button
                        size="sm"
                        className="flex-1 text-xs"
                        onClick={() => onStatusUpdate(task.id, 'completed')}
                      >
                        Complete
                      </Button>
                    </>
                  )}
                  {task.status === 'blocked' && (
                    <Button
                      size="sm"
                      className="flex-1 text-xs"
                      onClick={() => onStatusUpdate(task.id, 'in_progress')}
                    >
                      Resume
                    </Button>
                  )}
                </div>
              )}

              {/* Status indicator bar */}
              <div className="h-1 rounded-full" style={{ backgroundColor: statusColors[task.status] }} />
            </div>
          )}
        </Card>
      ))}

      {tasks.length === 0 && (
        <div className="text-center py-8 text-slate-400 dark:text-slate-500">
          <p className="text-sm">No tasks to display</p>
        </div>
      )}
    </div>
  );
}
