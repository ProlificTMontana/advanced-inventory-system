import { useState } from 'react';
import {
  DndContext,
  DragEndEvent,
  DragOverlay,
  DragStartEvent,
  PointerSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import { Plus } from 'lucide-react';
import { Button } from '../ui/button';
import { KanbanColumn } from './KanbanColumn';
import { TaskCard } from './TaskCard';
import { useTasks, useTaskRealtime } from '../../hooks/use-tasks';
import { Database } from '../../lib/supabase';

type Task = Database['public']['Tables']['tasks']['Row'] & {
  task_types: { name: string; color: string; icon: string | null } | null;
  assigned_to_profile: { username: string; role: string } | null;
  vehicles: { registration_number: string; type: string | null } | null;
};

const COLUMNS = [
  { id: 'pending', title: 'Pending' },
  { id: 'assigned', title: 'Assigned' },
  { id: 'in_progress', title: 'In Progress' },
  { id: 'blocked', title: 'Blocked' },
  { id: 'completed', title: 'Completed' },
];

export function KanbanBoard() {
  const { tasks, updateTask } = useTasks();
  const [activeTask, setActiveTask] = useState<Task | null>(null);
  
  // Enable real-time sync
  useTaskRealtime();

  // Configure sensors for touch support
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    })
  );

  // Group tasks by status
  const tasksByStatus = COLUMNS.reduce((acc, column) => {
    acc[column.id] = tasks.filter((task) => task.status === column.id);
    return acc;
  }, {} as Record<string, Task[]>);

  const handleDragStart = (event: DragStartEvent) => {
    const { active } = event;
    const task = tasks.find((t) => t.id === active.id);
    if (task) {
      setActiveTask(task);
    }
  };

  const handleDragEnd = async (event: DragEndEvent) => {
    const { active, over } = event;
    setActiveTask(null);

    if (!over) return;

    const taskId = active.id as string;
    const overId = over.id as string;

    const task = tasks.find((t) => t.id === taskId);
    if (!task) return;

    // If dropped on a column
    if (COLUMNS.some((col) => col.id === overId)) {
      const newStatus = overId as Task['status'];
      
      if (task.status !== newStatus) {
        try {
          await updateTask.mutateAsync({
            id: taskId,
            status: newStatus,
          });
        } catch (error) {
          // Rollback on error
          console.error('Failed to update task status:', error);
          // TanStack Query will automatically refetch on error
        }
      }
    }
  };

  const handleAddTask = () => {
    // TODO: Open task creation dialog
    console.log('Add task clicked');
  };

  const handleTaskClick = (task: Task) => {
    // TODO: Open task details dialog
    console.log('Task clicked:', task);
  };

  return (
    <div className="h-full flex flex-col">
      {/* Board Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Dispatch Board</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Manage tasks, shipments, and assignments
          </p>
        </div>
        <Button onClick={handleAddTask}>
          <Plus className="w-4 h-4 mr-2" />
          New Task
        </Button>
      </div>

      {/* Kanban Board */}
      <DndContext
        sensors={sensors}
        onDragStart={handleDragStart}
        onDragEnd={handleDragEnd}
      >
        <div className="flex gap-4 overflow-x-auto pb-4 h-full">
          {COLUMNS.map((column) => (
            <KanbanColumn
              key={column.id}
              id={column.id}
              title={column.title}
              tasks={tasksByStatus[column.id] || []}
              onAddTask={handleAddTask}
              onTaskClick={handleTaskClick}
            />
          ))}
        </div>

        <DragOverlay>
          {activeTask && (
            <div className="rotate-3 opacity-90">
              <TaskCard task={activeTask} />
            </div>
          )}
        </DragOverlay>
      </DndContext>
    </div>
  );
}
