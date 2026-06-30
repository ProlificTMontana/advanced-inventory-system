# AIMS Dispatch Board Testing Guide

This guide provides step-by-step instructions for testing the real-time collaborative dispatch board with concurrent edits, offline behavior, and role-based access control.

## Prerequisites

1. Run the base migration: `supabase-migrations.sql`
2. Run the dispatch migration: `supabase-dispatch-migration.sql`
3. Ensure you have test users with different roles (admin, dispatcher, staff, driver)
4. Start the development server: `npm run dev`

## Step 1: Database Migration Verification

### Verify Tables Created
Run these queries in Supabase SQL Editor to verify the new tables:

```sql
-- Check vehicles table
SELECT COUNT(*) FROM vehicles;

-- Check task_types table
SELECT COUNT(*) FROM task_types;

-- Check tasks table
SELECT COUNT(*) FROM tasks;

-- Check task_comments table
SELECT COUNT(*) FROM task_comments;

-- Check board_presence table
SELECT COUNT(*) FROM board_presence;
```

### Verify Role Extension
```sql
-- Check profiles role constraint
SELECT conname FROM pg_constraint WHERE conname = 'profiles_role_check';

-- Should allow: admin, manager, staff, dispatcher, driver
```

### Verify Seed Data
```sql
-- Check seeded task types
SELECT name, color, icon FROM task_types;
```

Expected: Pick Order, Load Shipment, Unload Shipment, Inventory Transfer, Vehicle Maintenance, Stock Count, General Task

## Step 2: Seed Test Data

### Create Test Vehicles
```sql
INSERT INTO vehicles (registration_number, type, status) VALUES
  ('TRK-001', 'truck', 'available'),
  ('TRK-002', 'truck', 'in_use'),
  ('VAN-001', 'van', 'available'),
  ('BUS-001', 'bus', 'maintenance');
```

### Create Test Users (if not exists)
```sql
-- Get existing user IDs or create new ones
-- You'll need these IDs for task assignment
SELECT id, username, role FROM profiles;
```

### Create Test Tasks
```sql
-- Get user IDs and vehicle IDs for foreign keys
DO $$
DECLARE
  v_dispatcher_id UUID := (SELECT id FROM profiles WHERE role = 'dispatcher' LIMIT 1);
  v_driver_id UUID := (SELECT id FROM profiles WHERE role = 'driver' LIMIT 1);
  v_vehicle_id UUID := (SELECT id FROM vehicles WHERE registration_number = 'TRK-001' LIMIT 1);
  v_pick_type_id UUID := (SELECT id FROM task_types WHERE name = 'Pick Order' LIMIT 1);
  v_load_type_id UUID := (SELECT id FROM task_types WHERE name = 'Load Shipment' LIMIT 1);
BEGIN
  -- Pending task
  INSERT INTO tasks (title, description, task_type_id, status, priority, created_by, due_date)
  VALUES (
    'Pick up order #12345',
    'Collect 50 units from warehouse A',
    v_pick_type_id,
    'pending',
    'medium',
    v_dispatcher_id,
    NOW() + INTERVAL '2 days'
  );

  -- Assigned task
  INSERT INTO tasks (title, description, task_type_id, status, priority, assigned_to, vehicle_id, created_by, due_date)
  VALUES (
    'Load shipment to distribution center',
    'Load 200 boxes onto truck for morning delivery',
    v_load_type_id,
    'assigned',
    'high',
    v_driver_id,
    v_vehicle_id,
    v_dispatcher_id,
    NOW() + INTERVAL '1 day'
  );

  -- In progress task
  INSERT INTO tasks (title, description, task_type_id, status, priority, assigned_to, created_by)
  VALUES (
    'Unload incoming shipment',
    'Unload pallets from dock 3',
    v_load_type_id,
    'in_progress',
    'medium',
    v_driver_id,
    v_dispatcher_id
  );

  -- Blocked task
  INSERT INTO tasks (title, description, task_type_id, status, priority, created_by)
  VALUES (
    'Vehicle maintenance required',
    'Forklift needs brake inspection',
    (SELECT id FROM task_types WHERE name = 'Vehicle Maintenance' LIMIT 1),
    'blocked',
    'urgent',
    v_dispatcher_id
  );

  -- Completed task
  INSERT INTO tasks (title, description, task_type_id, status, priority, created_by, completed_at)
  VALUES (
    'Stock count completed',
    'Weekly inventory audit',
    (SELECT id FROM task_types WHERE name = 'Stock Count' LIMIT 1),
    'completed',
    'low',
    v_dispatcher_id,
    NOW() - INTERVAL '1 hour'
  );
END $$;
```

## Step 3: Role-Based Access Control Testing

### Test Admin/Dispatcher Access
1. Login as admin or dispatcher user
2. Navigate to `/dispatch`
3. Verify:
   - All tasks are visible (pending, their own, others')
   - Can drag tasks between columns
   - Can create new tasks (New Task button)
   - Can delete tasks
   - Can assign tasks to any user
   - Can assign vehicles to tasks

### Test Staff Access
1. Login as staff user
2. Navigate to `/dispatch`
3. Verify:
   - Only own tasks are visible (created_by = current user)
   - Can drag own tasks between columns
   - Cannot create new tasks (New Task button should not work or be hidden)
   - Cannot delete tasks
   - Cannot assign tasks to others
   - Can only update status of own tasks

### Test Driver Access
1. Login as driver user
2. Navigate to `/dispatch`
3. Verify:
   - Only assigned tasks are visible (assigned_to = current user)
   - Can only update status (Start, Complete, Block buttons on mobile)
   - Cannot create new tasks
   - Cannot delete tasks
   - Cannot reassign tasks
   - On mobile, sees simplified list view with status buttons

### Test RLS Policies
```sql
-- Test that staff cannot see other users' tasks
-- Login as staff and run:
SELECT COUNT(*) FROM tasks WHERE created_by != (SELECT id FROM profiles WHERE email = 'your-staff@email.com');
-- Should return 0

-- Test that driver cannot see unassigned tasks
-- Login as driver and run:
SELECT COUNT(*) FROM tasks WHERE assigned_to IS NULL;
-- Should return 0
```

## Step 4: Real-Time Sync Testing

### Test Multi-User Sync
1. Open two browser windows
2. Login as dispatcher in Window A
3. Login as dispatcher in Window B
4. In Window A, drag a task from "Pending" to "Assigned"
5. In Window B, verify the task automatically moves to "Assigned"
6. Check browser console for "Realtime task change" logs

### Test Presence Indicator
1. Open three browser windows
2. Login as different users in each window
3. Navigate to `/dispatch` in all windows
4. Verify presence indicator shows 3 people viewing
5. Close one window
6. Verify presence indicator updates to 2 people within 30 seconds

### Test Conflict Resolution
1. Open two browser windows as same dispatcher
2. In Window A, drag Task X to "Completed"
3. Immediately in Window B, drag Task X to "Blocked"
4. Verify:
   - Last write wins (based on server timestamp)
   - Both windows eventually show the same state
   - No data corruption occurs

## Step 5: Drag-and-Drop Testing

### Desktop Drag-and-Drop
1. Navigate to `/dispatch` on desktop
2. Drag a task card from "Pending" to "Assigned"
3. Verify:
   - Card follows cursor smoothly
   - Drop zone highlights when hovering
   - Card snaps to new column
   - Task status updates in database
   - Real-time sync updates other users

### Mobile Touch Drag-and-Drop
1. Navigate to `/dispatch` on mobile device (or use browser dev tools mobile emulation)
2. Touch and hold a task card
3. Drag to another column
4. Verify:
   - Touch sensors work correctly
   - Card moves with finger
   - Drop zone highlights
   - Status updates on release

### Mobile List View
1. Resize browser to < 768px width
2. Verify:
   - Kanban board switches to list view
   - Tasks show as expandable cards
   - Tap to expand/collapse details
   - Status update buttons appear (Start, Complete, Block)
   - No drag-and-drop on mobile list view

## Step 6: Offline Behavior Testing

### Test PWA Offline Mode
1. Navigate to `/dispatch`
2. Open browser DevTools → Network tab
3. Check "Offline" to simulate no connection
4. Try to drag a task to a new column
5. Verify:
   - Optimistic UI update shows task moved
   - Error appears when sync fails
   - Task reverts to original position
   - Error message displayed to user

### Test Reconnection
1. While offline, move a task
2. Uncheck "Offline" to restore connection
3. Verify:
   - Queued changes sync automatically
   - Task shows correct final state
   - No duplicate tasks created

## Step 7: Task Assignment Notifications

### Test Assignment Notification
1. Login as dispatcher
2. Create a new task and assign it to a driver
3. Login as driver in another window
4. Verify:
   - Notification appears in NotificationCenter
   - Unread count badge shows
   - Notification shows task title and assigner

### Test @Mentions in Comments
1. Add a comment to a task with @username
2. Verify:
   - Mentioned user receives notification
   - Notification shows comment preview
   - Clicking notification navigates to task

## Step 8: Edge Cases

### Test No Tasks
1. Delete all tasks from database
2. Navigate to `/dispatch`
3. Verify:
   - "No tasks" message displays in each column
   - Board remains functional
   - Can still create new tasks (admin/dispatcher)

### Test Overdue Tasks
1. Create a task with due_date in the past
2. Verify:
   - Red warning icon appears on task card
   - Due date text is red
   - AlertCircle icon shows

### Test Vehicle Assignment
1. Create a task without vehicle
2. Verify:
   - Vehicle section doesn't appear on card
3. Assign a vehicle
4. Verify:
   - Vehicle registration number appears
   - Truck icon shows

### Test Task Type Colors
1. Create tasks with different task types
2. Verify:
   - Each task type has correct color
   - Icon displays correctly
   - Color matches seed data

## Step 9: Performance Testing

### Test Large Dataset
```sql
-- Create 100 test tasks
INSERT INTO tasks (title, description, task_type_id, status, priority, created_by)
SELECT 
  'Test Task ' || generate_series,
  'Description for test task ' || generate_series,
  (SELECT id FROM task_types LIMIT 1),
  CASE WHEN generate_series % 5 = 0 THEN 'pending'
       WHEN generate_series % 5 = 1 THEN 'assigned'
       WHEN generate_series % 5 = 2 THEN 'in_progress'
       WHEN generate_series % 5 = 3 THEN 'blocked'
       ELSE 'completed' END,
  CASE WHEN generate_series % 4 = 0 THEN 'low'
       WHEN generate_series % 4 = 1 THEN 'medium'
       WHEN generate_series % 4 = 2 THEN 'high'
       ELSE 'urgent' END,
  (SELECT id FROM profiles WHERE role = 'dispatcher' LIMIT 1)
FROM generate_series(1, 100);
```

Navigate to `/dispatch` and verify:
- Board loads within 2 seconds
- Drag-and-drop remains smooth
- No UI freezing or lag

### Test Real-Time Latency
1. Open two browser windows
2. Move a task in Window A
3. Measure time until Window B updates
4. Verify: Sync occurs within 1-2 seconds

## Step 10: Cleanup Test Data

```sql
-- Delete test tasks
DELETE FROM tasks WHERE title LIKE 'Test Task%' OR title LIKE 'Pick up%' OR title LIKE 'Load shipment%';

-- Delete test vehicles
DELETE FROM vehicles WHERE registration_number LIKE 'TRK-%' OR registration_number LIKE 'VAN-%' OR registration_number LIKE 'BUS-%';

-- Delete test comments
DELETE FROM task_comments WHERE task_id IN (SELECT id FROM tasks WHERE title LIKE 'Test Task%');

-- Clear presence
DELETE FROM board_presence;
```

## Expected Results Summary

- **Database**: All tables created with correct schema and RLS policies
- **Roles**: Admin/dispatcher have full access, staff limited to own tasks, drivers limited to assigned tasks
- **Real-time**: Changes sync across multiple browser sessions within 1-2 seconds
- **Presence**: Active users shown with avatars and count
- **Drag-and-drop**: Works smoothly on desktop and mobile touch
- **Mobile view**: Simplified list with status buttons for field staff
- **Offline**: Optimistic updates with rollback on error
- **Notifications**: Task assignments trigger in-app alerts
- **Performance**: Handles 100+ tasks without lag

## Troubleshooting

### Tasks Not Syncing
- Verify Supabase Realtime is enabled for the tasks table
- Check browser console for connection errors
- Ensure user has proper RLS permissions

### Drag-and-Drop Not Working
- Check @dnd-kit packages are installed
- Verify PointerSensor is configured correctly
- Check for CSS conflicts with drag overlay

### Presence Not Showing
- Verify presence channel subscription is successful
- Check board_presence table has records
- Ensure last_seen updates every 30 seconds

### Role Access Issues
- Verify RLS policies are enabled on all tables
- Check user role in profiles table
- Test policies directly in Supabase SQL Editor

### Mobile View Not Switching
- Verify window resize event listener is working
- Check isMobile state updates correctly
- Test with browser dev tools mobile emulation
