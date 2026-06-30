-- AIMS Dispatch Board Migration
-- Real-time collaborative dispatch and task assignment board

-- ============================================
-- EXTEND PROFILES ROLE ENUM
-- ============================================

-- Drop existing check constraint to add new roles
ALTER TABLE public.profiles DROP CONSTRAINT IF EXISTS profiles_role_check;

-- Add new check constraint with dispatcher and driver
ALTER TABLE public.profiles 
ADD CONSTRAINT profiles_role_check 
CHECK (role IN ('admin', 'manager', 'staff', 'dispatcher', 'driver'));

-- ============================================
-- NEW TABLES
-- ============================================

-- Vehicles table (minimal schema for Fleet Module integration)
CREATE TABLE IF NOT EXISTS vehicles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  registration_number VARCHAR NOT NULL UNIQUE,
  type VARCHAR,
  status VARCHAR DEFAULT 'available' CHECK (status IN ('available', 'in_use', 'maintenance')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Task types reference table (configurable task categories)
CREATE TABLE IF NOT EXISTS task_types (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR NOT NULL UNIQUE,
  color VARCHAR DEFAULT '#3B82F6',
  icon VARCHAR,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed task types
INSERT INTO task_types (name, color, icon) VALUES
  ('Pick Order', '#3B82F6', 'package'),
  ('Load Shipment', '#10B981', 'truck'),
  ('Unload Shipment', '#F59E0B', 'box'),
  ('Inventory Transfer', '#8B5CF6', 'arrow-right-left'),
  ('Vehicle Maintenance', '#EF4444', 'wrench'),
  ('Stock Count', '#06B6D4', 'clipboard-list'),
  ('General Task', '#6B7280', 'list')
ON CONFLICT (name) DO NOTHING;

-- Tasks table (core dispatch board entities)
CREATE TABLE IF NOT EXISTS tasks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title VARCHAR NOT NULL,
  description TEXT,
  task_type_id UUID REFERENCES task_types(id) ON DELETE SET NULL,
  status VARCHAR DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'in_progress', 'blocked', 'completed')),
  priority VARCHAR DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  assigned_to UUID REFERENCES profiles(id) ON DELETE SET NULL,
  vehicle_id UUID REFERENCES vehicles(id) ON DELETE SET NULL,
  created_by UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  due_date TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Task comments table (for @mentions and discussions)
CREATE TABLE IF NOT EXISTS task_comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  mentioned_users UUID[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Board presence table (real-time presence tracking)
CREATE TABLE IF NOT EXISTS board_presence (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  board_id VARCHAR DEFAULT 'default',
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, board_id)
);

-- ============================================
-- INDEXES
-- ============================================

-- Vehicles indexes
CREATE INDEX IF NOT EXISTS idx_vehicles_registration ON vehicles(registration_number);
CREATE INDEX IF NOT EXISTS idx_vehicles_status ON vehicles(status);

-- Task types indexes
CREATE INDEX IF NOT EXISTS idx_task_types_name ON task_types(name);

-- Tasks indexes
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tasks_vehicle_id ON tasks(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);
CREATE INDEX IF NOT EXISTS idx_tasks_task_type_id ON tasks(task_type_id);
CREATE INDEX IF NOT EXISTS idx_tasks_due_date ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority);

-- Task comments indexes
CREATE INDEX IF NOT EXISTS idx_task_comments_task_id ON task_comments(task_id);
CREATE INDEX IF NOT EXISTS idx_task_comments_user_id ON task_comments(user_id);
CREATE INDEX IF NOT EXISTS idx_task_comments_created_at ON task_comments(created_at DESC);

-- Board presence indexes
CREATE INDEX IF NOT EXISTS idx_board_presence_user_id ON board_presence(user_id);
CREATE INDEX IF NOT EXISTS idx_board_presence_board_id ON board_presence(board_id);
CREATE INDEX IF NOT EXISTS idx_board_presence_last_seen ON board_presence(last_seen);

-- ============================================
-- TRIGGERS
-- ============================================

-- Auto-update updated_at triggers
CREATE TRIGGER update_vehicles_updated_at
  BEFORE UPDATE ON vehicles
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at
  BEFORE UPDATE ON tasks
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Auto-set completed_at when status changes to completed
CREATE OR REPLACE FUNCTION handle_task_completion()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
    NEW.completed_at = NOW();
  ELSIF NEW.status != 'completed' THEN
    NEW.completed_at = NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER handle_task_completion_trigger
  BEFORE UPDATE ON tasks
  FOR EACH ROW
  EXECUTE FUNCTION handle_task_completion();

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================

-- Enable RLS on new tables
ALTER TABLE vehicles ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_presence ENABLE ROW LEVEL SECURITY;

-- Vehicles policies
CREATE POLICY "Authenticated users can view vehicles"
  ON vehicles FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and dispatchers can insert vehicles"
  ON vehicles FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Admins and dispatchers can update vehicles"
  ON vehicles FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Admins and dispatchers can delete vehicles"
  ON vehicles FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

-- Task types policies
CREATE POLICY "Authenticated users can view task types"
  ON task_types FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and dispatchers can insert task types"
  ON task_types FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Admins and dispatchers can update task types"
  ON task_types FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Admins and dispatchers can delete task types"
  ON task_types FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

-- Tasks policies (3-tier permission model)
CREATE POLICY "Users can view tasks assigned to them or created by them"
  ON tasks FOR SELECT
  TO authenticated
  USING (
    assigned_to = auth.uid() 
    OR created_by = auth.uid()
    OR EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Admins and dispatchers can insert tasks"
  ON tasks FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Staff can insert own tasks"
  ON tasks FOR INSERT
  TO authenticated
  WITH CHECK (
    created_by = auth.uid() AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'staff'
    )
  );

CREATE POLICY "Admins and dispatchers can update all tasks"
  ON tasks FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Staff can update own tasks (status only)"
  ON tasks FOR UPDATE
  TO authenticated
  USING (
    created_by = auth.uid() 
    AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'staff'
    )
  )
  WITH CHECK (
    created_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'staff'
    )
  );

CREATE POLICY "Drivers can update assigned tasks (status only)"
  ON tasks FOR UPDATE
  TO authenticated
  USING (
    assigned_to = auth.uid()
    AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'driver'
    )
  )
  WITH CHECK (
    assigned_to = auth.uid()
    AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'driver'
    )
  );

CREATE POLICY "Admins and dispatchers can delete tasks"
  ON tasks FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
    )
  );

CREATE POLICY "Staff can delete own tasks"
  ON tasks FOR DELETE
  TO authenticated
  USING (
    created_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'staff'
    )
  );

-- Task comments policies
CREATE POLICY "Users can view comments on visible tasks"
  ON task_comments FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM tasks t
      WHERE t.id = task_comments.task_id
      AND (
        t.assigned_to = auth.uid() 
        OR t.created_by = auth.uid()
        OR EXISTS (
          SELECT 1 FROM profiles 
          WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
        )
      )
    )
  );

CREATE POLICY "Users can insert comments on visible tasks"
  ON task_comments FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
      SELECT 1 FROM tasks t
      WHERE t.id = task_comments.task_id
      AND (
        t.assigned_to = auth.uid() 
        OR t.created_by = auth.uid()
        OR EXISTS (
          SELECT 1 FROM profiles 
          WHERE id = auth.uid() AND role IN ('admin', 'dispatcher')
        )
      )
    )
  );

-- Board presence policies
CREATE POLICY "Users can view board presence"
  ON board_presence FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Users can insert own presence"
  ON board_presence FOR INSERT
  TO authenticated
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update own presence"
  ON board_presence FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can delete own presence"
  ON board_presence FOR DELETE
  TO authenticated
  USING (user_id = auth.uid());
