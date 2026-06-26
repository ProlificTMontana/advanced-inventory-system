-- AIMS PWA Database Schema Migration
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- TABLES
-- ============================================

-- Profiles table (linked to Supabase Auth)
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'staff')),
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Suppliers table
CREATE TABLE IF NOT EXISTS suppliers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  contact_email TEXT,
  contact_phone TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Items table
CREATE TABLE IF NOT EXISTS items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  sku TEXT NOT NULL UNIQUE,
  category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
  supplier_id UUID REFERENCES suppliers(id) ON DELETE SET NULL,
  quantity INTEGER NOT NULL DEFAULT 0,
  min_stock INTEGER NOT NULL DEFAULT 0,
  price NUMERIC NOT NULL DEFAULT 0,
  location TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Inventory transactions table
CREATE TABLE IF NOT EXISTS inventory_transactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('add', 'remove', 'adjust')),
  quantity_change INTEGER NOT NULL,
  notes TEXT,
  created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX IF NOT EXISTS idx_items_category ON items(category_id);
CREATE INDEX IF NOT EXISTS idx_items_supplier ON items(supplier_id);
CREATE INDEX IF NOT EXISTS idx_items_sku ON items(sku);
CREATE INDEX IF NOT EXISTS idx_transactions_item ON inventory_transactions(item_id);
CREATE INDEX IF NOT EXISTS idx_transactions_created_by ON inventory_transactions(created_by);

-- ============================================
-- TRIGGERS
-- ============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for items table
CREATE TRIGGER update_items_updated_at
  BEFORE UPDATE ON items
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================

-- Enable RLS on all tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_transactions ENABLE ROW LEVEL SECURITY;

-- ============================================
-- RLS POLICIES
-- ============================================

-- Profiles policies
CREATE POLICY "Users can view all profiles"
  ON profiles FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Admins can insert profiles"
  ON profiles FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

CREATE POLICY "Admins can delete profiles"
  ON profiles FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

-- Categories policies
CREATE POLICY "Authenticated users can view categories"
  ON categories FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert categories"
  ON categories FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can update categories"
  ON categories FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins can delete categories"
  ON categories FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

-- Suppliers policies
CREATE POLICY "Authenticated users can view suppliers"
  ON suppliers FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert suppliers"
  ON suppliers FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can update suppliers"
  ON suppliers FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins can delete suppliers"
  ON suppliers FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

-- Items policies
CREATE POLICY "Authenticated users can view items"
  ON items FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert items"
  ON items FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can update items"
  ON items FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can delete items"
  ON items FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Inventory transactions policies
CREATE POLICY "Authenticated users can view transactions"
  ON inventory_transactions FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert transactions"
  ON inventory_transactions FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- ============================================
-- SEED DATA
-- ============================================

-- Insert initial categories
INSERT INTO categories (name, description) VALUES
  ('Storage Assets', 'Racks, shelves, and storage equipment'),
  ('Hardware Hardware', 'Fasteners, casters, and hardware components'),
  ('Electronics', 'Scanners, devices, and electronic equipment'),
  ('Packaging Packaging', 'Wraps, boxes, and packaging materials'),
  ('Machinery Assets', 'Chargers, tools, and machinery')
ON CONFLICT DO NOTHING;

-- Insert initial suppliers
INSERT INTO suppliers (name, contact_email, contact_phone) VALUES
  ('Global Iron Co.', 'sales@globaliron.com', '+1-555-0101'),
  ('Titan Parts Inc.', 'orders@titanparts.com', '+1-555-0102'),
  ('LogiTech Logistics', 'support@logitechlogistics.com', '+1-555-0103'),
  ('WrapSupply Ltd.', 'info@wrapsupply.com', '+1-555-0104'),
  ('VoltPower Corp', 'sales@voltpower.com', '+1-555-0105')
ON CONFLICT DO NOTHING;

-- ============================================
-- SEED USERS (TEST ACCOUNTS)
-- ============================================
-- NOTE: These users need to be created via Supabase Dashboard or Auth API
-- Run the following SQL after creating users in Supabase Auth to set their profiles

-- Admin user: Sarah Jenkins
-- Email: s.jenkins@aimspwa.com
-- Password: AdminPassword123!
INSERT INTO profiles (id, username, role, email)
VALUES (
  (SELECT id FROM auth.users WHERE email = 's.jenkins@aimspwa.com' LIMIT 1),
  'Sarah Jenkins',
  'admin',
  's.jenkins@aimspwa.com'
) ON CONFLICT (id) DO UPDATE SET role = 'admin';

-- Manager user: Marcus Vance  
-- Email: m.vance@aimspwa.com
-- Password: ManagerPassword123!
INSERT INTO profiles (id, username, role, email)
VALUES (
  (SELECT id FROM auth.users WHERE email = 'm.vance@aimspwa.com' LIMIT 1),
  'Marcus Vance',
  'manager',
  'm.vance@aimspwa.com'
) ON CONFLICT (id) DO UPDATE SET role = 'manager';

-- Manager user: Amara Okafor
-- Email: a.okafor@aimspwa.com  
-- Password: ManagerPassword123!
INSERT INTO profiles (id, username, role, email)
VALUES (
  (SELECT id FROM auth.users WHERE email = 'a.okafor@aimspwa.com' LIMIT 1),
  'Amara Okafor',
  'manager',
  'a.okafor@aimspwa.com'
) ON CONFLICT (id) DO UPDATE SET role = 'manager';

-- Staff user: Elena Rostova
-- Email: e.rostova@aimspwa.com
-- Password: StaffPassword123!
INSERT INTO profiles (id, username, role, email)
VALUES (
  (SELECT id FROM auth.users WHERE email = 'e.rostova@aimspwa.com' LIMIT 1),
  'Elena Rostova',
  'staff',
  'e.rostova@aimspwa.com'
) ON CONFLICT (id) DO UPDATE SET role = 'staff';

-- Staff user: David Kim
-- Email: d.kim@aimspwa.com
-- Password: StaffPassword123!
INSERT INTO profiles (id, username, role, email)
VALUES (
  (SELECT id FROM auth.users WHERE email = 'd.kim@aimspwa.com' LIMIT 1),
  'David Kim',
  'staff',
  'd.kim@aimspwa.com'
) ON CONFLICT (id) DO UPDATE SET role = 'staff';

-- ============================================
-- FUNCTIONS FOR AUTOMATIC PROFILE CREATION
-- ============================================

-- Function to create profile on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, username, role, email)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'role', 'staff'),
    NEW.email
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create profile on signup
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();
