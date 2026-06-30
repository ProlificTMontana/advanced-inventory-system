-- AIMS Barcode Scanner Integration Migration
-- Run this in Supabase SQL Editor after the base migration

-- ============================================
-- ADD BARCODE COLUMNS TO ITEMS TABLE
-- ============================================

ALTER TABLE items ADD COLUMN IF NOT EXISTS barcode VARCHAR;
ALTER TABLE items ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMPTZ;

-- Create index for fast barcode lookups
CREATE INDEX IF NOT EXISTS idx_items_barcode ON items(barcode);

-- ============================================
-- ADD SCAN SOURCE TO TRANSACTIONS TABLE
-- ============================================

ALTER TABLE inventory_transactions ADD COLUMN IF NOT EXISTS scan_source TEXT;

-- ============================================
-- UPDATE RLS POLICIES FOR BARCODE UPDATES
-- ============================================

-- Allow admins and managers to update barcode field
CREATE POLICY "Admins and managers can update barcode"
  ON items FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Allow admins and managers to update last_scanned_at
CREATE POLICY "Admins and managers can update last_scanned_at"
  ON items FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Allow staff to update last_scanned_at (for scan tracking)
CREATE POLICY "Staff can update last_scanned_at"
  ON items FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'staff'
    )
  )
  WITH CHECK (
    -- Only allow updating last_scanned_at, not other fields
    -- This is enforced at the application level
    true
  );

-- ============================================
-- FUNCTION TO FIND ITEM BY BARCODE
-- ============================================

CREATE OR REPLACE FUNCTION find_item_by_barcode(p_barcode VARCHAR)
RETURNS TABLE(
  id UUID,
  name TEXT,
  sku TEXT,
  quantity INTEGER,
  min_stock INTEGER,
  location TEXT,
  barcode VARCHAR,
  category_name TEXT,
  supplier_name TEXT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    i.id,
    i.name,
    i.sku,
    i.quantity,
    i.min_stock,
    i.location,
    i.barcode,
    c.name as category_name,
    s.name as supplier_name
  FROM items i
  LEFT JOIN categories c ON i.category_id = c.id
  LEFT JOIN suppliers s ON i.supplier_id = s.id
  WHERE i.barcode = p_barcode;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGER TO UPDATE LAST_SCANNED_AT
-- ============================================

-- Function to update last_scanned_at
CREATE OR REPLACE FUNCTION update_last_scanned_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.last_scanned_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to call the function when barcode is scanned
-- This will be called by the application after a successful scan
-- The trigger is not automatically attached - it's called via a function
