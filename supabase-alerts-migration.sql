-- AIMS Alert System Enhancement Migration
-- Run this in Supabase SQL Editor after the base migration

-- ============================================
-- NEW TABLES
-- ============================================

-- Stock alerts table for tracking low-stock alerts
CREATE TABLE IF NOT EXISTS stock_alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  alert_tier TEXT NOT NULL CHECK (alert_tier IN ('warning', 'critical', 'emergency')),
  current_stock INTEGER NOT NULL,
  min_stock INTEGER NOT NULL,
  days_until_stockout NUMERIC,
  forecasted_daily_usage NUMERIC,
  acknowledged_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
  acknowledged_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

-- Reorder requests table for tracking reorder intents
CREATE TABLE IF NOT EXISTS reorder_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  supplier_id UUID REFERENCES suppliers(id) ON DELETE SET NULL,
  requested_by UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  requested_quantity INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'ordered', 'received', 'cancelled')),
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert preferences table for per-user snooze/dismiss state
CREATE TABLE IF NOT EXISTS alert_preferences (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  item_id UUID REFERENCES items(id) ON DELETE CASCADE,
  alert_tier TEXT CHECK (alert_tier IN ('warning', 'critical', 'emergency')),
  is_snoozed BOOLEAN DEFAULT false,
  snoozed_until TIMESTAMPTZ,
  is_dismissed BOOLEAN DEFAULT false,
  dismissed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, item_id, alert_tier)
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX IF NOT EXISTS idx_stock_alerts_item ON stock_alerts(item_id);
CREATE INDEX IF NOT EXISTS idx_stock_alerts_tier ON stock_alerts(alert_tier);
CREATE INDEX IF NOT EXISTS idx_stock_alerts_created ON stock_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stock_alerts_resolved ON stock_alerts(resolved_at);

CREATE INDEX IF NOT EXISTS idx_reorder_requests_item ON reorder_requests(item_id);
CREATE INDEX IF NOT EXISTS idx_reorder_requests_supplier ON reorder_requests(supplier_id);
CREATE INDEX IF NOT EXISTS idx_reorder_requests_status ON reorder_requests(status);
CREATE INDEX IF NOT EXISTS idx_reorder_requests_created ON reorder_requests(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_preferences_user ON alert_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_preferences_item ON alert_preferences(item_id);
CREATE INDEX IF NOT EXISTS idx_alert_preferences_snoozed ON alert_preferences(is_snoozed, snoozed_until);

-- ============================================
-- DEMAND FORECASTING FUNCTION
-- ============================================

-- Function to calculate demand forecast for a single item
CREATE OR REPLACE FUNCTION calculate_item_forecast(
  p_item_id UUID,
  p_lookback_days INTEGER DEFAULT 30
)
RETURNS TABLE(
  avg_daily_usage NUMERIC,
  days_until_stockout NUMERIC,
  total_consumed INTEGER,
  days_with_data INTEGER
) AS $$
DECLARE
  v_quantity INTEGER;
  v_min_stock INTEGER;
BEGIN
  -- Get current stock and min_stock
  SELECT quantity, min_stock INTO v_quantity, v_min_stock
  FROM items
  WHERE id = p_item_id;

  -- Return NULL if item not found
  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY
  WITH consumption_data AS (
    SELECT
      SUM(ABS(quantity_change)) as total_consumed,
      COUNT(DISTINCT DATE(created_at)) as days_with_data
    FROM inventory_transactions
    WHERE item_id = p_item_id
      AND type = 'remove'
      AND created_at >= NOW() - (p_lookback_days || ' days')::INTERVAL
  ),
  forecast AS (
    SELECT
      CASE 
        WHEN days_with_data > 0 THEN total_consumed::NUMERIC / days_with_data
        ELSE 0 
      END as avg_daily_usage,
      CASE 
        WHEN days_with_data > 0 AND total_consumed > 0 
        THEN v_quantity::NUMERIC / (total_consumed::NUMERIC / days_with_data)
        ELSE NULL 
      END as days_until_stockout,
      total_consumed,
      days_with_data
    FROM consumption_data
  )
  SELECT 
    avg_daily_usage,
    days_until_stockout,
    COALESCE(total_consumed, 0),
    COALESCE(days_with_data, 0)
  FROM forecast;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate forecast for all items
CREATE OR REPLACE FUNCTION calculate_all_forecasts(p_lookback_days INTEGER DEFAULT 30)
RETURNS TABLE(
  item_id UUID,
  item_name TEXT,
  sku TEXT,
  current_quantity INTEGER,
  min_stock INTEGER,
  avg_daily_usage NUMERIC,
  days_until_stockout NUMERIC,
  days_with_data INTEGER
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    i.id,
    i.name,
    i.sku,
    i.quantity,
    i.min_stock,
    f.avg_daily_usage,
    f.days_until_stockout,
    f.days_with_data
  FROM items i
  LEFT JOIN LATERAL calculate_item_forecast(i.id, p_lookback_days) f ON true
  ORDER BY i.quantity - i.min_stock ASC;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- ALERT TIER DETERMINATION FUNCTION
-- ============================================

-- Function to determine alert tier based on stock level
CREATE OR REPLACE FUNCTION determine_alert_tier(
  p_quantity INTEGER,
  p_min_stock INTEGER
)
RETURNS TEXT AS $$
BEGIN
  -- Emergency: Stock is zero
  IF p_quantity = 0 THEN
    RETURN 'emergency';
  END IF;
  
  -- Critical: At or below minimum stock
  IF p_quantity <= p_min_stock THEN
    RETURN 'critical';
  END IF;
  
  -- Warning: Within 30% of minimum stock
  IF p_quantity <= p_min_stock * 1.3 THEN
    RETURN 'warning';
  END IF;
  
  -- No alert needed
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- ALERT CREATION FUNCTION
-- ============================================

-- Function to create or update stock alerts
CREATE OR REPLACE FUNCTION evaluate_and_create_alerts()
RETURNS TABLE(
  item_id UUID,
  alert_tier TEXT,
  current_stock INTEGER,
  min_stock INTEGER,
  days_until_stockout NUMERIC,
  action_taken TEXT
) AS $$
DECLARE
  v_existing_alert_id UUID;
  v_item_record RECORD;
BEGIN
  -- Iterate through all items
  FOR v_item_record IN
    SELECT 
      i.id as item_id,
      determine_alert_tier(i.quantity, i.min_stock) as alert_tier,
      i.quantity as current_stock,
      i.min_stock,
      f.days_until_stockout,
      f.avg_daily_usage
    FROM items i
    LEFT JOIN LATERAL calculate_item_forecast(i.id, 30) f ON true
  LOOP
    -- Skip if no alert tier
    IF v_item_record.alert_tier IS NULL THEN
      -- Resolve any existing alerts for this item
      UPDATE stock_alerts
      SET resolved_at = NOW()
      WHERE item_id = v_item_record.item_id AND resolved_at IS NULL;
      
      RETURN QUERY SELECT v_item_record.item_id, NULL, v_item_record.current_stock, v_item_record.min_stock, v_item_record.days_until_stockout, 'resolved_existing'::TEXT;
      CONTINUE;
    END IF;
    
    -- Check if there's an existing unresolved alert of the same tier
    SELECT id INTO v_existing_alert_id
    FROM stock_alerts
    WHERE item_id = v_item_record.item_id 
      AND alert_tier = v_item_record.alert_tier
      AND resolved_at IS NULL
    LIMIT 1;
    
    -- If no existing alert, create one
    IF v_existing_alert_id IS NULL THEN
      INSERT INTO stock_alerts (
        item_id, alert_tier, current_stock, min_stock, 
        days_until_stockout, forecasted_daily_usage
      ) VALUES (
        v_item_record.item_id, v_item_record.alert_tier, v_item_record.current_stock, v_item_record.min_stock,
        v_item_record.days_until_stockout, v_item_record.avg_daily_usage
      );
      
      RETURN QUERY SELECT v_item_record.item_id, v_item_record.alert_tier, v_item_record.current_stock, v_item_record.min_stock, v_item_record.days_until_stockout, 'created'::TEXT;
    ELSE
      -- Update existing alert with current data
      UPDATE stock_alerts
      SET 
        current_stock = v_item_record.current_stock,
        days_until_stockout = v_item_record.days_until_stockout,
        forecasted_daily_usage = v_item_record.avg_daily_usage
      WHERE id = v_existing_alert_id;
      
      RETURN QUERY SELECT v_item_record.item_id, v_item_record.alert_tier, v_item_record.current_stock, v_item_record.min_stock, v_item_record.days_until_stockout, 'updated'::TEXT;
    END IF;
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger to update updated_at timestamp on reorder_requests
CREATE TRIGGER update_reorder_requests_updated_at
  BEFORE UPDATE ON reorder_requests
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Trigger to update updated_at timestamp on alert_preferences
CREATE TRIGGER update_alert_preferences_updated_at
  BEFORE UPDATE ON alert_preferences
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================

-- Enable RLS on new tables
ALTER TABLE stock_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE reorder_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_preferences ENABLE ROW LEVEL SECURITY;

-- Stock alerts policies
CREATE POLICY "Authenticated users can view stock alerts"
  ON stock_alerts FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert stock alerts"
  ON stock_alerts FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can update stock alerts"
  ON stock_alerts FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Reorder requests policies
CREATE POLICY "Authenticated users can view reorder requests"
  ON reorder_requests FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Admins and managers can insert reorder requests"
  ON reorder_requests FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Admins and managers can update reorder requests"
  ON reorder_requests FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

-- Alert preferences policies (per-user data)
CREATE POLICY "Users can view own alert preferences"
  ON alert_preferences FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can insert own alert preferences"
  ON alert_preferences FOR INSERT
  TO authenticated
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update own alert preferences"
  ON alert_preferences FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can delete own alert preferences"
  ON alert_preferences FOR DELETE
  TO authenticated
  USING (user_id = auth.uid());
