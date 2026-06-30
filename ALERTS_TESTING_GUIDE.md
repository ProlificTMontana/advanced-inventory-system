# AIMS Alert System Testing Guide

This guide provides step-by-step instructions for testing the enhanced alert system with automated low-stock alerts, reorder workflows, and demand forecasting.

## Prerequisites

1. Run the base migration: `supabase-migrations.sql`
2. Run the alerts migration: `supabase-alerts-migration.sql`
3. Ensure you have test data in the `items` and `inventory_transactions` tables
4. Start the development server: `npm run dev`

## Step 1: Database Migration Verification

### Verify Tables Created
Run these queries in Supabase SQL Editor to verify the new tables:

```sql
-- Check stock_alerts table
SELECT COUNT(*) FROM stock_alerts;

-- Check reorder_requests table
SELECT COUNT(*) FROM reorder_requests;

-- Check alert_preferences table
SELECT COUNT(*) FROM alert_preferences;
```

### Verify Functions Created
```sql
-- Test demand forecasting function
SELECT * FROM calculate_item_forecast(
  (SELECT id FROM items LIMIT 1),
  30
);

-- Test alert tier determination
SELECT determine_alert_tier(5, 10);  -- Should return 'warning'
SELECT determine_alert_tier(10, 10); -- Should return 'critical'
SELECT determine_alert_tier(0, 10);  -- Should return 'emergency'
SELECT determine_alert_tier(20, 10); -- Should return NULL
```

## Step 2: Seed Test Data

### Create Test SKU with Known Consumption Pattern
```sql
-- Insert a test item with low stock
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'Test Widget A',
  'TEST-WIDGET-001',
  (SELECT id FROM categories WHERE name = 'Storage Assets' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'Global Iron Co.' LIMIT 1),
  8,  -- Current quantity (below min_stock)
  10, -- Min stock
  25.00,
  'Test Location A'
);

-- Get the item ID
SELECT id, name, sku, quantity, min_stock FROM items WHERE sku = 'TEST-WIDGET-001';
```

### Seed Historical Transaction Data (Last 30 Days)
```sql
-- Get the test item ID (replace with actual ID from above)
DO $$
DECLARE
  v_item_id UUID := (SELECT id FROM items WHERE sku = 'TEST-WIDGET-001' LIMIT 1);
  v_date DATE;
BEGIN
  -- Create 30 days of transaction history
  FOR i IN 0..29 LOOP
    v_date := CURRENT_DATE - i;
    
    -- Random daily consumption (1-3 units per day)
    INSERT INTO inventory_transactions (item_id, type, quantity_change, notes, created_at, created_by)
    VALUES (
      v_item_id,
      'remove',
      -(1 + (i % 3)),  -- Alternates between 1, 2, 3 units
      'Test transaction for demand forecasting',
      v_date || ' 10:00:00',
      (SELECT id FROM profiles WHERE role = 'manager' LIMIT 1)
    );
  END LOOP;
END $$;
```

### Create Additional Test Scenarios
```sql
-- Warning tier item (30% above min_stock)
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'Warning Test Item',
  'WARN-TEST-001',
  (SELECT id FROM categories WHERE name = 'Hardware Hardware' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'Titan Parts Inc.' LIMIT 1),
  13,  -- quantity (min_stock * 1.3)
  10,  -- min_stock
  15.00,
  'Test Location B'
);

-- Critical tier item (at min_stock)
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'Critical Test Item',
  'CRIT-TEST-001',
  (SELECT id FROM categories WHERE name = 'Electronics' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'LogiTech Logistics' LIMIT 1),
  5,   -- quantity (at min_stock)
  5,   -- min_stock
  50.00,
  'Test Location C'
);

-- Emergency tier item (zero stock)
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'Emergency Test Item',
  'EMERG-TEST-001',
  (SELECT id FROM categories WHERE name = 'Packaging Packaging' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'WrapSupply Ltd.' LIMIT 1),
  0,   -- quantity (zero)
  10,  -- min_stock
  8.00,
  'Test Location D'
);
```

## Step 3: Manual Alert Evaluation

### Trigger Alert Evaluation Function
```sql
-- Run the alert evaluation function
SELECT * FROM evaluate_and_create_alerts();
```

### Verify Alert Records Created
```sql
-- Check created alerts
SELECT 
  sa.id,
  sa.alert_tier,
  sa.current_stock,
  sa.min_stock,
  sa.days_until_stockout,
  sa.forecasted_daily_usage,
  i.name,
  i.sku
FROM stock_alerts sa
JOIN items i ON sa.item_id = i.id
WHERE sa.resolved_at IS NULL
ORDER BY sa.created_at DESC;
```

Expected results:
- Warning tier: quantity between min_stock and min_stock * 1.3
- Critical tier: quantity at or below min_stock
- Emergency tier: quantity = 0

## Step 4: Test Dashboard Widget

1. Navigate to the Dashboard in the application
2. Look for the "Stock Alerts" widget in the right column
3. Verify the following:
   - Active alert count is displayed
   - Alert cards show correct tier badges (Warning/Critical/Emergency)
   - SKU name and current stock are displayed
   - "View details" button expands alert card
   - Expanded view shows:
     - Days until stockout estimate
     - Average daily usage
     - Supplier information
     - "Reorder" button

## Step 5: Test Reorder Workflow

### Create Reorder from Alert
1. Click "View details" on an alert
2. Click "Reorder" button
3. Verify:
   - Reorder request is created
   - Success message appears
   - Alert card collapses

### Verify Reorder Request in Database
```sql
SELECT 
  rr.id,
  rr.requested_quantity,
  rr.status,
  rr.notes,
  i.name as item_name,
  i.sku,
  s.name as supplier_name,
  p.username as requested_by
FROM reorder_requests rr
JOIN items i ON rr.item_id = i.id
LEFT JOIN suppliers s ON rr.supplier_id = s.id
JOIN profiles p ON rr.requested_by = p.id
ORDER BY rr.created_at DESC
LIMIT 5;
```

### Test Reorder Requests Page
1. Navigate to "Reorders" in the sidebar
2. Verify the following:
   - List of reorder requests is displayed
   - Status badges are correct (Pending/Approved/Ordered/Received/Cancelled)
   - Filter buttons work correctly
   - "Show More" expands to show notes
   - Status update buttons work (for admin/manager roles)

## Step 6: Test Alert Preferences (Snooze/Dismiss)

### Test Snooze Function
```sql
-- Test snoozing an alert (replace with actual IDs)
INSERT INTO alert_preferences (user_id, item_id, alert_tier, is_snoozed, snoozed_until)
VALUES (
  (SELECT id FROM profiles WHERE email = 'your-test@email.com'),
  (SELECT id FROM items WHERE sku = 'TEST-WIDGET-001'),
  'critical',
  true,
  NOW() + INTERVAL '1 hour'
);
```

### Test Dismiss Function
```sql
-- Test dismissing an alert
INSERT INTO alert_preferences (user_id, item_id, alert_tier, is_dismissed, dismissed_at)
VALUES (
  (SELECT id FROM profiles WHERE email = 'your-test@email.com'),
  (SELECT id FROM items WHERE sku = 'TEST-WIDGET-001'),
  'critical',
  true,
  NOW()
);
```

### Verify Per-User State
```sql
-- Check that preferences are per-user
SELECT 
  ap.user_id,
  p.username,
  ap.item_id,
  i.name,
  ap.alert_tier,
  ap.is_snoozed,
  ap.snoozed_until,
  ap.is_dismissed
FROM alert_preferences ap
JOIN profiles p ON ap.user_id = p.id
JOIN items i ON ap.item_id = i.id;
```

## Step 7: Test Notification Center

1. Look for the bell icon in the top-right of the sidebar
2. Click to open notification center
3. Verify:
   - Unread count badge appears
   - Alert notifications are displayed
   - "Mark all read" button works
   - Individual dismiss buttons work
   - Notifications show correct timestamps

## Step 8: Test Demand Forecasting Accuracy

### Compare Forecast vs Actual
```sql
-- Get forecast for test item
SELECT 
  i.name,
  i.sku,
  i.quantity,
  i.min_stock,
  f.avg_daily_usage,
  f.days_until_stockout,
  f.days_with_data
FROM items i
LEFT JOIN LATERAL calculate_item_forecast(i.id, 30) f ON true
WHERE i.sku = 'TEST-WIDGET-001';
```

### Manually Adjust Stock and Re-evaluate
```sql
-- Reduce stock to trigger different alert tier
UPDATE items
SET quantity = 3
WHERE sku = 'TEST-WIDGET-001';

-- Re-run alert evaluation
SELECT * FROM evaluate_and_create_alerts();

-- Check if alert tier changed
SELECT alert_tier, current_stock, min_stock
FROM stock_alerts
WHERE item_id = (SELECT id FROM items WHERE sku = 'TEST-WIDGET-001')
  AND resolved_at IS NULL;
```

## Step 9: Test Edge Cases

### No Historical Data
```sql
-- Create item with no transaction history
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'No History Item',
  'NO-HIST-001',
  (SELECT id FROM categories WHERE name = 'Storage Assets' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'Global Iron Co.' LIMIT 1),
  5,
  10,
  30.00,
  'Test Location E'
);

-- Run evaluation - should handle gracefully
SELECT * FROM evaluate_and_create_alerts();
```

### Zero Consumption Pattern
```sql
-- Create item with transactions but no consumption
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES (
  'Zero Consumption Item',
  'ZERO-CONS-001',
  (SELECT id FROM categories WHERE name = 'Hardware Hardware' LIMIT 1),
  (SELECT id FROM suppliers WHERE name = 'Titan Parts Inc.' LIMIT 1),
  5,
  10,
  20.00,
  'Test Location F'
);

-- Add only 'add' transactions (no 'remove')
DO $$
DECLARE
  v_item_id UUID := (SELECT id FROM items WHERE sku = 'ZERO-CONS-001' LIMIT 1);
BEGIN
  INSERT INTO inventory_transactions (item_id, type, quantity_change, notes, created_at, created_by)
  VALUES (
    v_item_id,
    'add',
    10,
    'Initial stock addition',
    NOW(),
    (SELECT id FROM profiles WHERE role = 'manager' LIMIT 1)
  );
END $$;

-- Run evaluation - should handle zero daily usage
SELECT * FROM evaluate_and_create_alerts();
```

## Step 10: Cleanup Test Data

```sql
-- Delete test alerts
DELETE FROM stock_alerts WHERE item_id IN (
  SELECT id FROM items WHERE sku LIKE '%-TEST-%' OR sku LIKE 'TEST-%'
);

-- Delete test reorder requests
DELETE FROM reorder_requests WHERE item_id IN (
  SELECT id FROM items WHERE sku LIKE '%-TEST-%' OR sku LIKE 'TEST-%'
);

-- Delete test alert preferences
DELETE FROM alert_preferences WHERE item_id IN (
  SELECT id FROM items WHERE sku LIKE '%-TEST-%' OR sku LIKE 'TEST-%'
);

-- Delete test transactions
DELETE FROM inventory_transactions WHERE item_id IN (
  SELECT id FROM items WHERE sku LIKE '%-TEST-%' OR sku LIKE 'TEST-%'
);

-- Delete test items
DELETE FROM items WHERE sku LIKE '%-TEST-%' OR sku LIKE 'TEST-%';
```

## Expected Results Summary

- **Alert Tiers**: Correctly classified based on stock levels
- **Demand Forecasting**: Reasonable estimates based on historical data
- **Reorder Workflow**: Creates records with suggested quantities
- **Per-User State**: Snooze/dismiss persists per user
- **Dashboard Widget**: Displays alerts with correct information
- **Notification Center**: Shows unread count and alert details
- **Edge Cases**: Handles no history, zero consumption gracefully

## Troubleshooting

### Alerts Not Appearing
- Verify `evaluate_and_create_alerts()` was run
- Check `resolved_at` is NULL in `stock_alerts`
- Ensure user has permission to view alerts (RLS policies)

### Forecast Shows NULL
- Check if item has transaction history
- Verify transactions have type='remove'
- Ensure transactions are within the lookback period (default 30 days)

### Reorder Button Disabled
- Verify user is authenticated
- Check user role (admin/manager required for some actions)
- Ensure item has a supplier assigned

### Notifications Not Showing
- Check browser console for errors
- Verify `useStockAlerts` hook is loading data
- Ensure notification center component is mounted
