# Supabase Integration Setup Guide

## Completed Steps

### 1. Database Schema Migration ✅
Created `supabase-migrations.sql` with:
- All required tables (profiles, categories, suppliers, items, inventory_transactions)
- Row Level Security (RLS) policies for role-based access control
- Indexes for performance
- Triggers for automatic timestamp updates
- Automatic profile creation on user signup
- Seed data for categories and suppliers

### 2. Supabase Client Configuration ✅
- Created `src/lib/supabase.ts` with typed database schema
- Configured environment variables in `.env.local`
- Set up TypeScript types for all database tables

### 3. Authentication Integration ✅
- Created `src/hooks/use-auth.ts` for Supabase Auth
- Updated `src/pages/login.tsx` to use real Supabase authentication
- Updated `src/components/layout.tsx` to handle logout and profile sync
- Automatic profile creation on signup with default 'staff' role

### 4. Data Layer Migration ✅
- Created `src/hooks/use-items.ts` for items CRUD operations
- Created `src/hooks/use-transactions.ts` for transaction operations
- Created `src/hooks/use-profile.ts` for profile operations
- Updated `src/pages/dashboard.tsx` to use Supabase data via TanStack Query
- All hooks use TanStack Query for caching and optimistic updates

## Required Actions

### Step 1: Run Database Migration
1. Go to your Supabase project dashboard
2. Navigate to SQL Editor
3. Copy the contents of `supabase-migrations.sql`
4. Paste and run the SQL script

This will create all tables, RLS policies, indexes, triggers, and seed data.

### Step 2: Create a Test User
After running the migration, create a test user in Supabase:

1. Go to Authentication → Users in Supabase dashboard
2. Click "Add User"
3. Enter email and password
4. The user will automatically get a profile with 'staff' role

To assign admin/manager roles, you can manually update the profile in the database:

```sql
UPDATE profiles SET role = 'admin' WHERE email = 'your-admin@email.com';
UPDATE profiles SET role = 'manager' WHERE email = 'your-manager@email.com';
```

### Step 3: Test the Application
1. Restart the dev server: `npm run dev`
2. Navigate to http://localhost:5173
3. Sign in with your Supabase credentials
4. You should see the dashboard with empty data (since no items exist yet)

### Step 4: Add Initial Items
You can add items through the UI (Inventory page) or via SQL:

```sql
-- Get category and supplier IDs first
SELECT id, name FROM categories;
SELECT id, name FROM suppliers;

-- Insert sample items
INSERT INTO items (name, sku, category_id, supplier_id, quantity, min_stock, price, location)
VALUES 
  ('Industrial Steel Rack', 'SR-IND-001', 
   (SELECT id FROM categories WHERE name = 'Storage Assets'),
   (SELECT id FROM suppliers WHERE name = 'Global Iron Co.'),
   12, 5, 299.99, 'Aisle A1'),
  ('Wireless Barcode Scanner', 'SC-WL-440',
   (SELECT id FROM categories WHERE name = 'Electronics'),
   (SELECT id FROM suppliers WHERE name = 'LogiTech Logistics'),
   25, 6, 120.00, 'Office Cabin 2');
```

## Architecture Changes

### Before (Mock Data)
- Zustand store with hardcoded mock data
- Simulated authentication
- No backend persistence

### After (Supabase Integration)
- TanStack Query for server state management
- Supabase Auth for real authentication
- PostgreSQL database with RLS for security
- Automatic profile creation on signup
- Role-based access control enforced at database level

## Remaining Work

### 1. Items Page Migration
The `src/pages/items.tsx` still uses Zustand. It needs to be updated to use the `useItems` hook for CRUD operations.

### 2. Reports Page Migration
The `src/pages/reports.tsx` needs to be updated to use real Supabase data for report generation.

### 3. Settings Page Migration
The `src/pages/settings.tsx` role simulation should be removed since roles are now managed by Supabase.

### 4. Export Functionality
Implement actual Excel and PDF export using `exceljs` and `pdf-lib` libraries (currently placeholders).

### 5. Offline Sync
Implement IndexedDB for offline data caching and sync logic for when the app comes back online.

### 6. Real-time Updates
Enable Supabase Realtime subscriptions for live inventory updates.

## Troubleshooting

### Authentication Issues
- Check that `.env.local` has correct Supabase URL and anon key
- Verify email confirmation is enabled/disabled in Supabase Auth settings
- Check browser console for Supabase errors

### Data Not Loading
- Verify RLS policies are correctly set up
- Check that the user has the correct role in the profiles table
- Look at browser Network tab for API errors

### Permission Errors
- Ensure the user's role in the profiles table matches the RLS policy requirements
- Admin users have full access, managers can create/update items, staff can only view

## Next Steps Priority

1. **High Priority**: Run the database migration and test authentication
2. **Medium Priority**: Update Items page to use Supabase hooks
3. **Medium Priority**: Update Reports page for real data
4. **Low Priority**: Implement export functionality and offline sync
