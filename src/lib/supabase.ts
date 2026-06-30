import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export type Database = {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          username: string;
          role: 'admin' | 'manager' | 'staff' | 'dispatcher' | 'driver';
          email: string;
          created_at: string;
        };
        Insert: {
          id: string;
          username: string;
          role: 'admin' | 'manager' | 'staff' | 'dispatcher' | 'driver';
          email: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          username?: string;
          role?: 'admin' | 'manager' | 'staff' | 'dispatcher' | 'driver';
          email?: string;
          created_at?: string;
        };
      };
      categories: {
        Row: {
          id: string;
          name: string;
          description?: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          description?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          name?: string;
          description?: string;
          created_at?: string;
        };
      };
      suppliers: {
        Row: {
          id: string;
          name: string;
          contact_email?: string;
          contact_phone?: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          contact_email?: string;
          contact_phone?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          name?: string;
          contact_email?: string;
          contact_phone?: string;
          created_at?: string;
        };
      };
      items: {
        Row: {
          id: string;
          name: string;
          sku: string;
          category_id: string;
          supplier_id: string;
          quantity: number;
          min_stock: number;
          price: number;
          location: string;
          barcode: string | null;
          last_scanned_at: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          sku: string;
          category_id: string;
          supplier_id: string;
          quantity: number;
          min_stock: number;
          price: number;
          location: string;
          barcode?: string | null;
          last_scanned_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          name?: string;
          sku?: string;
          category_id?: string;
          supplier_id?: string;
          quantity?: number;
          min_stock?: number;
          price?: number;
          location?: string;
          barcode?: string | null;
          last_scanned_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
      };
      inventory_transactions: {
        Row: {
          id: string;
          item_id: string;
          type: 'add' | 'remove' | 'adjust';
          quantity_change: number;
          notes?: string;
          created_by: string;
          created_at: string;
          scan_source?: string | null;
        };
        Insert: {
          id?: string;
          item_id: string;
          type: 'add' | 'remove' | 'adjust';
          quantity_change: number;
          notes?: string;
          created_by: string;
          created_at?: string;
          scan_source?: string | null;
        };
        Update: {
          id?: string;
          item_id?: string;
          type?: 'add' | 'remove' | 'adjust';
          quantity_change?: number;
          notes?: string;
          created_by?: string;
          created_at?: string;
          scan_source?: string | null;
        };
      };
      stock_alerts: {
        Row: {
          id: string;
          item_id: string;
          alert_tier: 'warning' | 'critical' | 'emergency';
          current_stock: number;
          min_stock: number;
          days_until_stockout: number | null;
          forecasted_daily_usage: number | null;
          acknowledged_by: string | null;
          acknowledged_at: string | null;
          created_at: string;
          resolved_at: string | null;
        };
        Insert: {
          id?: string;
          item_id: string;
          alert_tier: 'warning' | 'critical' | 'emergency';
          current_stock: number;
          min_stock: number;
          days_until_stockout?: number | null;
          forecasted_daily_usage?: number | null;
          acknowledged_by?: string | null;
          acknowledged_at?: string | null;
          created_at?: string;
          resolved_at?: string | null;
        };
        Update: {
          id?: string;
          item_id?: string;
          alert_tier?: 'warning' | 'critical' | 'emergency';
          current_stock?: number;
          min_stock?: number;
          days_until_stockout?: number | null;
          forecasted_daily_usage?: number | null;
          acknowledged_by?: string | null;
          acknowledged_at?: string | null;
          created_at?: string;
          resolved_at?: string | null;
        };
      };
      reorder_requests: {
        Row: {
          id: string;
          item_id: string;
          supplier_id: string | null;
          requested_by: string;
          requested_quantity: number;
          status: 'pending' | 'approved' | 'ordered' | 'received' | 'cancelled';
          notes?: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          item_id: string;
          supplier_id?: string | null;
          requested_by: string;
          requested_quantity: number;
          status?: 'pending' | 'approved' | 'ordered' | 'received' | 'cancelled';
          notes?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          item_id?: string;
          supplier_id?: string | null;
          requested_by?: string;
          requested_quantity?: number;
          status?: 'pending' | 'approved' | 'ordered' | 'received' | 'cancelled';
          notes?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      alert_preferences: {
        Row: {
          id: string;
          user_id: string;
          item_id: string | null;
          alert_tier: 'warning' | 'critical' | 'emergency' | null;
          is_snoozed: boolean;
          snoozed_until: string | null;
          is_dismissed: boolean;
          dismissed_at: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          item_id?: string | null;
          alert_tier?: 'warning' | 'critical' | 'emergency' | null;
          is_snoozed?: boolean;
          snoozed_until?: string | null;
          is_dismissed?: boolean;
          dismissed_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          item_id?: string | null;
          alert_tier?: 'warning' | 'critical' | 'emergency' | null;
          is_snoozed?: boolean;
          snoozed_until?: string | null;
          is_dismissed?: boolean;
          dismissed_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
      };
      vehicles: {
        Row: {
          id: string;
          registration_number: string;
          type: string | null;
          status: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          registration_number: string;
          type?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          registration_number?: string;
          type?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      task_types: {
        Row: {
          id: string;
          name: string;
          color: string;
          icon: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          name: string;
          color?: string;
          icon?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          name?: string;
          color?: string;
          icon?: string | null;
          created_at?: string;
        };
      };
      tasks: {
        Row: {
          id: string;
          title: string;
          description: string | null;
          task_type_id: string | null;
          status: 'pending' | 'assigned' | 'in_progress' | 'blocked' | 'completed';
          priority: 'low' | 'medium' | 'high' | 'urgent';
          assigned_to: string | null;
          vehicle_id: string | null;
          created_by: string;
          due_date: string | null;
          completed_at: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          title: string;
          description?: string | null;
          task_type_id?: string | null;
          status?: 'pending' | 'assigned' | 'in_progress' | 'blocked' | 'completed';
          priority?: 'low' | 'medium' | 'high' | 'urgent';
          assigned_to?: string | null;
          vehicle_id?: string | null;
          created_by: string;
          due_date?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          title?: string;
          description?: string | null;
          task_type_id?: string | null;
          status?: 'pending' | 'assigned' | 'in_progress' | 'blocked' | 'completed';
          priority?: 'low' | 'medium' | 'high' | 'urgent';
          assigned_to?: string | null;
          vehicle_id?: string | null;
          created_by?: string;
          due_date?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
        };
      };
      task_comments: {
        Row: {
          id: string;
          task_id: string;
          user_id: string;
          content: string;
          mentioned_users: string[];
          created_at: string;
        };
        Insert: {
          id?: string;
          task_id: string;
          user_id: string;
          content: string;
          mentioned_users?: string[];
          created_at?: string;
        };
        Update: {
          id?: string;
          task_id?: string;
          user_id?: string;
          content?: string;
          mentioned_users?: string[];
          created_at?: string;
        };
      };
      board_presence: {
        Row: {
          id: string;
          user_id: string;
          board_id: string;
          last_seen: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          board_id?: string;
          last_seen?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          board_id?: string;
          last_seen?: string;
        };
      };
    };
  };
};
