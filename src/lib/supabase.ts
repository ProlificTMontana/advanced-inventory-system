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
          role: 'admin' | 'manager' | 'staff';
          email: string;
          created_at: string;
        };
        Insert: {
          id: string;
          username: string;
          role: 'admin' | 'manager' | 'staff';
          email: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          username?: string;
          role?: 'admin' | 'manager' | 'staff';
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
        };
        Insert: {
          id?: string;
          item_id: string;
          type: 'add' | 'remove' | 'adjust';
          quantity_change: number;
          notes?: string;
          created_by: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          item_id?: string;
          type?: 'add' | 'remove' | 'adjust';
          quantity_change?: number;
          notes?: string;
          created_by?: string;
          created_at?: string;
        };
      };
    };
  };
};
