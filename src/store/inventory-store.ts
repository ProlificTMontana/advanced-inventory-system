import { create } from 'zustand';

export interface Item {
  id: number;
  name: string;
  sku: string;
  category: string;
  supplier: string;
  quantity: number;
  min_stock: number;
  price: number;
  location: string;
}

export interface Transaction {
  id: number;
  item_id: number;
  itemName: string;
  type: 'add' | 'remove' | 'adjust';
  quantity_change: number;
  notes: string;
  created_at: string;
}

interface UserProfile {
  username: string;
  role: 'admin' | 'manager' | 'staff' | 'dispatcher' | 'driver';
  email: string;
}

interface InventoryState {
  items: Item[];
  transactions: Transaction[];
  user: UserProfile | null;
  isOffline: boolean;
  setUser: (user: UserProfile | null) => void;
  setOfflineStatus: (status: boolean) => void;
  addItem: (item: Omit<Item, 'id'>) => void;
  updateItem: (id: number, updates: Partial<Item>) => void;
  deleteItem: (id: number) => void;
  logTransaction: (tx: Omit<Transaction, 'id' | 'created_at'>) => void;
}

const initialItems: Item[] = [
  { id: 1, name: "Industrial Steel Rack", sku: "SR-IND-001", category: "Storage Assets", supplier: "Global Iron Co.", quantity: 12, min_stock: 5, price: 299.99, location: "Aisle A1" },
  { id: 2, name: "Heavy Duty Casters (4x)", sku: "CS-HD-992", category: "Hardware Hardware", supplier: "Titan Parts Inc.", quantity: 3, min_stock: 10, price: 45.50, location: "Bin B12" },
  { id: 3, name: "Wireless Barcode Scanner", sku: "SC-WL-440", category: "Electronics", supplier: "LogiTech Logistics", quantity: 25, min_stock: 6, price: 120.00, location: "Office Cabin 2" },
  { id: 4, name: "Pallet Wrap Roll 500mm", sku: "WP-PL-022", category: "Packaging Packaging", supplier: "WrapSupply Ltd.", quantity: 45, min_stock: 15, price: 18.25, location: "Aisle C3" },
  { id: 5, name: "Forklift Battery Charger", sku: "CH-FL-881", category: "Machinery Assets", supplier: "VoltPower Corp", quantity: 1, min_stock: 2, price: 850.00, location: "Bay 4" }
];

const initialTransactions: Transaction[] = [
  { id: 101, item_id: 1, itemName: "Industrial Steel Rack", type: "add", quantity_change: 4, notes: "Restock procurement received", created_at: new Date(Date.now() - 3600000).toISOString() },
  { id: 102, item_id: 2, itemName: "Heavy Duty Casters (4x)", type: "remove", quantity_change: -2, notes: "Fulfillment checkout for Assembly", created_at: new Date(Date.now() - 7200000).toISOString() }
];

export const useInventoryStore = create<InventoryState>((set) => ({
  items: initialItems,
  transactions: initialTransactions,
  user: { username: "demo_manager", role: "manager", email: "manager@aims-pwa.com" },
  isOffline: !navigator.onLine,
  setUser: (user) => set({ user }),
  setOfflineStatus: (isOffline) => set({ isOffline }),
  addItem: (itemData) => set((state) => {
    const newId = state.items.length ? Math.max(...state.items.map(i => i.id)) + 1 : 1;
    const newItem = { ...itemData, id: newId };
    return { items: [...state.items, newItem] };
  }),
  updateItem: (id, updates) => set((state) => ({
    items: state.items.map((item) => (item.id === id ? { ...item, ...updates } : item)),
  })),
  deleteItem: (id) => set((state) => ({
    items: state.items.filter((item) => item.id !== id),
  })),
  logTransaction: (txData) => set((state) => {
    const newId = state.transactions.length ? Math.max(...state.transactions.map(t => t.id)) + 1 : 1;
    const newTx = { ...txData, id: newId, created_at: new Date().toISOString() };
    return { transactions: [newTx, ...state.transactions] };
  }),
}));
