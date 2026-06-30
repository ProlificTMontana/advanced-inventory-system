import React, { useState } from 'react';
import { useItems } from '../hooks/use-items';
import { useCategories } from '../hooks/use-categories';
import { useSuppliers } from '../hooks/use-suppliers';
import { useTransactions } from '../hooks/use-transactions';
import { useAuth } from '../hooks/use-auth';
import { useProfile } from '../hooks/use-profile';
import { Table } from '../components/ui/table';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Dialog } from '../components/ui/dialog';
import { Search, Plus, SlidersHorizontal, AlertCircle, Trash2, Edit, Loader2, ScanLine } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Items() {
  const { items, isLoading, createItem, updateItem, deleteItem } = useItems();
  const { categories } = useCategories();
  const { suppliers } = useSuppliers();
  const { createTransaction } = useTransactions();
  const { user: authUser } = useAuth();
  const { data: profile } = useProfile(authUser?.id);
  const navigate = useNavigate();
  
  const [search, setSearch] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<any | null>(null);

  // Form State Architecture
  const [name, setName] = useState('');
  const [sku, setSku] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [supplierId, setSupplierId] = useState('');
  const [quantity, setQuantity] = useState(10);
  const [minStock, setMinStock] = useState(5);
  const [price, setPrice] = useState(99.99);
  const [location, setLocation] = useState('Aisle A1');

  const openAddModal = () => {
    setEditingItem(null);
    setName(''); 
    setSku(''); 
    setCategoryId(categories[0]?.id || '');
    setSupplierId(suppliers[0]?.id || '');
    setQuantity(10); 
    setMinStock(5); 
    setPrice(49.99); 
    setLocation('Aisle A1');
    setIsModalOpen(true);
  };

  const openEditModal = (item: any) => {
    setEditingItem(item);
    setName(item.name); 
    setSku(item.sku); 
    setCategoryId(item.category_id || '');
    setSupplierId(item.supplier_id || '');
    setQuantity(item.quantity); 
    setMinStock(item.min_stock); 
    setPrice(item.price); 
    setLocation(item.location);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!authUser?.id) {
      console.error('User not authenticated');
      return;
    }

    const payload = { 
      name, 
      sku, 
      category_id: categoryId, 
      supplier_id: supplierId,
      quantity: Number(quantity), 
      min_stock: Number(minStock), 
      price: Number(price), 
      location 
    };

    try {
      if (editingItem) {
        await updateItem.mutateAsync({ id: editingItem.id, ...payload });
        // Log transaction for quantity changes
        if (payload.quantity !== editingItem.quantity) {
          await createTransaction.mutateAsync({
            item_id: editingItem.id,
            type: 'adjust',
            quantity_change: payload.quantity - editingItem.quantity,
            notes: 'Item parameters structural amendment',
            created_by: authUser.id,
          });
        }
      } else {
        const newItem = await createItem.mutateAsync(payload);
        // Log transaction for new item
        await createTransaction.mutateAsync({
          item_id: newItem.id,
          type: 'add',
          quantity_change: payload.quantity,
          notes: 'Initial provision deployment register',
          created_by: authUser.id,
        });
      }
      setIsModalOpen(false);
    } catch (error) {
      console.error('Error saving item:', error);
    }
  };

  const filteredItems = items.filter(i => 
    i.name.toLowerCase().includes(search.toLowerCase()) || 
    i.sku.toLowerCase().includes(search.toLowerCase())
  );
  const isReadOnly = profile?.role === 'staff';

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Inventory Stock Ledger</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">Granular query structures and manipulation parameters for registered objects.</p>
        </div>
        {!isReadOnly && (
          <Button onClick={openAddModal} className="flex items-center gap-2 self-start sm:self-auto">
            <Plus className="w-4 h-4" /> Provision Item
          </Button>
        )}
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <Input placeholder="Query via Item Title or SKU Identifier..." className="pl-9" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <Button variant="secondary" className="flex items-center gap-2"><SlidersHorizontal className="w-4 h-4" /> Filters</Button>
      </div>

      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
          </div>
        ) : (
          <Table>
          <thead>
            <tr className="bg-slate-100/70 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">
              <th className="p-3.5">Identification Matrix</th>
              <th className="p-3.5">Category Class</th>
              <th className="p-3.5 text-center">Status Capacity</th>
              <th className="p-3.5 text-right">Unit Price</th>
              <th className="p-3.5">Warehouse Location</th>
              {!isReadOnly && <th className="p-3.5 text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
            {filteredItems.map((item) => {
              const isLowStock = item.quantity <= item.min_stock;
              return (
                <tr key={item.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors">
                  <td className="p-3.5">
                    <p className="font-semibold text-slate-900 dark:text-white">{item.name}</p>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">{item.sku}</p>
                  </td>
                  <td className="p-3.5 text-slate-600 dark:text-slate-400">{item.categories?.name || 'Uncategorized'}</td>
                  <td className="p-3.5 text-center">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                      isLowStock ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-400' : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400'
                    }`}>
                      {isLowStock && <AlertCircle className="w-3.5 h-3.5" />}
                      {item.quantity} units
                    </span>
                  </td>
                  <td className="p-3.5 text-right font-medium text-slate-700 dark:text-slate-300">${item.price.toFixed(2)}</td>
                  <td className="p-3.5 font-mono text-xs text-slate-500 dark:text-slate-400">{item.location}</td>
                  {!isReadOnly && (
                    <td className="p-3.5 text-right space-x-1">
                      <Button variant="ghost" size="sm" onClick={() => openEditModal(item)}><Edit className="w-3.5 h-3.5" /></Button>
                      <Button variant="ghost" size="sm" className="hover:text-red-500" onClick={() => deleteItem.mutateAsync(item.id)}><Trash2 className="w-3.5 h-3.5" /></Button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </Table>
        )}
      </Card>

      {/* Form Dialog Architecture */}
      <Dialog isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title={editingItem ? "Amend Item Architecture" : "Provision New Asset Module"}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Item Label Nomenclature</label>
            <Input value={name} onChange={e => setName(e.target.value)} required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1">SKU Code</label>
              <Input value={sku} onChange={e => setSku(e.target.value)} required />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Location Vector</label>
              <Input value={location} onChange={e => setLocation(e.target.value)} required />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1">Category</label>
              <select 
                value={categoryId} 
                onChange={e => setCategoryId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white"
                required
              >
                {categories.map(cat => (
                  <option key={cat.id} value={cat.id}>{cat.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Supplier</label>
              <select 
                value={supplierId} 
                onChange={e => setSupplierId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-white"
                required
              >
                {suppliers.map(sup => (
                  <option key={sup.id} value={sup.id}>{sup.name}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-xs font-medium mb-1">Quantity</label>
              <Input type="number" value={quantity} onChange={e => setQuantity(Number(e.target.value))} required />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Floor Target</label>
              <Input type="number" value={minStock} onChange={e => setMinStock(Number(e.target.value))} required />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Price ($)</label>
              <Input type="number" step="0.01" value={price} onChange={e => setPrice(Number(e.target.value))} required />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-4 border-t border-slate-100 dark:border-slate-800">
            <Button variant="secondary" type="button" onClick={() => setIsModalOpen(false)}>Abort</Button>
            <Button type="submit">Commit Block</Button>
          </div>
        </form>
      </Dialog>

      {/* Scanner FAB */}
      <button
        onClick={() => navigate('/scan')}
        className="fixed bottom-6 right-6 w-14 h-14 bg-blue-600 hover:bg-blue-700 text-white rounded-full shadow-lg flex items-center justify-center transition-all hover:scale-105 z-40"
        title="Open Barcode Scanner"
      >
        <ScanLine className="w-6 h-6" />
      </button>
    </div>
  );
}
