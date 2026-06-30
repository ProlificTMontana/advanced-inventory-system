import { useState } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useReorderRequests } from '../hooks/use-reorder-requests';
import { useAuth } from '../hooks/use-auth';
import { ShoppingCart, Package, Clock, CheckCircle, Ban, Filter } from 'lucide-react';

const statusConfig = {
  pending: {
    label: 'Pending',
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-100 dark:bg-amber-950/40',
    icon: <Clock className="w-4 h-4" />,
  },
  approved: {
    label: 'Approved',
    color: 'text-blue-600 dark:text-blue-400',
    bgColor: 'bg-blue-100 dark:bg-blue-950/40',
    icon: <CheckCircle className="w-4 h-4" />,
  },
  ordered: {
    label: 'Ordered',
    color: 'text-purple-600 dark:text-purple-400',
    bgColor: 'bg-purple-100 dark:bg-purple-950/40',
    icon: <ShoppingCart className="w-4 h-4" />,
  },
  received: {
    label: 'Received',
    color: 'text-emerald-600 dark:text-emerald-400',
    bgColor: 'bg-emerald-100 dark:bg-emerald-950/40',
    icon: <Package className="w-4 h-4" />,
  },
  cancelled: {
    label: 'Cancelled',
    color: 'text-red-600 dark:text-red-400',
    bgColor: 'bg-red-100 dark:bg-red-950/40',
    icon: <Ban className="w-4 h-4" />,
  },
};

export default function ReorderRequests() {
  const { requests, isLoading, updateReorderRequest } = useReorderRequests();
  const { user } = useAuth();
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [expandedRequest, setExpandedRequest] = useState<string | null>(null);

  const filteredRequests = filterStatus === 'all' 
    ? requests 
    : requests.filter(req => req.status === filterStatus);

  const handleStatusUpdate = async (requestId: string, newStatus: string) => {
    try {
      await updateReorderRequest.mutateAsync({
        id: requestId,
        status: newStatus as any,
      });
    } catch (error) {
      console.error('Failed to update status:', error);
    }
  };

  const canUpdateStatus = user?.role === 'admin' || user?.role === 'manager';

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
          Reorder Requests
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Manage and track inventory reorder requests
        </p>
      </div>

      {/* Filter Bar */}
      <Card className="p-4">
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Filter:</span>
          {['all', 'pending', 'approved', 'ordered', 'received', 'cancelled'].map((status) => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                filterStatus === status
                  ? 'bg-blue-100 text-blue-700 dark:bg-blue-950/40 dark:text-blue-400'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:hover:bg-slate-700'
              }`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>
      </Card>

      {/* Requests List */}
      {isLoading ? (
        <Card className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        </Card>
      ) : filteredRequests.length === 0 ? (
        <Card className="p-8 text-center">
          <ShoppingCart className="w-12 h-12 mx-auto mb-4 text-slate-300 dark:text-slate-600" />
          <p className="text-slate-500 dark:text-slate-400">
            {filterStatus === 'all' 
              ? 'No reorder requests yet' 
              : `No ${filterStatus} requests`}
          </p>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredRequests.map((request) => {
            const config = statusConfig[request.status as keyof typeof statusConfig];
            const isExpanded = expandedRequest === request.id;

            return (
              <Card key={request.id} className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color}`}>
                        {config.icon}
                        {config.label}
                      </span>
                      <span className="text-xs text-slate-400">
                        {new Date(request.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    
                    <h3 className="font-medium text-slate-900 dark:text-white text-sm">
                      {request.items?.name}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {request.items?.sku}
                    </p>

                    <div className="flex items-center gap-4 mt-2 text-xs">
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Qty: </span>
                        <span className="font-semibold text-slate-900 dark:text-white">
                          {request.requested_quantity}
                        </span>
                      </div>
                      {request.suppliers && (
                        <div>
                          <span className="text-slate-500 dark:text-slate-400">Supplier: </span>
                          <span className="font-medium text-slate-900 dark:text-white">
                            {request.suppliers.name}
                          </span>
                        </div>
                      )}
                      {request.requested_by_profile && (
                        <div>
                          <span className="text-slate-500 dark:text-slate-400">By: </span>
                          <span className="font-medium text-slate-900 dark:text-white">
                            {request.requested_by_profile.username}
                          </span>
                        </div>
                      )}
                    </div>

                    {isExpanded && request.notes && (
                      <div className="mt-3 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
                        <p className="text-xs text-slate-600 dark:text-slate-400">
                          <span className="font-medium">Notes:</span> {request.notes}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col gap-2 shrink-0">
                    {canUpdateStatus && request.status === 'pending' && (
                      <>
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => handleStatusUpdate(request.id, 'approved')}
                          disabled={updateReorderRequest.isPending}
                        >
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleStatusUpdate(request.id, 'cancelled')}
                          disabled={updateReorderRequest.isPending}
                          className="text-red-600 hover:text-red-700 dark:text-red-400"
                        >
                          Cancel
                        </Button>
                      </>
                    )}
                    {canUpdateStatus && request.status === 'approved' && (
                      <Button
                        size="sm"
                        onClick={() => handleStatusUpdate(request.id, 'ordered')}
                        disabled={updateReorderRequest.isPending}
                      >
                        Mark Ordered
                      </Button>
                    )}
                    {canUpdateStatus && request.status === 'ordered' && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleStatusUpdate(request.id, 'received')}
                        disabled={updateReorderRequest.isPending}
                      >
                        Mark Received
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setExpandedRequest(isExpanded ? null : request.id)}
                    >
                      {isExpanded ? 'Show Less' : 'Show More'}
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
