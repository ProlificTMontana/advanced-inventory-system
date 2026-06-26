import React from 'react';

export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={`w-full text-left border-collapse text-sm ${className || ''}`} {...props} />
    </div>
  );
}
