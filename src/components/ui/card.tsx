import React from 'react';

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div 
      className={`bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 rounded-xl shadow-sm overflow-hidden ${className || ''}`} 
      {...props} 
    />
  );
}
