"use client";

import { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export function DataTable<T extends Record<string, unknown>>({
  columns, data, loading = false, onRowClick, emptyMessage = "No data found.",
}: DataTableProps<T>) {
  if (loading) {
    return (
      <div className="border rounded-lg">
        <table className="w-full">
          <thead><tr className="border-b bg-muted/50">
            {columns.map((col) => <th key={col.key} className="px-4 py-3 text-left text-sm font-medium">{col.header}</th>)}
          </tr></thead>
          <tbody>
            {Array.from({ length: 5 }).map((_, i) => (
              <tr key={i} className="border-b">
                {columns.map((col) => <td key={col.key} className="px-4 py-3"><div className="h-4 bg-muted rounded animate-pulse" /></td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if (data.length === 0) {
    return <div className="border rounded-lg p-8 text-center text-muted-foreground">{emptyMessage}</div>;
  }
  return (
    <div className="border rounded-lg overflow-hidden">
      <table className="w-full">
        <thead><tr className="border-b bg-muted/50">
          {columns.map((col) => <th key={col.key} className="px-4 py-3 text-left text-sm font-medium">{col.header}</th>)}
        </tr></thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} className={`border-b hover:bg-muted/30 ${onRowClick ? "cursor-pointer" : ""}`} onClick={() => onRowClick?.(row)}>
              {columns.map((col) => <td key={col.key} className="px-4 py-3 text-sm">{col.render ? col.render(row) : String(row[col.key] ?? "")}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
