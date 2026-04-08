"use client";

interface PaginationProps {
  total: number;
  limit: number;
  offset: number;
  onPageChange: (newOffset: number) => void;
}

export function Pagination({ total, limit, offset, onPageChange }: PaginationProps) {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="flex items-center justify-between py-4">
      <p className="text-sm text-muted-foreground">Showing {Math.min(offset + 1, total)}-{Math.min(offset + limit, total)} of {total}</p>
      <div className="flex gap-2">
        <button onClick={() => onPageChange(Math.max(0, offset - limit))} disabled={offset === 0} className="px-3 py-1 text-sm border rounded disabled:opacity-50">Previous</button>
        <span className="px-3 py-1 text-sm">Page {currentPage} of {totalPages}</span>
        <button onClick={() => onPageChange(offset + limit)} disabled={offset + limit >= total} className="px-3 py-1 text-sm border rounded disabled:opacity-50">Next</button>
      </div>
    </div>
  );
}
