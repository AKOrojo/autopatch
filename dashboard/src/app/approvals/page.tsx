"use client";
import { useState } from "react";
import { useApprovals, useApproveRequest, useRejectRequest } from "@/lib/hooks";
import { ApprovalCard } from "@/components/approval-card";

export default function ApprovalsPage() {
  const [statusFilter, setStatusFilter] = useState("pending");
  const { data, isLoading } = useApprovals({ status: statusFilter });
  const approveMutation = useApproveRequest();
  const rejectMutation = useRejectRequest();
  const filters = ["pending", "approved", "rejected"];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Approval Queue</h1>
      <div className="flex gap-1 border rounded-lg p-1 w-fit mb-6">
        {filters.map((f) => (
          <button key={f} onClick={() => setStatusFilter(f)}
            className={`px-3 py-1 rounded text-sm capitalize ${statusFilter === f ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}>
            {f}
          </button>
        ))}
      </div>
      {isLoading ? (
        <div className="space-y-4">{Array.from({ length: 3 }).map((_, i) => (<div key={i} className="border rounded-lg p-4 animate-pulse"><div className="h-4 bg-muted rounded w-48 mb-2" /><div className="h-3 bg-muted rounded w-32" /></div>))}</div>
      ) : (
        <div className="space-y-4">
          {data?.data.length === 0 ? <p className="text-muted-foreground">No {statusFilter} approvals.</p> :
            data?.data.map((a) => (<ApprovalCard key={a.id} approval={a} onApprove={(id, reason) => approveMutation.mutate({ id, reason })} onReject={(id, reason) => rejectMutation.mutate({ id, reason })} />))}
        </div>
      )}
    </div>
  );
}
