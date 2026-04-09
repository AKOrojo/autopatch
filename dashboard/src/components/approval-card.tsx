"use client";
import { useState } from "react";
import type { ApprovalRequest } from "@/lib/types";

interface ApprovalCardProps {
  approval: ApprovalRequest;
  onApprove: (id: string, reason?: string) => void;
  onReject: (id: string, reason: string) => void;
}

export function ApprovalCard({ approval, onApprove, onReject }: ApprovalCardProps) {
  const [rejectReason, setRejectReason] = useState("");
  const isPending = approval.status === "pending";
  const tierColors: Record<string, string> = { dev: "bg-blue-100 text-blue-800", staging: "bg-yellow-100 text-yellow-800", prod: "bg-red-100 text-red-800" };

  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${tierColors[approval.asset_tier] || "bg-gray-100 text-gray-800"}`}>{approval.asset_tier}</span>
          <span className="text-sm font-medium">CVSS: {approval.risk_score.toFixed(1)}</span>
        </div>
        <span className="text-xs text-muted-foreground">{new Date(approval.created_at).toLocaleString()}</span>
      </div>
      <p className="text-sm text-muted-foreground mb-1 font-mono">{approval.remediation_id}</p>
      {isPending ? (
        <div className="flex items-center gap-2 mt-3">
          <button onClick={() => onApprove(approval.id)} className="px-3 py-1.5 text-sm bg-green-600 text-white rounded-md hover:bg-green-700">Approve</button>
          <input type="text" placeholder="Rejection reason (required)" value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} className="flex-1 px-2 py-1.5 text-sm border rounded-md" />
          <button onClick={() => rejectReason && onReject(approval.id, rejectReason)} disabled={!rejectReason} className="px-3 py-1.5 text-sm bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50">Reject</button>
        </div>
      ) : (
        <div className="mt-3 text-sm">
          <span className={`font-medium ${approval.status === "approved" ? "text-green-600" : "text-red-600"}`}>{approval.status}</span>
          {approval.reason && <span className="text-muted-foreground"> — {approval.reason}</span>}
        </div>
      )}
    </div>
  );
}
