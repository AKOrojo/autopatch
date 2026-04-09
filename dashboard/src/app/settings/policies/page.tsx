"use client";
import { usePolicies } from "@/lib/hooks";
import { updateApprovalPolicy } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";

export default function PoliciesPage() {
  const { data: policies, isLoading } = usePolicies();
  const qc = useQueryClient();
  const tiers = ["dev", "staging", "prod"];

  const handleUpdate = async (tier: string, field: string, value: number | boolean) => {
    await updateApprovalPolicy(tier, { [field]: value });
    qc.invalidateQueries({ queryKey: ["policies"] });
  };

  const getPolicy = (tier: string) =>
    policies?.find((p) => p.asset_tier === tier) || { max_auto_approve_cvss: 7.0, auto_approve_config_only: true, require_approval_for_service_restart: true };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Approval Policies</h1>
      {isLoading ? (
        <div className="animate-pulse space-y-4">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-32 bg-muted rounded-lg" />)}</div>
      ) : (
        <div className="space-y-6">
          {tiers.map((tier) => {
            const policy = getPolicy(tier);
            return (
              <div key={tier} className="border rounded-lg p-6">
                <h2 className="text-lg font-semibold capitalize mb-4">{tier}</h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Max auto-approve CVSS</label>
                    <input type="number" step="0.1" min="0" max="10" defaultValue={policy.max_auto_approve_cvss}
                      onBlur={(e) => handleUpdate(tier, "max_auto_approve_cvss", parseFloat(e.target.value))} className="w-20 px-2 py-1 border rounded text-sm text-right" />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Auto-approve config-only changes</label>
                    <input type="checkbox" defaultChecked={policy.auto_approve_config_only}
                      onChange={(e) => handleUpdate(tier, "auto_approve_config_only", e.target.checked)} className="h-4 w-4" />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Require approval for service restarts</label>
                    <input type="checkbox" defaultChecked={policy.require_approval_for_service_restart}
                      onChange={(e) => handleUpdate(tier, "require_approval_for_service_restart", e.target.checked)} className="h-4 w-4" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
