"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { analyzeVulnerability } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Wrench } from "lucide-react";

interface LaunchRemediationButtonProps {
  vulnerabilityId: string;
  status: string;
}

export function LaunchRemediationButton({ vulnerabilityId, status }: LaunchRemediationButtonProps) {
  const router = useRouter();
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const alreadyRemediated = status === "remediated" || status === "in_progress";

  const handleLaunch = async () => {
    setError(null);
    setLaunching(true);
    try {
      const result = await analyzeVulnerability(vulnerabilityId);
      router.push(`/remediations/${result.task_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to launch remediation.");
      setLaunching(false);
    }
  };

  return (
    <div>
      <Button onClick={handleLaunch} disabled={launching || alreadyRemediated}>
        <Wrench data-icon="inline-start" />
        {launching ? "Launching..." : alreadyRemediated ? "Already Remediated" : "Launch Remediation"}
      </Button>
      {error && <p className="text-sm text-destructive mt-2">{error}</p>}
    </div>
  );
}
