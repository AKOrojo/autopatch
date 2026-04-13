"use client";

import { useState, useEffect } from "react";
import { updateAsset, type Asset, type AssetUpdate } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { X } from "lucide-react";

const ENVIRONMENTS = ["production", "staging", "development", "testing"];
const CRITICALITIES = ["critical", "high", "medium", "low"];

interface EditAssetDialogProps {
  asset: Asset;
  onClose: () => void;
  onSaved: () => void;
}

export function EditAssetDialog({ asset, onClose, onSaved }: EditAssetDialogProps) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<AssetUpdate>({
    hostname: asset.hostname,
    ip_address: asset.ip_address,
    os_family: asset.os_family ?? "",
    os_version: asset.os_version ?? "",
    environment: asset.environment,
    criticality: asset.criticality,
  });

  useEffect(() => {
    setForm({
      hostname: asset.hostname,
      ip_address: asset.ip_address,
      os_family: asset.os_family ?? "",
      os_version: asset.os_version ?? "",
      environment: asset.environment,
      criticality: asset.criticality,
    });
  }, [asset]);

  const updateField = <K extends keyof AssetUpdate>(key: K, value: AssetUpdate[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!form.hostname?.trim() || !form.ip_address?.trim()) {
      setError("Hostname and IP address are required.");
      return;
    }

    setSubmitting(true);
    try {
      await updateAsset(asset.id, {
        ...form,
        os_family: form.os_family || undefined,
        os_version: form.os_version || undefined,
      });
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update asset.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={onClose} />

      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between px-6 py-4 border-b border-border">
            <h2 className="text-lg font-semibold">Edit Asset</h2>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
              <X className="size-5" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
            {error && (
              <div className="rounded-lg bg-destructive/10 text-destructive px-4 py-2.5 text-sm">
                {error}
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <FieldGroup label="Hostname" required>
                <input
                  type="text"
                  value={form.hostname ?? ""}
                  onChange={(e) => updateField("hostname", e.target.value)}
                  placeholder="e.g. web-server-01"
                  className="field-input"
                  required
                />
              </FieldGroup>
              <FieldGroup label="IP Address" required>
                <input
                  type="text"
                  value={form.ip_address ?? ""}
                  onChange={(e) => updateField("ip_address", e.target.value)}
                  placeholder="e.g. 10.0.1.50"
                  className="field-input"
                  required
                />
              </FieldGroup>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FieldGroup label="OS Family">
                <input
                  type="text"
                  value={form.os_family ?? ""}
                  onChange={(e) => updateField("os_family", e.target.value)}
                  placeholder="e.g. Ubuntu, Windows"
                  className="field-input"
                />
              </FieldGroup>
              <FieldGroup label="OS Version">
                <input
                  type="text"
                  value={form.os_version ?? ""}
                  onChange={(e) => updateField("os_version", e.target.value)}
                  placeholder="e.g. 22.04"
                  className="field-input"
                />
              </FieldGroup>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FieldGroup label="Environment">
                <select
                  value={form.environment}
                  onChange={(e) => updateField("environment", e.target.value)}
                  className="field-input"
                >
                  {ENVIRONMENTS.map((env) => (
                    <option key={env} value={env}>{env.charAt(0).toUpperCase() + env.slice(1)}</option>
                  ))}
                </select>
              </FieldGroup>
              <FieldGroup label="Criticality">
                <select
                  value={form.criticality}
                  onChange={(e) => updateField("criticality", e.target.value)}
                  className="field-input"
                >
                  {CRITICALITIES.map((c) => (
                    <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
                  ))}
                </select>
              </FieldGroup>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={submitting}>
                {submitting ? "Saving..." : "Save Changes"}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}

function FieldGroup({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="text-sm font-medium text-foreground">
        {label}
        {required && <span className="text-destructive ml-0.5">*</span>}
      </label>
      {children}
    </div>
  );
}
