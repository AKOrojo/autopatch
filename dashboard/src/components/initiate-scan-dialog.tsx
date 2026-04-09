"use client";

import { useState, useEffect } from "react";
import { createScan, getAssets, type Asset } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Scan, X, Check } from "lucide-react";

const SCANNER_TYPES = [
  { value: "openvas", label: "OpenVAS", desc: "Network vulnerability scanner" },
  { value: "trivy", label: "Trivy", desc: "Container & OS package scanner" },
  { value: "nuclei", label: "Nuclei", desc: "Web vulnerability scanner" },
];

interface InitiateScanDialogProps {
  onScanCreated: () => void;
}

export function InitiateScanDialog({ onScanCreated }: InitiateScanDialogProps) {
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<string>>(new Set());
  const [scannerType, setScannerType] = useState("openvas");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    if (open) {
      setLoadingAssets(true);
      getAssets(200, 0)
        .then((res) => setAssets(res.data))
        .catch(console.error)
        .finally(() => setLoadingAssets(false));
    }
  }, [open]);

  const toggleAsset = (id: string) => {
    setSelectedAssetIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedAssetIds.size === filteredAssets.length) {
      setSelectedAssetIds(new Set());
    } else {
      setSelectedAssetIds(new Set(filteredAssets.map((a) => a.id)));
    }
  };

  const filteredAssets = assets.filter(
    (a) =>
      a.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.ip_address.includes(searchQuery)
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (selectedAssetIds.size === 0) {
      setError("Select at least one asset to scan.");
      return;
    }

    setSubmitting(true);
    try {
      const promises = Array.from(selectedAssetIds).map((asset_id) =>
        createScan({ asset_id, scanner_type: scannerType })
      );
      await Promise.all(promises);
      setSelectedAssetIds(new Set());
      setScannerType("openvas");
      setSearchQuery("");
      setOpen(false);
      onScanCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initiate scan.");
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) {
    return (
      <Button onClick={() => setOpen(true)}>
        <Scan data-icon="inline-start" />
        Initiate Scan
      </Button>
    );
  }

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={() => setOpen(false)} />

      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center justify-between px-6 py-4 border-b border-border">
            <h2 className="text-lg font-semibold">Initiate Scan</h2>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground transition-colors">
              <X className="size-5" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
            {error && (
              <div className="rounded-lg bg-destructive/10 text-destructive px-4 py-2.5 text-sm">
                {error}
              </div>
            )}

            {/* Scanner Type */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground">Scanner Type</label>
              <div className="grid grid-cols-3 gap-2">
                {SCANNER_TYPES.map((s) => (
                  <button
                    key={s.value}
                    type="button"
                    onClick={() => setScannerType(s.value)}
                    className={`rounded-lg border px-3 py-2 text-left text-sm transition-colors ${
                      scannerType === s.value
                        ? "border-primary bg-primary/5 text-foreground"
                        : "border-border text-muted-foreground hover:border-primary/50"
                    }`}
                  >
                    <div className="font-medium">{s.label}</div>
                    <div className="text-xs mt-0.5 opacity-70">{s.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Asset Selection */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-foreground">
                  Target Assets <span className="text-destructive ml-0.5">*</span>
                </label>
                {selectedAssetIds.size > 0 && (
                  <span className="text-xs text-muted-foreground">{selectedAssetIds.size} selected</span>
                )}
              </div>

              {loadingAssets ? (
                <div className="field-input text-muted-foreground animate-pulse">Loading assets...</div>
              ) : assets.length === 0 ? (
                <div className="field-input text-muted-foreground">No assets available. Add an asset first.</div>
              ) : (
                <>
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by hostname or IP..."
                    className="field-input"
                  />
                  <div className="border border-border rounded-lg max-h-48 overflow-y-auto">
                    {/* Select all */}
                    <label className="flex items-center gap-3 px-3 py-2 border-b border-border cursor-pointer hover:bg-muted/50 transition-colors">
                      <span className={`flex items-center justify-center size-4 rounded border transition-colors ${
                        selectedAssetIds.size === filteredAssets.length && filteredAssets.length > 0
                          ? "bg-primary border-primary text-primary-foreground"
                          : "border-input"
                      }`}>
                        {selectedAssetIds.size === filteredAssets.length && filteredAssets.length > 0 && <Check className="size-3" />}
                      </span>
                      <button type="button" onClick={toggleAll} className="text-sm font-medium text-foreground">
                        Select all ({filteredAssets.length})
                      </button>
                    </label>

                    {filteredAssets.map((asset) => (
                      <label
                        key={asset.id}
                        className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-muted/50 transition-colors"
                      >
                        <span className={`flex items-center justify-center size-4 rounded border transition-colors ${
                          selectedAssetIds.has(asset.id)
                            ? "bg-primary border-primary text-primary-foreground"
                            : "border-input"
                        }`}>
                          {selectedAssetIds.has(asset.id) && <Check className="size-3" />}
                        </span>
                        <button type="button" onClick={() => toggleAsset(asset.id)} className="flex-1 text-left">
                          <span className="text-sm font-medium">{asset.hostname}</span>
                          <span className="text-xs text-muted-foreground ml-2">{asset.ip_address}</span>
                          <span className="text-xs text-muted-foreground ml-2">{asset.environment}</span>
                        </button>
                      </label>
                    ))}

                    {filteredAssets.length === 0 && (
                      <div className="px-3 py-4 text-sm text-muted-foreground text-center">No assets match your search.</div>
                    )}
                  </div>
                </>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={submitting || selectedAssetIds.size === 0}>
                {submitting
                  ? "Starting..."
                  : `Scan ${selectedAssetIds.size || ""} Asset${selectedAssetIds.size !== 1 ? "s" : ""}`}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}
