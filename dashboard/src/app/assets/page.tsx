"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getAssets, deleteAsset, type Asset } from "@/lib/api";
import { DataTable, type Column } from "@/components/data-table";
import { Pagination } from "@/components/pagination";
import { AddAssetDialog } from "@/components/add-asset-dialog";
import { EditAssetDialog } from "@/components/edit-asset-dialog";
import { Button } from "@/components/ui/button";
import { Pencil, Trash2, X } from "lucide-react";

export default function AssetsPage() {
  const router = useRouter();
  const [data, setData] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
  const [deleting, setDeleting] = useState(false);
  const limit = 50;

  const fetchAssets = useCallback(() => {
    setLoading(true);
    getAssets(limit, offset)
      .then((res) => { setData(res.data); setTotal(res.total); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const handleDelete = async () => {
    if (!deletingAsset) return;
    setDeleting(true);
    try {
      await deleteAsset(deletingAsset.id);
      setDeletingAsset(null);
      fetchAssets();
    } catch (err) {
      console.error(err);
    } finally {
      setDeleting(false);
    }
  };

  const columns: Column<Asset>[] = [
    { key: "hostname", header: "Hostname" },
    { key: "ip_address", header: "IP Address" },
    { key: "os_family", header: "OS" },
    { key: "environment", header: "Environment" },
    { key: "criticality", header: "Criticality" },
    {
      key: "actions",
      header: "",
      render: (row) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={() => setEditingAsset(row)}
            className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title="Edit asset"
          >
            <Pencil className="size-4" />
          </button>
          <button
            onClick={() => setDeletingAsset(row)}
            className="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
            title="Delete asset"
          >
            <Trash2 className="size-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Assets</h1>
          <p className="mt-1 text-muted-foreground">Manage and monitor your infrastructure assets.</p>
        </div>
        <AddAssetDialog onAssetAdded={fetchAssets} />
      </div>

      <DataTable
        columns={columns}
        data={data}
        loading={loading}
        onRowClick={(row) => router.push(`/assets/${row.id}`)}
      />
      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />

      {editingAsset && (
        <EditAssetDialog
          asset={editingAsset}
          onClose={() => setEditingAsset(null)}
          onSaved={fetchAssets}
        />
      )}

      {deletingAsset && (
        <>
          <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={() => setDeletingAsset(null)} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                <h2 className="text-lg font-semibold">Delete Asset</h2>
                <button onClick={() => setDeletingAsset(null)} className="text-muted-foreground hover:text-foreground transition-colors">
                  <X className="size-5" />
                </button>
              </div>
              <div className="px-6 py-5 space-y-4">
                <p className="text-sm text-muted-foreground">
                  Are you sure you want to delete{" "}
                  <span className="font-medium text-foreground">{deletingAsset.hostname}</span>{" "}
                  ({deletingAsset.ip_address})? This cannot be undone.
                </p>
                <div className="flex justify-end gap-3">
                  <Button variant="outline" onClick={() => setDeletingAsset(null)}>
                    Cancel
                  </Button>
                  <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
                    {deleting ? "Deleting..." : "Delete"}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
