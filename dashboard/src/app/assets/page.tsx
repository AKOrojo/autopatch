"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getAssets, type Asset } from "@/lib/api";
import { DataTable, type Column } from "@/components/data-table";
import { Pagination } from "@/components/pagination";
import { AddAssetDialog } from "@/components/add-asset-dialog";

const columns: Column<Asset>[] = [
  { key: "hostname", header: "Hostname" },
  { key: "ip_address", header: "IP Address" },
  { key: "os_family", header: "OS" },
  { key: "environment", header: "Environment" },
  { key: "criticality", header: "Criticality" },
];

export default function AssetsPage() {
  const router = useRouter();
  const [data, setData] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const limit = 50;

  const fetchAssets = useCallback(() => {
    setLoading(true);
    getAssets(limit, offset).then((res) => { setData(res.data); setTotal(res.total); }).catch(console.error).finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Assets</h1>
          <p className="mt-1 text-muted-foreground">Manage and monitor your infrastructure assets.</p>
        </div>
        <AddAssetDialog onAssetAdded={fetchAssets} />
      </div>
      <DataTable columns={columns} data={data} loading={loading} onRowClick={(row) => router.push(`/assets/${row.id}`)} />
      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />
    </div>
  );
}
