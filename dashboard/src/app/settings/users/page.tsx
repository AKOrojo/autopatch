"use client";
import { useUsers } from "@/lib/hooks";
import { createUser, updateUser, deleteUser } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { DataTable, type Column } from "@/components/data-table";

export default function UsersPage() {
  const { data: users, isLoading } = useUsers();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");

  const handleCreate = async () => {
    await createUser({ email, name, password, role });
    qc.invalidateQueries({ queryKey: ["users"] });
    setShowForm(false);
    setEmail(""); setName(""); setPassword(""); setRole("viewer");
  };

  const handleRoleChange = async (id: string, newRole: string) => {
    await updateUser(id, { role: newRole });
    qc.invalidateQueries({ queryKey: ["users"] });
  };

  const handleDeactivate = async (id: string) => {
    await deleteUser(id);
    qc.invalidateQueries({ queryKey: ["users"] });
  };

  const columns: Column<Record<string, unknown>>[] = [
    { key: "name", header: "Name" },
    { key: "email", header: "Email" },
    { key: "role", header: "Role", render: (row) => (
      <select value={String(row.role)} onChange={(e) => handleRoleChange(String(row.id), e.target.value)} className="px-2 py-1 border rounded text-sm">
        <option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option>
      </select>
    )},
    { key: "is_active", header: "Active", render: (row) => (
      <span className={`text-sm ${row.is_active ? "text-green-600" : "text-red-600"}`}>{row.is_active ? "Active" : "Inactive"}</span>
    )},
    { key: "last_login_at", header: "Last Login", render: (row) => <span className="text-xs">{row.last_login_at ? new Date(String(row.last_login_at)).toLocaleString() : "Never"}</span> },
    { key: "actions", header: "", render: (row) => row.is_active ? (
      <button onClick={() => handleDeactivate(String(row.id))} className="text-xs text-red-600 hover:underline">Deactivate</button>
    ) : null },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">User Management</h1>
        <button onClick={() => setShowForm(!showForm)} className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">{showForm ? "Cancel" : "Add User"}</button>
      </div>
      {showForm && (
        <div className="border rounded-lg p-4 mb-6 grid grid-cols-2 gap-3">
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="px-3 py-2 border rounded-md text-sm" />
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" className="px-3 py-2 border rounded-md text-sm" />
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="px-3 py-2 border rounded-md text-sm" />
          <select value={role} onChange={(e) => setRole(e.target.value)} className="px-3 py-2 border rounded-md text-sm">
            <option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option>
          </select>
          <button onClick={handleCreate} className="col-span-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">Create User</button>
        </div>
      )}
      <DataTable columns={columns} data={(users || []) as unknown as Record<string, unknown>[]} loading={isLoading} />
    </div>
  );
}
