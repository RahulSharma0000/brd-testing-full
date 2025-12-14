import { useEffect, useState, useMemo } from "react";
import { userAPI } from "../services/userService";
import { tenantAPI } from "../services/tenantService";

// Allowed roles for Tenant Admin
const ROLE_OPTIONS = [
  { value: "LOAN_OFFICER", label: "Loan Officer" },
  { value: "UNDERWRITER", label: "Underwriter" },
  { value: "FINANCE_STAFF", label: "Finance Staff" },
  { value: "SALES_EXECUTIVE", label: "Sales Executive" },
  { value: "BORROWER", label: "Borrower" },
];

export default function Users() {
  const currentTenant = sessionStorage.getItem("tenant_id");

  const emptyForm = {
    email: "",
    first_name: "",
    last_name: "",
    phone: "",
    role: "BORROWER",
    tenant: currentTenant,
    password: "",
  };

  const [users, setUsers] = useState([]);
  const [tenants, setTenants] = useState([]);

  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const [search, setSearch] = useState("");
  const [modalError, setModalError] = useState("");
  const [form, setForm] = useState(emptyForm);

  // ---------------- LOAD USERS ----------------
  const loadUsers = async () => {
    try {
      const res = await userAPI.getAll();
      let list = res.data || [];

      // Remove global/system users
      list = list.filter(
        (u) =>
          u.role !== "MASTER_ADMIN" &&
          u.role !== "SUPER_ADMIN" &&
          u.role !== "ADMIN"
      );

      // Only users from this tenant
      list = list.filter((u) => u.tenant === currentTenant);

      setUsers(list);
    } catch (err) {
      console.log("Error loading users", err);
    }
  };

  // ---------------- LOAD TENANTS ----------------
  const loadTenants = async () => {
    try {
      const res = await tenantAPI.getAll();
      setTenants(res.data || []);
    } catch (err) {
      console.log("Error loading tenants", err);
    }
  };

  useEffect(() => {
    loadUsers();
    loadTenants();
  }, []);

  // Tenant Map for edit modal
  const tenantMap = useMemo(() => {
    const map = {};
    tenants.forEach((t) => {
      map[t.tenant_id] = t.name || t.company_name || t.business_name || t.slug;
    });
    return map;
  }, [tenants]);

  // -------- Search Filter --------
  const filteredUsers = useMemo(() => {
    const s = search.toLowerCase();
    return users.filter(
      (u) =>
        u.email.toLowerCase().includes(s) ||
        `${u.first_name} ${u.last_name}`.toLowerCase().includes(s) ||
        u.role.toLowerCase().includes(s)
    );
  }, [users, search]);

  // ---------------- CREATE USER ----------------
  const createUser = async () => {
    setModalError("");

    if (!form.email || !form.password) {
      setModalError("Email and password are required!");
      return;
    }

    const payload = {
      ...form,
      tenant: currentTenant,
    };

    try {
      await userAPI.create(payload);
      setCreating(false);
      setForm(emptyForm);
      loadUsers();
    } catch (err) {
      console.log(err.response?.data);
      setModalError("Failed to create user.");
    }
  };

  // ---------------- UPDATE USER ----------------
  const updateUser = async () => {
    setModalError("");

    const payload = { ...editing };
    if (!payload.password) delete payload.password;

    // Tenant cannot be changed
    delete payload.tenant;

    try {
      await userAPI.update(editing.id, payload);
      setEditing(null);
      loadUsers();
    } catch (err) {
      setModalError("Failed to update user.");
    }
  };

  // ---------------- DELETE USER ----------------
  const deleteUser = async () => {
    try {
      await userAPI.delete(deleting.id);
      setDeleting(null);
      loadUsers();
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <div className="p-4 space-y-4">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Users</h1>

        <button
          className="h-9 px-4 rounded-lg bg-primary-600 text-white"
          onClick={() => {
            setForm(emptyForm);
            setCreating(true);
            setModalError("");
          }}
        >
          + Add User
        </button>
      </div>

      {/* SEARCH */}
      <input
        className="border px-3 py-2 rounded-lg w-72"
        placeholder="Search user by name/email/role"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {/* TABLE */}
      <div className="bg-white rounded-xl border shadow-sm overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b text-gray-600">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Email</th>
              <th className="px-4 py-3">Phone</th>
              <th className="px-4 py-3">Role</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>

          <tbody>
            {filteredUsers.map((u) => (
              <tr key={u.id} className="border-t">
                <td className="px-4 py-3">
                  {u.first_name} {u.last_name}
                </td>
                <td className="px-4 py-3">{u.email}</td>
                <td className="px-4 py-3">{u.phone || "-"}</td>
                <td className="px-4 py-3">{u.role}</td>

                <td className="px-4 py-3 flex gap-2">
                  <button
                    className="px-3 py-1 border rounded"
                    onClick={() => setEditing({ ...u, password: "" })}
                  >
                    Edit
                  </button>

                  <button
                    className="px-3 py-1 border border-red-400 text-red-600 rounded"
                    onClick={() => setDeleting(u)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}

            {!filteredUsers.length && (
              <tr>
                <td colSpan={5} className="p-4 text-center text-gray-600">
                  No users found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ---------- CREATE MODAL ---------- */}
      {creating && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center z-50">
          <div className="bg-white w-full max-w-lg rounded-xl p-6 shadow-lg">
            <h2 className="text-lg font-semibold">Add User</h2>

            {modalError && (
              <div className="mt-2 bg-red-100 text-red-600 p-2 rounded">
                {modalError}
              </div>
            )}

            <div className="mt-4 space-y-3">
              <input
                className="border w-full rounded px-3 py-2"
                placeholder="First Name"
                value={form.first_name}
                onChange={(e) =>
                  setForm({ ...form, first_name: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Last Name"
                value={form.last_name}
                onChange={(e) =>
                  setForm({ ...form, last_name: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Email"
                type="email"
                value={form.email}
                onChange={(e) =>
                  setForm({ ...form, email: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Phone"
                value={form.phone}
                onChange={(e) =>
                  setForm({ ...form, phone: e.target.value })
                }
              />

              {/* Allowed Roles Only */}
              <select
                className="border w-full rounded px-3 py-2"
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}
              >
                {ROLE_OPTIONS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>

              {/* Tenant Auto-Assigned */}
              <input type="hidden" value={currentTenant} readOnly />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Password"
                type="password"
                value={form.password}
                onChange={(e) =>
                  setForm({ ...form, password: e.target.value })
                }
              />
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                className="px-4 py-2 border rounded"
                onClick={() => setCreating(false)}
              >
                Cancel
              </button>

              <button
                className="px-4 py-2 bg-primary-600 text-white rounded"
                onClick={createUser}
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---------- EDIT MODAL ---------- */}
      {editing && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center z-50">
          <div className="bg-white w-full max-w-lg rounded-xl p-6 shadow-lg">
            <h2 className="text-lg font-semibold">Edit User</h2>

            {modalError && (
              <div className="mt-2 bg-red-100 text-red-600 p-2 rounded">
                {modalError}
              </div>
            )}

            <div className="mt-4 space-y-3">
              <input
                className="border w-full rounded px-3 py-2"
                placeholder="First Name"
                value={editing.first_name}
                onChange={(e) =>
                  setEditing({ ...editing, first_name: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Last Name"
                value={editing.last_name}
                onChange={(e) =>
                  setEditing({ ...editing, last_name: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Email"
                type="email"
                value={editing.email}
                onChange={(e) =>
                  setEditing({ ...editing, email: e.target.value })
                }
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="Phone"
                value={editing.phone}
                onChange={(e) =>
                  setEditing({ ...editing, phone: e.target.value })
                }
              />

              {/* Allowed roles only */}
              <select
                className="border w-full rounded px-3 py-2"
                value={editing.role}
                onChange={(e) =>
                  setEditing({ ...editing, role: e.target.value })
                }
              >
                {ROLE_OPTIONS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>

              {/* Tenant cannot be edited */}
              <input
                disabled
                className="border w-full rounded px-3 py-2 bg-gray-100"
                value={tenantMap[editing.tenant] || "Tenant"}
              />

              <input
                className="border w-full rounded px-3 py-2"
                placeholder="New Password (optional)"
                type="password"
                value={editing.password}
                onChange={(e) =>
                  setEditing({ ...editing, password: e.target.value })
                }
              />
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                className="px-4 py-2 border rounded"
                onClick={() => setEditing(null)}
              >
                Cancel
              </button>

              <button
                className="px-4 py-2 bg-primary-600 text-white rounded"
                onClick={updateUser}
              >
                Update
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---------- DELETE MODAL ---------- */}
      {deleting && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center z-50">
          <div className="bg-white w-full max-w-md rounded-xl p-6 shadow-lg text-center">
            <h2 className="text-lg font-semibold">Delete User</h2>

            <p className="mt-2">
              Are you sure you want to delete{" "}
              <b>{deleting.first_name + " " + deleting.last_name}</b>?
            </p>

            <div className="mt-6 flex justify-center gap-2">
              <button
                className="px-4 py-2 border rounded"
                onClick={() => setDeleting(null)}
              >
                Cancel
              </button>

              <button
                className="px-4 py-2 bg-red-600 text-white rounded"
                onClick={deleteUser}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
