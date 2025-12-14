import { useEffect, useMemo, useState } from 'react'
import { branchAPI } from "../services/branchService";

const statusBadge = (active) => {
  return active
    ? "inline-flex px-3 py-1 rounded-full bg-green-50 text-green-700 border border-green-200"
    : "inline-flex px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-200";
};

export default function Branches() {

  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);

  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const [validationError, setValidationError] = useState("");

  const [search, setSearch] = useState("");

  const [form, setForm] = useState({
    name: "",
    phone: "",
    address: "",
    branch_code: "",
    is_active: true,
  });

  // -----------------------------
  // VALIDATION FUNCTION
  // -----------------------------
  const validateBranch = (data) => {
    if (!data.branch_code.trim()) return "Branch Code is required";
    if (!/^[A-Za-z0-9_-]+$/.test(data.branch_code))
      return "Branch Code must contain only letters, numbers, - or _";

    if (!data.name.trim()) return "Branch Name is required";
    if (data.name.length < 3) return "Branch Name must be at least 3 characters";

    if (data.phone) {
      if (!/^[0-9]{7,15}$/.test(data.phone))
        return "Phone must be a valid number (7-15 digits)";
    }

    if (data.address && data.address.length < 3)
      return "Address must be at least 3 characters";

    return null;
  };

  // --------------------------------------
  // LOAD BRANCHES
  // --------------------------------------
  const loadBranches = async () => {
    try {
      const res = await branchAPI.getAll();

      let data = [];
      if (Array.isArray(res)) data = res;
      else if (Array.isArray(res.data)) data = res.data;
      else if (Array.isArray(res.results)) data = res.results;
      else if (Array.isArray(res.branches)) data = res.branches;

      setItems(data);
    } catch (err) {
      console.log(err);
      setError("Unable to load branches");
    }
  };

  useEffect(() => {
    loadBranches();
  }, []);

  // --------------------------------------
  // FILTER BRANCHES
  // --------------------------------------
  const filteredItems = useMemo(() => {
    const s = search.toLowerCase();
    return items.filter(b =>
      b.name?.toLowerCase().includes(s) ||
      b.phone?.toLowerCase().includes(s) ||
      b.branch_code?.toLowerCase().includes(s)
    );
  }, [items, search]);

  // --------------------------------------
  // CREATE BRANCH
  // --------------------------------------
  const saveBranch = async () => {
    const errorMsg = validateBranch(form);
    if (errorMsg) {
      setValidationError(errorMsg);
      return;
    }

    try {
      const payload = {
        name: form.name,
        phone: form.phone,
        address: form.address,
        branch_code: form.branch_code,
        is_active: form.is_active,
      };

      const res = await branchAPI.create(payload);
      setItems([...items, res]);

      setCreating(false);
      setValidationError("");

    } catch (e) {
      console.log(e.response?.data);
      setValidationError("Error creating branch");
    }
  };

  // --------------------------------------
  // UPDATE BRANCH
  // --------------------------------------
  const updateBranch = async () => {
    const errorMsg = validateBranch(editing);
    if (errorMsg) {
      setValidationError(errorMsg);
      return;
    }

    try {
      const payload = {
        name: editing.name,
        phone: editing.phone,
        address: editing.address,
        branch_code: editing.branch_code,
        is_active: editing.is_active,
      };

      const res = await branchAPI.update(editing.id, payload);
      setItems(items.map(b => (b.id === editing.id ? res : b)));

      setEditing(null);
      setValidationError("");
    } catch (e) {
      setValidationError("Unable to update branch");
    }
  };

  // --------------------------------------
  // DELETE BRANCH
  // --------------------------------------
  const deleteBranch = async () => {
    try {
      await branchAPI.delete(deleting.id);
      setItems(items.filter(b => b.id !== deleting.id));
      setDeleting(null);
    } catch (e) {
      alert("Unable to delete branch");
    }
  };


  return (
    <div className="p-4 space-y-4">

      <div className="flex justify-between">
        <h1 className="text-xl font-semibold">Manage Branches</h1>
        <button
          className="px-3 py-1 bg-primary-600 text-white rounded"
          onClick={() => {
            setCreating(true);
            setForm({
              name: "",
              phone: "",
              address: "",
              branch_code: "",
              is_active: true,
            });
            setValidationError("");
          }}
        >
          + Add Branch
        </button>
      </div>

      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search branch"
        className="border px-3 py-1 rounded w-64"
      />

      <div className="bg-white rounded-xl shadow border overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-600 border-b">
              <th className="px-4 py-3">Branch Code</th>
              <th className="px-4 py-3">Branch Name</th>
              <th className="px-4 py-3">Phone</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>

          <tbody>
            {filteredItems.map((b) => (
              <tr key={b.id} className="border-t">
                <td className="px-4 py-3">{b.branch_code}</td>
                <td className="px-4 py-3">{b.name}</td>
                <td className="px-4 py-3">{b.phone}</td>
                <td className="px-4 py-3">
                  <span className={statusBadge(b.is_active)}>
                    {b.is_active ? "Active" : "Inactive"}
                  </span>
                </td>

                <td className="px-4 py-3 flex gap-2">
                  <button
                    className="px-2 py-1 border rounded"
                    onClick={() => {
                      setEditing(b);
                      setValidationError("");
                    }}
                  >
                    Edit
                  </button>
                  <button
                    className="px-2 py-1 border border-red-300 text-red-600 rounded"
                    onClick={() => setDeleting(b)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}

            {!items.length && (
              <tr>
                <td colSpan={5} className="text-center py-3 text-gray-600">
                  No branches found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* VALIDATION ERROR */}
      {validationError && (
        <div className="text-red-600 font-medium">{validationError}</div>
      )}

      {/* CREATE MODAL */}
      {creating && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center">
          <div className="bg-white rounded-xl p-4 w-full max-w-lg">

            <h2 className="text-lg font-semibold">Create Branch</h2>

            <label className="block mt-3">
              Branch Code
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={form.branch_code}
                onChange={(e) => setForm({ ...form, branch_code: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Branch Name
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Phone
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={form.phone}
                onChange={(e) => setForm({ ...form, phone: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Address
              <textarea
                className="border w-full mt-1 px-2 py-1 rounded"
                value={form.address}
                onChange={(e) => setForm({ ...form, address: e.target.value })}
              />
            </label>

            <div className="mt-4 flex justify-end gap-2">
              <button className="px-3 py-1 border rounded" onClick={() => setCreating(false)}>
                Cancel
              </button>
              <button className="px-3 py-1 bg-primary-600 text-white rounded" onClick={saveBranch}>
                Save
              </button>
            </div>

          </div>
        </div>
      )}

      {/* EDIT MODAL */}
      {editing && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center">
          <div className="bg-white rounded-xl p-4 w-full max-w-lg">

            <h2 className="text-lg font-semibold">Edit Branch</h2>

            <label className="block mt-3">
              Branch Code
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={editing.branch_code}
                onChange={(e) => setEditing({ ...editing, branch_code: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Branch Name
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={editing.name}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Phone
              <input
                className="border w-full mt-1 px-2 py-1 rounded"
                value={editing.phone}
                onChange={(e) => setEditing({ ...editing, phone: e.target.value })}
              />
            </label>

            <label className="block mt-3">
              Address
              <textarea
                className="border w-full mt-1 px-2 py-1 rounded"
                value={editing.address}
                onChange={(e) => setEditing({ ...editing, address: e.target.value })}
              />
            </label>

            <div className="mt-4 flex justify-end gap-2">
              <button className="px-3 py-1 border rounded" onClick={() => setEditing(null)}>
                Cancel
              </button>
              <button className="px-3 py-1 bg-primary-600 text-white rounded" onClick={updateBranch}>
                Update
              </button>
            </div>

          </div>
        </div>
      )}

      {/* DELETE MODAL */}
      {deleting && (
        <div className="fixed inset-0 bg-black/30 grid place-items-center">
          <div className="bg-white rounded-xl p-4 w-full max-w-md">

            <div className="text-lg font-semibold">Delete Branch</div>
            <div className="mt-3">
              Are you sure you want to delete <b>{deleting.name}</b>?
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <button className="px-3 py-1 border rounded" onClick={() => setDeleting(null)}>
                Cancel
              </button>
              <button className="px-3 py-1 bg-red-600 text-white rounded" onClick={deleteBranch}>
                Delete
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
