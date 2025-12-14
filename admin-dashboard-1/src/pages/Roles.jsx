import { useEffect, useState } from "react";
import { roleAPI } from "../services/roleService";

export default function Roles() {
  const [roles, setRoles] = useState([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const emptyForm = {
    name: "",
    description: "",
    parent_role: "",
    permissions: {},
  };

  const [form, setForm] = useState(emptyForm);

  // ----------------------------
  // LOAD ROLES
  // ----------------------------
  const load = async () => {
    try {
      const res = await roleAPI.list();
      setRoles(res.data || []);
    } catch (err) {
      console.log("Failed to load roles", err);
    }
  };

  useEffect(() => {
    load();
  }, []);

  // ----------------------------
  // CREATE ROLE
  // ----------------------------
  const createRole = async () => {
    try {
      await roleAPI.create(form);
      setOpen(false);
      setForm(emptyForm);
      load();
    } catch (err) {
      console.log(err);
    }
  };

  // ----------------------------
  // UPDATE ROLE
  // ----------------------------
  const updateRole = async () => {
    try {
      await roleAPI.update(editing.id, form);
      setEditing(null);
      setForm(emptyForm);
      load();
    } catch (err) {
      console.log(err);
    }
  };

  // ----------------------------
  // DELETE ROLE
  // ----------------------------
  const deleteRole = async () => {
    try {
      await roleAPI.delete(deleting.id);
      setDeleting(null);
      load();
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <div className="p-4">
      {/* HEADER */}
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold">Roles & Permissions</h1>

        <button
          className="h-9 px-4 rounded-lg bg-primary-600 text-white"
          onClick={() => {
            setForm(emptyForm);
            setOpen(true);
          }}
        >
          Create Role
        </button>
      </div>

      {/* ROLES TABLE */}
      <div className="bg-white rounded-lg border shadow-sm overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b text-gray-600">
              <th className="px-4 py-3">Role Name</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">System Role</th>
              <th className="px-4 py-3">Action</th>
            </tr>
          </thead>

          <tbody>
            {roles.map((r) => (
              <tr key={r.id} className="border-t">
                <td className="px-4 py-3 font-medium">{r.name}</td>
                <td className="px-4 py-3">{r.description || "-"}</td>
                <td className="px-4 py-3">{r.parent_role_name || "-"}</td>

                <td className="px-4 py-3 flex gap-2">
                  <button
                    className="px-3 py-1 rounded border"
                    onClick={() => {
                      setEditing(r);
                      setForm({
                        name: r.name,
                        description: r.description,
                        parent_role: r.parent_role,
                        permissions: r.permissions || {},
                      });
                    }}
                  >
                    Edit
                  </button>

                  <button
                    className="px-3 py-1 rounded border border-red-400 text-red-600"
                    onClick={() => setDeleting(r)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}

            {!roles.length && (
              <tr>
                <td colSpan={4} className="text-center p-4">
                  No roles available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* CREATE / EDIT MODAL */}
      {(open || editing) && (
        <Modal
          title={editing ? "Edit Role" : "Create Role"}
          onClose={() => {
            setOpen(false);
            setEditing(null);
          }}
        >
          <div className="space-y-3">
            <input
              className="border w-full rounded px-3 py-2"
              placeholder="Role Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />

            <textarea
              className="border w-full rounded px-3 py-2"
              placeholder="Description"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
            />

            <select
              className="border w-full rounded px-3 py-2"
              value={form.parent_role}
              onChange={(e) =>
                setForm({ ...form, parent_role: e.target.value })
              }
            >
              <option value="">Select Parent Role</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>

            <button
              className="px-4 py-2 bg-primary-600 text-white rounded"
              onClick={editing ? updateRole : createRole}
            >
              Save
            </button>
          </div>
        </Modal>
      )}

      {/* DELETE CONFIRMATION */}
      {deleting && (
        <Modal title="Delete Role" onClose={() => setDeleting(null)}>
          <p>Are you sure you want to delete <b>{deleting.name}</b>?</p>

          <div className="flex justify-end gap-2 mt-4">
            <button
              className="px-4 py-2 border rounded"
              onClick={() => setDeleting(null)}
            >
              Cancel
            </button>
            <button
              className="px-4 py-2 bg-red-600 text-white rounded"
              onClick={deleteRole}
            >
              Delete
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Modal({ title, children, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white w-full max-w-md rounded-xl p-6 shadow-lg relative">
        <h2 className="text-lg font-semibold">{title}</h2>
        <div className="mt-4">{children}</div>
        <button className="absolute top-4 right-4" onClick={onClose}>
          ✕
        </button>
      </div>
    </div>
  );
}
