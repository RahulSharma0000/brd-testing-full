import { useEffect, useState } from "react";
import { rolesApi } from "../services/api.js";

export default function RolesPermissions() {
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState(null);
  const [creating, setCreating] = useState(false);
  const [newRole, setNewRole] = useState({
    name: "",
    description: "",
    permissions: {
      loan_create: false,
      loan_approve: false,
      loan_edit: false,
      view_docs: false,
      download_docs: false,
      audit_logs: false,
      edit_policies: false,
    },
  });

  const [matrixRole, setMatrixRole] = useState(null);
  const [matrix, setMatrix] = useState([]);
  const [matrixLoading, setMatrixLoading] = useState(false);
  const [matrixError, setMatrixError] = useState(null);

  // ---------------------
  // Load roles
  // ---------------------
  const loadRoles = async () => {
    setError(null);
    const res = await rolesApi.list();
    if (res.ok) {
      setRoles(
        (res.data || [])
          .filter((r) => r.name !== "Super Admin")
          .map((r) => ({ ...r, role_id: r.role_id || r.id })) // ensure role_id exists
      );
    } else {
      setError("Unable to load roles");
    }
  };

  useEffect(() => {
    loadRoles();
  }, []);

  // ---------------------
  // Open Permissions Matrix
  // ---------------------
  const openMatrix = async (r) => {
    setMatrixRole(r);
    setMatrix([]);
    setMatrixError(null);
    setMatrixLoading(true);

    const res = await rolesApi.getPermissions(r.role_id);
    setMatrixLoading(false);

    if (res.ok) {
      let permsArray;

      // If response is an array of granted permissions
      if (Array.isArray(res.data)) {
        const allPerms = Object.keys(newRole.permissions); // same permission keys
        permsArray = [
          {
            module: "Permissions",
            permissions: allPerms.map((key) => ({
              permission_id: key,
              name: key.replace(/_/g, " "),
              is_granted: res.data.includes(key),
            })),
          },
        ];
      } else {
        // If response is object
        permsArray = [
          {
            module: "Permissions",
            permissions: Object.keys(res.data).map((key) => ({
              permission_id: key,
              name: key.replace(/_/g, " "),
              is_granted: res.data[key],
            })),
          },
        ];
      }

      setMatrix(permsArray);
    } else {
      setMatrixError("Unable to load permissions");
    }
  };

  // ---------------------
  // Toggle permission
  // ---------------------
  const togglePerm = (permId) => {
    setMatrix((prev) =>
      prev.map((group) => ({
        ...group,
        permissions: group.permissions.map((p) =>
          p.permission_id === permId ? { ...p, is_granted: !p.is_granted } : p
        ),
      }))
    );
  };

  // ---------------------
  // Save permissions matrix
  // ---------------------
  const saveMatrix = async () => {
    const granted = matrix.flatMap((g) =>
      g.permissions.filter((p) => p.is_granted).map((p) => p.permission_id)
    );

    const res = await rolesApi.updatePermissions(matrixRole.role_id, granted);
    if (res.ok) {
      setMatrixRole(null);
      loadRoles(); // reload roles to update permissions
    } else {
      alert("Failed to save permissions");
    }
  };

  // ---------------------
  // Create Role
  // ---------------------
  const createRole = async () => {
    const payload = {
      name: newRole.name,
      description: newRole.description,
      permissions: newRole.permissions,
    };

    const res = await rolesApi.create(payload);
    if (res.ok) {
      setCreating(false);
      setNewRole({
        name: "",
        description: "",
        permissions: {
          loan_create: false,
          loan_approve: false,
          loan_edit: false,
          view_docs: false,
          download_docs: false,
          audit_logs: false,
          edit_policies: false,
        },
      });
      loadRoles();
    } else {
      console.error("Error creating role:", res);
      alert("Failed to create role");
    }
  };

  // ---------------------
  // Render
  // ---------------------
  return (
    <div className="p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="text-xl font-semibold">Roles & Permissions</div>
        <button
          className="h-9 px-3 rounded-lg bg-primary-600 text-white"
          onClick={() => setCreating(true)}
        >
          Create Role
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-50 text-red-700 border border-red-200 rounded-lg p-3">
          {error}
        </div>
      )}

      {/* Roles table */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-card overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-600">
              <th className="px-4 py-3">Role Name</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">Action</th>
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.role_id} className="border-t border-gray-100">
                <td className="px-4 py-3 font-medium">{r.name}</td>
                <td className="px-4 py-3">{r.description}</td>
                <td className="px-4 py-3 flex gap-2">
                  <button
                    className="h-8 px-3 rounded-lg border border-gray-200"
                    onClick={() => openMatrix(r)}
                  >
                    Manage Permissions
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create Role Modal */}
      {creating && (
        <div className="fixed inset-0 bg-black/25 grid place-items-center z-40">
          <div className="bg-white w-full max-w-lg rounded-xl border border-gray-200 shadow-card p-4">
            <div className="text-lg font-semibold">Create Role</div>
            <div className="mt-3 space-y-3">
              <label className="block">
                <div className="text-sm text-gray-700">Role Name</div>
                <input
                  value={newRole.name}
                  onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                  className="mt-1 w-full h-9 rounded-lg border border-gray-300 px-3"
                />
              </label>
              <label className="block">
                <div className="text-sm text-gray-700">Description</div>
                <input
                  value={newRole.description}
                  onChange={(e) =>
                    setNewRole({ ...newRole, description: e.target.value })
                  }
                  className="mt-1 w-full h-9 rounded-lg border border-gray-300 px-3"
                />
              </label>

              {/* Permissions checkboxes */}
              <div className="mt-2">
                <div className="font-medium mb-1 text-gray-700">Permissions</div>
                <div className="grid grid-cols-2 gap-2">
                  {Object.keys(newRole.permissions).map((key) => (
                    <label key={key} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={newRole.permissions[key]}
                        onChange={() =>
                          setNewRole({
                            ...newRole,
                            permissions: {
                              ...newRole.permissions,
                              [key]: !newRole.permissions[key],
                            },
                          })
                        }
                      />
                      <span>{key.replace(/_/g, " ")}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-3">
                <button
                  className="h-9 px-3 rounded-lg border border-gray-200"
                  onClick={() => setCreating(false)}
                >
                  Cancel
                </button>
                <button
                  className="h-9 px-3 rounded-lg bg-primary-600 text-white"
                  onClick={createRole}
                >
                  Create
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Permissions Matrix Modal */}
      {matrixRole && (
        <div className="fixed inset-0 bg-black/25 grid place-items-center z-40">
          <div className="bg-white w-full max-w-2xl rounded-xl border border-gray-200 shadow-card p-4">
            <div className="flex items-center justify-between">
              <div className="text-lg font-semibold">
                Manage Permissions • {matrixRole.name}
              </div>
              <button
                className="h-9 px-3 rounded-lg border border-gray-200"
                onClick={() => setMatrixRole(null)}
              >
                Close
              </button>
            </div>
            <div className="mt-3 space-y-4">
              {matrixLoading && (
                <div className="text-sm text-gray-600">Loading permissions...</div>
              )}
              {matrixError && (
                <div className="bg-red-50 text-red-700 border border-red-200 rounded-lg p-3 text-sm">
                  {matrixError}
                </div>
              )}
              {Array.isArray(matrix) &&
                matrix.map((group) => (
                  <div
                    key={group.module || group.id}
                    className="border border-gray-100 rounded-lg p-3"
                  >
                    <div className="font-medium mb-2">{group.module}</div>
                    <div className="grid grid-cols-2 gap-2">
                      {group.permissions.map((p) => (
                        <label
                          key={p.permission_id}
                          className="flex items-center gap-2 text-sm"
                        >
                          <input
                            type="checkbox"
                            checked={p.is_granted}
                            onChange={() => togglePerm(p.permission_id)}
                          />
                          <span>
                            {p.name} ({p.permission_id})
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
            </div>
            <div className="mt-3 flex justify-end">
              <button
                className="h-9 px-3 rounded-lg bg-primary-600 text-white disabled:opacity-60"
                disabled={!matrix.length || matrixLoading}
                onClick={saveMatrix}
              >
                Save Permissions
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
