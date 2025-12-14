import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { 
  FiArrowLeft, 
  FiTrash2, 
  FiPlus, 
  FiShield, 
  FiX, 
  FiCheckCircle,
  FiAlertCircle 
} from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import { roleService } from "../../services/roleService";

// ✅ Master List: Backend keys ko readable naam dene ke liye
const PERMISSION_LABELS = {
  loan_create: "Create Loan Application",
  loan_approve: "Approve Loan Application",
  loan_edit: "Edit Loan Details",
  view_docs: "View Customer Documents",
  download_docs: "Download Documents",
  edit_policies: "Edit Loan Policies",
  audit_logs: "View Audit Logs",
};

const RoleList = () => {
  const navigate = useNavigate();
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);

  // --- PANEL STATES ---
  const [selectedRole, setSelectedRole] = useState(null); // Abhi kon sa role khula hai
  const [rolePermissions, setRolePermissions] = useState({}); // Us role ki permissions

  // 1. Load All Roles
  const loadRoles = async () => {
    try {
      const data = await roleService.getRoles();
      setRoles(data || []);
    } catch (error) {
      console.error("Error loading roles:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRoles();
  }, []);

  // 2. Delete Entire Role
  const handleDeleteRole = async (id) => {
    if (!window.confirm("Are you sure you want to delete this Role entirely?")) return;
    await roleService.deleteRole(id);
    loadRoles();
    if (selectedRole?.id === id) setSelectedRole(null);
  };

  // 3. Open Permission Panel
  const handleOpenPermissions = async (role) => {
    setSelectedRole(role);
    try {
      // Backend se permissions fetch karein
      const perms = await roleService.getPermissions(role.id);
      setRolePermissions(perms || {});
    } catch (error) {
      console.error("Error fetching permissions:", error);
    }
  };

  // 4. Remove Single Permission
  const handleRemovePermission = async (permKey) => {
    if (!window.confirm(`Remove "${PERMISSION_LABELS[permKey]}" permission from this role?`)) return;

    // Logic: Permission ko 'false' set karke save kar do
    const updatedPerms = { ...rolePermissions, [permKey]: false };

    try {
      await roleService.savePermissions(selectedRole.id, updatedPerms);
      setRolePermissions(updatedPerms); // UI update
    } catch (error) {
      alert("Failed to remove permission.");
    }
  };

  // Helper: Get list of active permissions only
  const activePermsList = Object.keys(rolePermissions).filter(
    (key) => rolePermissions[key] === true
  );

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 shadow-sm transition"
          >
            <FiArrowLeft className="text-gray-700 text-xl" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-800">All Roles</h1>
            <p className="text-gray-500 text-sm">View roles and manage permissions.</p>
          </div>
        </div>

        <button
          onClick={() => navigate("/roles/create")}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2.5 rounded-xl text-sm font-medium hover:bg-blue-700 shadow-sm"
        >
          <FiPlus className="text-lg" /> Create New Role
        </button>
      </div>

      <div className="flex gap-6 relative items-start">
        
        {/* LEFT SECTION: ROLE LIST */}
        <div className={`transition-all duration-300 ${selectedRole ? "w-2/3" : "w-full"}`}>
          <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-6">
            {roles.length === 0 ? (
              <p className="text-gray-500 text-center py-10">No roles found.</p>
            ) : (
              <div className="space-y-4">
                {roles.map((role) => (
                  <div
                    key={role.id}
                    className={`flex items-center justify-between p-5 rounded-xl border transition cursor-pointer ${
                      selectedRole?.id === role.id
                        ? "bg-blue-50 border-blue-500 ring-1 ring-blue-500"
                        : "bg-white border-gray-200 hover:shadow-md"
                    }`}
                    onClick={() => handleOpenPermissions(role)}
                  >
                    <div>
                      <h3 className="font-bold text-gray-800 text-lg">{role.roleName}</h3>
                      <p className="text-sm text-gray-500">
                        {role.description || "Custom Role"}
                      </p>
                    </div>

                    <div className="flex items-center gap-4">
                      {/* Permissions Link */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenPermissions(role);
                        }}
                        className="text-sm text-blue-600 font-medium hover:underline flex items-center gap-1"
                      >
                        Permissions
                      </button>

                      {/* Delete Role Button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteRole(role.id);
                        }}
                        className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition"
                        title="Delete Role"
                      >
                        <FiTrash2 size={18} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT SECTION: PERMISSIONS PANEL (Slide-in) */}
        {selectedRole && (
          <div className="w-1/3 bg-white border border-gray-200 rounded-2xl shadow-xl sticky top-24 animate-fade-in-up">
            
            {/* Panel Header */}
            <div className="flex justify-between items-center p-5 border-b bg-gray-50 rounded-t-2xl">
              <div>
                <h3 className="font-bold text-gray-800 text-lg">
                  {selectedRole.roleName}
                </h3>
                <p className="text-xs text-gray-500">Assigned Permissions</p>
              </div>
              <button 
                onClick={() => setSelectedRole(null)}
                className="p-2 hover:bg-gray-200 rounded-full text-gray-600"
              >
                <FiX size={20} />
              </button>
            </div>

            {/* Panel Body: List of Permissions */}
            <div className="p-5 max-h-[60vh] overflow-y-auto">
              {activePermsList.length === 0 ? (
                <div className="text-center py-10">
                  <FiAlertCircle className="text-4xl text-gray-300 mx-auto mb-3" />
                  <p className="text-gray-500 text-sm">No permissions assigned yet.</p>
                  <button
                    onClick={() => navigate(`/roles/set-permissions?role=${selectedRole.id}`)}
                    className="mt-4 text-blue-600 text-sm font-medium hover:underline"
                  >
                    + Assign Permissions Now
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  {activePermsList.map((key) => (
                    <div
                      key={key}
                      className="flex items-center justify-between p-3 border border-gray-100 bg-gray-50 rounded-lg hover:bg-white hover:shadow-sm transition"
                    >
                      <div className="flex items-center gap-3">
                        <FiCheckCircle className="text-green-600 flex-shrink-0" />
                        <span className="text-sm font-medium text-gray-700">
                          {PERMISSION_LABELS[key] || key}
                        </span>
                      </div>

                      {/* DELETE PERMISSION BUTTON */}
                      <button
                        onClick={() => handleRemovePermission(key)}
                        className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-full transition"
                        title="Remove Permission"
                      >
                        <FiTrash2 size={16} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Panel Footer */}
            <div className="p-4 border-t bg-gray-50 rounded-b-2xl">
              <button
                onClick={() => navigate(`/roles/set-permissions?role=${selectedRole.id}`)}
                className="w-full bg-blue-600 text-white py-2.5 rounded-xl text-sm font-semibold hover:bg-blue-700 transition"
              >
                Manage / Add More
              </button>
            </div>

          </div>
        )}

      </div>
    </MainLayout>
  );
};

export default RoleList;