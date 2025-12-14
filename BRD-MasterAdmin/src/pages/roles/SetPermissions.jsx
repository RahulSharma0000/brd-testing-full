import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiCheckCircle, FiSave, FiLoader } from "react-icons/fi";
import { useNavigate, useSearchParams } from "react-router-dom";
import { roleService } from "../../services/roleService";

// Master List of Permissions
const PERMISSION_LIST = [
  { key: "loan_create", label: "Create Loan", desc: "Can create new loan applications" },
  { key: "loan_approve", label: "Approve Loan", desc: "Authority to approve/reject loans" },
  { key: "loan_edit", label: "Edit Loan", desc: "Can modify loan details" },
  { key: "view_docs", label: "View Documents", desc: "Can view uploaded customer documents" },
  { key: "download_docs", label: "Download Documents", desc: "Can download KYC files" },
  { key: "edit_policies", label: "Edit Policies", desc: "Can change interest rates & policies" },
  { key: "audit_logs", label: "View Audit Logs", desc: "Access to system audit trails" },
];

const SetPermissions = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const preSelectedRoleId = searchParams.get("role"); // URL se role ID lena (agar hai to)

  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState("");
  const [permissions, setPermissions] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  // 1. Load Roles on Mount
  useEffect(() => {
    const fetchRoles = async () => {
      const data = await roleService.getRoles();
      setRoles(data || []);
      
      // Agar URL me role ID hai, to use auto-select karein
      if (preSelectedRoleId) {
        handleRoleChange(preSelectedRoleId);
      }
    };
    fetchRoles();
  }, []);

  // 2. Handle Role Selection & Fetch Permissions
  const handleRoleChange = async (roleId) => {
    setSelectedRole(roleId);
    if (!roleId) {
      setPermissions({});
      return;
    }

    setLoading(true);
    try {
      const data = await roleService.getPermissions(roleId);
      setPermissions(data || {});
    } catch (error) {
      console.error("Error fetching permissions");
    } finally {
      setLoading(false);
    }
  };

  // 3. Toggle Permission Checkbox
  const togglePermission = (key) => {
    setPermissions((prev) => ({
      ...prev,
      [key]: !prev[key], // True <-> False
    }));
  };

  // 4. Save Changes
  const handleSave = async () => {
    if (!selectedRole) return alert("Please select a role first.");

    setSaving(true);
    try {
      await roleService.savePermissions(selectedRole, permissions);
      alert("Permissions updated successfully!");
      navigate("/roles/list"); // Wapas list par bhejein
    } catch (error) {
      alert("Failed to save permissions.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 shadow-sm transition"
        >
          <FiArrowLeft className="text-gray-700 text-xl" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-gray-800">Set Permissions</h1>
          <p className="text-gray-500 text-sm">
            Configure access levels for system roles.
          </p>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-8">
        
        {/* LEFT: SELECT ROLE */}
        <div className="w-full lg:w-1/3">
          <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200">
            <label className="text-gray-700 font-semibold mb-2 block">
              Select Role to Configure
            </label>
            <select
              value={selectedRole}
              onChange={(e) => handleRoleChange(e.target.value)}
              className="w-full p-3 bg-gray-50 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500 transition"
            >
              <option value="">-- Choose Role --</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.roleName}
                </option>
              ))}
            </select>
            
            <p className="text-xs text-gray-500 mt-3">
              Selecting a role will fetch its current active permissions.
            </p>
          </div>
        </div>

        {/* RIGHT: PERMISSIONS LIST */}
        <div className="w-full lg:w-2/3">
          <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-200">
            
            {!selectedRole ? (
              <div className="text-center py-10 text-gray-400">
                Please select a role from the left panel to view permissions.
              </div>
            ) : loading ? (
              <div className="text-center py-10 flex flex-col items-center">
                <FiLoader className="animate-spin text-2xl text-blue-600 mb-2"/>
                <span className="text-gray-500">Loading permissions...</span>
              </div>
            ) : (
              <>
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-bold text-gray-800">Manage Access</h3>
                  <span className="text-sm bg-blue-50 text-blue-700 px-3 py-1 rounded-full">
                    {roles.find(r => r.id == selectedRole)?.roleName}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {PERMISSION_LIST.map((perm) => {
                    const isChecked = permissions[perm.key] === true;
                    
                    return (
                      <div
                        key={perm.key}
                        onClick={() => togglePermission(perm.key)}
                        className={`p-4 rounded-xl border cursor-pointer transition-all flex items-start gap-3 ${
                          isChecked
                            ? "bg-blue-50 border-blue-500 ring-1 ring-blue-500"
                            : "bg-white border-gray-200 hover:border-blue-300"
                        }`}
                      >
                        <div className={`mt-1 w-5 h-5 rounded border flex items-center justify-center ${
                          isChecked ? "bg-blue-600 border-blue-600" : "bg-white border-gray-400"
                        }`}>
                          {isChecked && <FiCheckCircle className="text-white text-xs" />}
                        </div>

                        <div>
                          <p className={`font-semibold text-sm ${isChecked ? "text-blue-800" : "text-gray-700"}`}>
                            {perm.label}
                          </p>
                          <p className="text-xs text-gray-500 mt-0.5">{perm.desc}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-8 border-t pt-6 flex justify-end">
                  <button
                    onClick={handleSave}
                    disabled={saving}
                    className="bg-blue-600 text-white px-6 py-3 rounded-xl font-semibold flex items-center gap-2 hover:bg-blue-700 transition shadow-md disabled:opacity-70"
                  >
                    {saving ? <FiLoader className="animate-spin" /> : <FiSave />}
                    {saving ? "Saving..." : "Save Changes"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

      </div>
    </MainLayout>
  );
};

export default SetPermissions;