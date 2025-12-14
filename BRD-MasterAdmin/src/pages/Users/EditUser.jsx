// src/pages/users/EditUser.jsx

import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";

import { organizationService } from "../../services/organizationService";
import { branchService } from "../../services/branchService";
import { userService } from "../../services/userService";

const EditUser = () => {
  const navigate = useNavigate();
  const { id } = useParams(); // <-- user ID from URL

  const [loading, setLoading] = useState(true);
  const [organizations, setOrganizations] = useState([]);
  const [branches, setBranches] = useState([]);

  // FORM STATE
  const [form, setForm] = useState({
    email: "",
    phone: "",
    password: "",
    role: "",
    organization: "",
    branch: "",
    status: "Active",
    employee_id: "",
    approval_limit: 0,
  });

  // ROLE MAP (backend-format)
  const ROLE_MAP = {
    Admin: "ADMIN",
    "Branch Manager": "BRANCH_MANAGER",
    "Loan Officer": "LOAN_OFFICER",
    "Field Staff": "FIELD_STAFF",
  };

  const ROLE_MAP_REVERSE = {
    ADMIN: "Admin",
    BRANCH_MANAGER: "Branch Manager",
    LOAN_OFFICER: "Loan Officer",
    FIELD_STAFF: "Field Staff",
  };

  // ---------------------
  // LOAD INITIAL DATA
  // ---------------------
  useEffect(() => {
    (async () => {
      try {
        // Load orgs
        const orgs = await organizationService.getOrganizations();
        setOrganizations(orgs);

        // Load user details
        const u = await userService.getUser(id);

        // Load branches based on user's org
        let br = [];
        if (u.tenant) {
          br = await branchService.getBranchesByOrg(u.tenant);
        }
        setBranches(br);

        // Prefill form
        setForm({
          email: u.email,
          phone: u.phone,
          password: "",
          role: ROLE_MAP_REVERSE[u.role] || "",

          organization: u.tenant || "",
          branch: u.branch || "",

          status: u.is_active ? "Active" : "Inactive",
          employee_id: u.employee_id || "",
          approval_limit: u.approval_limit || 0,
        });

        setLoading(false);
      } catch (err) {
        console.error("Error loading user:", err);
        alert("Unable to load user details.");
        navigate("/users/list");
      }
    })();
  }, [id]);

  // ---------------------
  // ON CHANGE
  // ---------------------
  const handleChange = async (e) => {
    const { name, value } = e.target;

    setForm((prev) => ({ ...prev, [name]: value }));

    if (name === "organization") {
      const br = await branchService.getBranchesByOrg(value);
      setBranches(br);
      setForm((prev) => ({ ...prev, branch: "" }));
    }
  };

  // ---------------------
  // SUBMIT
  // ---------------------
  const handleSubmit = async (e) => {
    e.preventDefault();

    const payload = {
      email: form.email,
      phone: form.phone,
      role: ROLE_MAP[form.role] || null,

      tenant: form.organization ? Number(form.organization) : null,
      branch: form.branch ? Number(form.branch) : null,

      employee_id: form.employee_id || "",
      approval_limit: Number(form.approval_limit) || 0,

      is_active: form.status === "Active",
    };

    // Only send password if user typed something
    if (form.password.trim() !== "") {
      payload.password = form.password;
    }

    try {
      await userService.updateUser(id, payload);
      alert("User updated successfully!");
      navigate("/users/list");
    } catch (err) {
      console.error("UPDATE ERROR:", err.response?.data || err);
      alert("Unable to update user. Check console.");
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <p className="text-center text-gray-500 py-10">Loading user...</p>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition shadow-sm"
        >
          <FiArrowLeft className="text-gray-700 text-xl" />
        </button>

        <div>
          <h1 className="text-2xl font-bold text-gray-800">Edit User</h1>
          <p className="text-gray-500 text-sm">Update user information & settings</p>
        </div>
      </div>

      <div className="bg-white p-8 rounded-2xl shadow-md max-w-3xl">
        <form className="grid grid-cols-1 md:grid-cols-2 gap-6" onSubmit={handleSubmit}>

          <InputField name="email" label="Email" value={form.email} onChange={handleChange} />
          <InputField name="phone" label="Phone Number" value={form.phone} onChange={handleChange} />

          {/* Password is optional */}
          <InputField
            name="password"
            label="Password (Leave blank to keep unchanged)"
            type="password"
            value={form.password}
            onChange={handleChange}
          />

          <SelectField
            name="role"
            label="User Role"
            value={form.role}
            onChange={handleChange}
            options={["Admin", "Branch Manager", "Loan Officer", "Field Staff"]}
          />

          <SelectField
            name="organization"
            label="Organization"
            value={form.organization}
            onChange={handleChange}
            options={organizations.map((o) => ({ label: o.name, value: o.id }))}
          />

          <SelectField
            name="branch"
            label="Branch"
            value={form.branch}
            onChange={handleChange}
            options={branches.map((b) => ({ label: b.name, value: b.id }))}
          />

          <InputField
            name="employee_id"
            label="Employee ID"
            value={form.employee_id}
            onChange={handleChange}
          />

          <InputField
            name="approval_limit"
            label="Approval Limit"
            type="number"
            value={form.approval_limit}
            onChange={handleChange}
          />

          <SelectField
            name="status"
            label="Status"
            value={form.status}
            onChange={handleChange}
            options={["Active", "Inactive"]}
          />

          <div className="md:col-span-2">
            <button className="w-full bg-blue-600 text-white py-3 rounded-xl flex items-center justify-center gap-2 hover:bg-blue-700 transition shadow-md">
              <FiSave /> Update User
            </button>
          </div>

        </form>
      </div>
    </MainLayout>
  );
};

// Input Field Component
const InputField = ({ label, type = "text", name, value, onChange }) => (
  <div className="flex flex-col">
    <label className="text-gray-700 text-sm font-medium">{label}</label>
    <input
      type={type}
      name={name}
      value={value}
      onChange={onChange}
      className="mt-2 p-3 rounded-xl bg-gray-50 focus:bg-white shadow-sm outline-none"
    />
  </div>
);

// Select Field Component
const SelectField = ({ label, name, value, onChange, options }) => (
  <div className="flex flex-col">
    <label className="text-gray-700 text-sm font-medium">{label}</label>
    <select
      name={name}
      value={value}
      onChange={onChange}
      className="mt-2 p-3 rounded-xl bg-gray-50 shadow-sm outline-none"
    >
      <option value="">Select {label}</option>
      {options.map((op, i) => (
        <option key={i} value={op.value || op}>
          {op.label || op}
        </option>
      ))}
    </select>
  </div>
);

export default EditUser;
