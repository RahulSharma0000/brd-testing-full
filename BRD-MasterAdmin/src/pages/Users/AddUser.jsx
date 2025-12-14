// src/pages/users/AddUser.jsx

import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate } from "react-router-dom";

import { organizationService } from "../../services/organizationService";
import { branchService } from "../../services/branchService";
import { userService } from "../../services/userService";

const AddUser = () => {
  const navigate = useNavigate();

  const [organizations, setOrganizations] = useState([]);
  const [branches, setBranches] = useState([]);

  // FORM DATA
  const [form, setForm] = useState({
    email: "",
    phone: "",
    password: "",
    role: "",
    organization: "",
    branch: "",
    status: "Active",
    employee_id: "",
    approval_limit: "",
  });

  // ✅ ROLE MAP → EXACTLY AS IN User.ROLE_CHOICES
  const ROLE_MAP = {
    Admin: "ADMIN",
    "Loan Officer": "LOAN_OFFICER",
    Underwriter: "UNDERWRITER",
    "Finance Staff": "FINANCE_STAFF",
    "Sales Executive": "SALES_EXECUTIVE",
    Borrower: "BORROWER",
  };

  // 🔁 LOAD ORGANIZATIONS
  useEffect(() => {
    (async () => {
      const orgs = await organizationService.getOrganizations();
      setOrganizations(orgs || []);
    })();
  }, []);

  // 🔁 HANDLE CHANGE
  const handleChange = async (e) => {
    const { name, value } = e.target;

    setForm((prev) => ({ ...prev, [name]: value }));

    if (name === "organization") {
      // yaha value tenant/organization identifier hoga
      const br = await branchService.getBranchesByOrg(value);
      setBranches(br || []);
      setForm((prev) => ({ ...prev, branch: "" }));
    }
  };

  // ✅ SIMPLE, CLEAR VALIDATION
  const validateForm = () => {
    if (!form.email) return "Email is required.";
    if (!form.email.endsWith("@gmail.com")) {
      return "Email must be a valid Gmail address (example@gmail.com).";
    }

    if (!form.phone) return "Phone number is required.";
    if (!/^\d{10}$/.test(form.phone)) {
      return "Phone number must be exactly 10 digits.";
    }

    if (!form.password) return "Password is required.";

    if (!form.role) return "Please select a role.";

    // Organization & Branch OPTIONAL from backend POV.
    // Agar tum chaho to yaha role-based required bana sakte ho.

    return null;
  };

  // 📨 SUBMIT
  const handleSubmit = async (e) => {
    e.preventDefault();

    const error = validateForm();
    if (error) {
      alert(error);
      return;
    }

    const payload = {
      email: form.email,
      phone: form.phone,
      password: form.password,
      role: ROLE_MAP[form.role],          // map to backend enum

      // ✅ FIX: Tenant (Organization) bhejna zaroori hai
      tenant: form.organization ? Number(form.organization) : null,

      branch: form.branch ? Number(form.branch) : null,

      employee_id: form.employee_id || "",
      approval_limit:
        form.approval_limit !== "" ? Number(form.approval_limit) : null,

      is_active: form.status === "Active",
      is_staff: false,
      is_superuser: false,
    };

    try {
      await userService.addUser(payload);
      alert("User added successfully!");
      navigate("/users/list");
    } catch (err) {
      console.error("ADD USER ERROR:", err.response?.data || err);
      alert(
        "Error: Unable to add user.\n" +
          JSON.stringify(err.response?.data || {}, null, 2)
      );
    }
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition shadow-sm"
        >
          <FiArrowLeft className="text-gray-700 text-xl" />
        </button>

        <div>
          <h1 className="text-2xl font-bold text-gray-800">Add New User</h1>
          <p className="text-gray-500 text-sm">
            Enter user details and assign role & permissions
          </p>
        </div>
      </div>

      {/* FORM */}
      <div className="bg-white p-8 rounded-2xl shadow-md max-w-3xl">
        <form
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
          onSubmit={handleSubmit}
        >
          <InputField
            name="email"
            label="Email (Gmail only)"
            value={form.email}
            onChange={handleChange}
          />

          <InputField
            name="phone"
            label="Phone Number (10 digits)"
            value={form.phone}
            onChange={handleChange}
          />

          <InputField
            name="password"
            label="Password"
            type="password"
            value={form.password}
            onChange={handleChange}
          />

          <SelectField
            name="role"
            label="User Role"
            value={form.role}
            onChange={handleChange}
            options={[
              "Admin",
              "Loan Officer",
              "Underwriter",
              "Finance Staff",
              "Sales Executive",
              "Borrower",
            ]}
          />

          <SelectField
            name="organization"
            label="Organization"
            value={form.organization}
            onChange={handleChange}
            options={organizations.map((o) => ({
              // depends on your org API; keeping value as o.tenant_id if available
              label: o.name,
              value: o.tenant_id || o.id || "",
            }))}
          />

          <SelectField
            name="branch"
            label="Branch"
            value={form.branch}
            onChange={handleChange}
            options={branches.map((b) => ({
              label: b.name,
              value: b.id,
            }))}
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
              <FiSave /> Add User
            </button>
          </div>
        </form>
      </div>
    </MainLayout>
  );
};

// INPUT FIELD
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

// SELECT FIELD
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

export default AddUser;