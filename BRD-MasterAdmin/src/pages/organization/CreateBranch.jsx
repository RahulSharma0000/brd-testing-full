import React, { useState, useEffect } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import { organizationService } from "../../services/organizationService";
import { branchService } from "../../services/branchService";

const CreateBranch = () => {
  const navigate = useNavigate();

  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);

  const [form, setForm] = useState({
    organization: "",
    branchCode: "", // ✅ branch code
    name: "",
    address: "",
    contactPerson: "",
    phone: "",
  });

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  // Load organizations
  useEffect(() => {
    const load = async () => {
      const orgs = await organizationService.getOrganizations();
      setOrganizations(orgs);
      setLoading(false);
    };
    load();
  }, []);

  // Generate branch code when organization or name changes
  useEffect(() => {
    if (form.organization && form.name) {
      const orgPrefix =
        organizations
          .find((o) => o.tenant_id === form.organization)
          ?.name.replace(/\s+/g, "")
          .substring(0, 3)
          .toUpperCase() || "ORG";
      const namePrefix = form.name
        .replace(/\s+/g, "")
        .substring(0, 3)
        .toUpperCase();
      setForm((prev) => ({
        ...prev,
        branchCode: `${orgPrefix}-${namePrefix}-${Date.now()}`, // unique branch code
      }));
    }
  }, [form.organization, form.name, organizations]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (
      !form.organization ||
      !form.name ||
      !form.address ||
      !form.contactPerson ||
      !form.phone
    ) {
      alert("Please fill all fields.");
      return;
    }

    const payload = {
      tenant: form.organization, 
      branch_code: form.branchCode,
      name: form.name,
      address: form.address,
      phone: form.phone,
    };

    console.log("Branch Payload:", payload);
    await branchService.addBranch(payload);
    navigate("/organization/branches/list");
  };

  if (loading)
    return (
      <MainLayout>
        <p className="text-gray-600 text-sm">Loading organizations...</p>
      </MainLayout>
    );

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition shadow-sm"
        >
          <FiArrowLeft className="text-xl text-gray-700" />
        </button>

        <div>
          <h1 className="text-2xl font-bold text-gray-800">Create Branch</h1>
          <p className="text-gray-500 text-sm">Fill in the branch details below</p>
        </div>
      </div>

      {/* FORM */}
      <div className="bg-white p-8 rounded-2xl shadow-md max-w-2xl">
        <form onSubmit={handleSubmit} className="space-y-7">
          <SelectField
            label="Select Organization *"
            name="organization"
            value={form.organization}
            onChange={handleChange}
            options={organizations.map((o) => ({
              label: o.name,
              value: o.tenant_id, // ✅ CORRECT
            }))}
          />

          <InputField
            label="Branch Name *"
            name="name"
            placeholder="Enter branch name"
            value={form.name}
            onChange={handleChange}
          />

          {/* Branch Code */}
          <InputField
            label="Branch Code"
            name="branchCode"
            value={form.branchCode}
            readOnly
          />

          {/* Address */}
          <div className="flex flex-col">
            <label className="text-gray-700 text-sm font-medium">
              Branch Address *
            </label>
            <textarea
              name="address"
              value={form.address}
              onChange={handleChange}
              placeholder="Full branch address"
              className="mt-2 p-3 h-24 rounded-xl bg-gray-50 shadow-sm focus:bg-white outline-none"
            />
          </div>

          <InputField
            label="Contact Person *"
            name="contactPerson"
            value={form.contactPerson}
            onChange={handleChange}
            placeholder="Enter contact name"
          />

          <InputField
            label="Phone Number *"
            name="phone"
            value={form.phone}
            onChange={handleChange}
            placeholder="+91 XXXXX XXXXX"
          />

          <button
            type="submit"
            className="w-full bg-green-600 text-white py-3 rounded-xl font-semibold flex items-center justify-center gap-2 hover:bg-green-700 transition shadow-md"
          >
            <FiSave /> Create Branch
          </button>
        </form>
      </div>
    </MainLayout>
  );
};

function InputField({ label, ...props }) {
  return (
    <div className="flex flex-col">
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <input
        {...props}
        className="mt-2 p-3 rounded-xl bg-gray-50 shadow-sm focus:bg-white outline-none"
      />
    </div>
  );
}

function SelectField({ label, options = [], ...props }) {
  return (
    <div className="flex flex-col">
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <select
        {...props}
        className="mt-2 p-3 rounded-xl bg-gray-50 shadow-sm outline-none focus:bg-white"
      >
        <option value="">Choose option</option>
        {options.map((op, idx) => (
          <option key={idx} value={op.value}>
            {op.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export default CreateBranch;