import React, { useState, useEffect } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";
import { organizationService } from "../../services/organizationService";
import { branchService } from "../../services/branchService"; // ✅ Import BranchService

const UpdateBranch = () => {
  const navigate = useNavigate();
  const { id } = useParams(); // URL se Branch ID milega

  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);

  const [form, setForm] = useState({
    organization: "",
    branchCode: "",
    name: "",
    address: "",
    contactPerson: "", // Backend mein shayad ye field alag naam se ho, check kar lena
    phone: "",
    email: "",
  });

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  // ✅ Load Data (Organizations + Current Branch Info)
  useEffect(() => {
    const loadData = async () => {
      try {
        // 1. Load Orgs for Dropdown
        const orgs = await organizationService.getOrganizations();
        setOrganizations(orgs);

        // 2. Load Current Branch Data from Backend
        const branchData = await branchService.getBranch(id);
        
        // Form ko fill karein
        setForm({
          organization: branchData.tenant || "", // Backend 'tenant' ID bhejta hai
          branchCode: branchData.branch_code,
          name: branchData.name,
          address: branchData.address || "",
          phone: branchData.phone || "",
          email: branchData.email || "",
          contactPerson: branchData.contact_person || "", // Check backend field name
        });

      } catch (error) {
        console.error("Error loading branch data:", error);
        alert("Failed to load branch details.");
        navigate("/organization/branches/list");
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [id, navigate]);

  // ✅ Real Submit Handler
  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!form.organization || !form.name) {
      alert("Please fill all required fields.");
      return;
    }

    // Payload taiyar karein
    const payload = {
      tenant: form.organization, // Backend expects 'tenant'
      name: form.name,
      branch_code: form.branchCode,
      address: form.address,
      phone: form.phone,
      email: form.email,
      // Add other fields if backend supports them
    };

    try {
      await branchService.updateBranch(id, payload);
      alert("Branch updated successfully!");
      navigate("/organization/branches/list");
    } catch (error) {
      console.error("Update failed:", error);
      alert("Failed to update branch. Please try again.");
    }
  };

  if (loading)
    return (
      <MainLayout>
        <div className="p-10 text-center text-gray-500">Loading branch details...</div>
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
          <h1 className="text-2xl font-bold text-gray-800">Update Branch</h1>
          <p className="text-gray-500 text-sm">Edit branch details below</p>
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
              value: o.tenant_id || o.id, // Ensure correct ID usage
            }))}
          />

          <InputField
            label="Branch Name *"
            name="name"
            placeholder="Enter branch name"
            value={form.name}
            onChange={handleChange}
          />

          <InputField
            label="Branch Code"
            name="branchCode"
            value={form.branchCode}
            readOnly // Code usually change nahi hona chahiye
            className="bg-gray-100 cursor-not-allowed"
          />

          <InputField
            label="Email"
            name="email"
            placeholder="Branch email"
            value={form.email}
            onChange={handleChange}
          />

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
            label="Contact Person"
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
            className="w-full bg-blue-600 text-white py-3 rounded-xl font-semibold flex items-center justify-center gap-2 hover:bg-blue-700 transition shadow-md"
          >
            <FiSave /> Update Changes
          </button>
        </form>
      </div>
    </MainLayout>
  );
};

// Helper Components (Same as before)
function InputField({ label, ...props }) {
  return (
    <div className="flex flex-col">
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <input
        {...props}
        className={`mt-2 p-3 rounded-xl bg-gray-50 shadow-sm focus:bg-white outline-none ${props.className || ''}`}
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

export default UpdateBranch;
