import React, { useState, useEffect } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";
import { organizationService } from "../../services/organizationService";

export default function EditOrganization() {
  const navigate = useNavigate();
  const { id } = useParams(); // URL se ID milega

  const [form, setForm] = useState({
    name: "",
    email: "",
    phone: "",
    address: "",
    city: "",
    state: "",
    pincode: "",
    tenant_type: "NBFC",
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load Data on Mount
  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await organizationService.getOrganization(id);
        // Form populate karein
        setForm({
          name: data.name || "",
          email: data.email || "",
          phone: data.phone || "",
          address: data.address || "",
          city: data.city || "",
          state: data.state || "",
          pincode: data.pincode || "",
          tenant_type: data.tenant_type || "NBFC",
        });
      } catch (err) {
        setError("Failed to load organization details.");
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [id]);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await organizationService.updateOrganization(id, form);
      alert("Organization updated successfully!");
      navigate("/organization/list");
    } catch (err) {
      alert("Failed to update organization.");
    }
  };

  if (loading) return <MainLayout><div className="p-10">Loading...</div></MainLayout>;

  return (
    <MainLayout>
      <div className="flex items-center gap-3 mb-8">
        <button onClick={() => navigate(-1)} className="p-2 rounded-xl bg-gray-100 hover:bg-gray-200 border">
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>
        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">Edit Organization</h1>
          <p className="text-gray-500 text-sm">Update company details.</p>
        </div>
      </div>

      <div className="bg-white border border-gray-200 p-8 rounded-2xl shadow-sm max-w-4xl">
        {error && <div className="text-red-500 mb-4">{error}</div>}
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <InputField label="Business Name" name="name" value={form.name} onChange={handleChange} required />
            <InputField label="Email" name="email" type="email" value={form.email} onChange={handleChange} required />
            <InputField label="Phone" name="phone" value={form.phone} onChange={handleChange} />
            
            <div>
              <label className="text-gray-700 text-sm font-medium">Type</label>
              <select name="tenant_type" value={form.tenant_type} onChange={handleChange} className="w-full mt-2 p-3 rounded-xl bg-gray-50 border outline-none text-sm">
                <option value="NBFC">NBFC</option>
                <option value="BANK">Bank</option>
                <option value="FINTECH">FinTech</option>
              </select>
            </div>

            <InputField label="City" name="city" value={form.city} onChange={handleChange} />
            <InputField label="State" name="state" value={form.state} onChange={handleChange} />
            <InputField label="Pincode" name="pincode" value={form.pincode} onChange={handleChange} />
          </div>

          <div>
            <label className="text-gray-700 text-sm font-medium">Address</label>
            <textarea name="address" value={form.address} onChange={handleChange} className="w-full mt-2 p-3 rounded-xl bg-gray-50 border outline-none text-sm h-24" />
          </div>

          <button type="submit" className="w-full bg-blue-600 text-white py-3 rounded-xl font-semibold flex justify-center items-center gap-2 hover:bg-blue-700">
            <FiSave /> Update Organization
          </button>
        </form>
      </div>
    </MainLayout>
  );
}

function InputField({ label, ...props }) {
  return (
    <div>
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <input {...props} className="w-full mt-2 p-3 rounded-xl bg-gray-50 border outline-none text-sm" />
    </div>
  );
}