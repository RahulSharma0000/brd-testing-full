import React, { useState, useEffect } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";
import { organizationService } from "../../services/organizationService";

export default function EditOrganization() {
  const navigate = useNavigate();
  const { id } = useParams();

  const [tenantId, setTenantId] = useState("");

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

  /* ---------------- LOAD DATA ---------------- */
  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await organizationService.getOrganization(id);

        setTenantId(data.tenant_id || "");

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

  /* ---------------- SUBMIT ---------------- */
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    try {
      await organizationService.updateOrganization(id, form);
      navigate("/organizations");
    } catch (err) {
      setError("Failed to update organization.");
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="p-10 text-gray-500">Loading organization details...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 transition"
        >
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>

        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">
            Edit Organization
          </h1>
          <p className="text-gray-500 text-sm">
            Update company details
          </p>
        </div>
      </div>

      {/* FORM CARD */}
      <div className="bg-white p-8 rounded-2xl shadow-sm max-w-4xl">
        {error && (
          <div className="mb-6 p-4 bg-red-50 text-red-600 rounded-lg text-sm">
            {error}
          </div>
        )}

        {/* TENANT ID (READ ONLY) */}
        {tenantId && (
          <div className="mb-8 bg-gray-50 p-4 rounded-xl">
            <p className="text-xs text-gray-500">Tenant ID</p>
            <p className="text-sm font-mono text-gray-800 break-all">
              {tenantId}
            </p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <InputField
              label="Business Name"
              name="name"
              placeholder="ABC Finance Pvt Ltd"
              value={form.name}
              onChange={handleChange}
              required
            />

            <InputField
              label="Email Address"
              name="email"
              type="email"
              placeholder="example@company.com"
              value={form.email}
              onChange={handleChange}
              required
            />

            <InputField
              label="Mobile Number"
              name="phone"
              placeholder="9876543210"
              value={form.phone}
              onChange={handleChange}
            />

            <div>
              <label className="text-gray-700 text-sm font-medium">
                Organization Type
              </label>
              <select
                name="tenant_type"
                value={form.tenant_type}
                onChange={handleChange}
                className="w-full mt-2 p-3 rounded-xl bg-gray-50 outline-none text-sm"
              >
                <option value="NBFC">NBFC</option>
                <option value="BANK">Bank</option>
                <option value="FINTECH">FinTech</option>
              </select>
            </div>

            <InputField
              label="City"
              name="city"
              placeholder="Mumbai"
              value={form.city}
              onChange={handleChange}
            />

            <InputField
              label="State"
              name="state"
              placeholder="Maharashtra"
              value={form.state}
              onChange={handleChange}
            />

            <InputField
              label="Pincode"
              name="pincode"
              placeholder="400001"
              value={form.pincode}
              onChange={handleChange}
            />
          </div>

          <div>
            <label className="text-gray-700 text-sm font-medium">
              Address
            </label>
            <textarea
              name="address"
              value={form.address}
              onChange={handleChange}
              placeholder="Complete office address"
              className="w-full mt-2 p-3 rounded-xl bg-gray-50 outline-none text-sm h-24"
            />
          </div>

          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold flex justify-center items-center gap-2 hover:bg-blue-700 transition"
          >
            <FiSave className="text-lg" />
            Update Organization
          </button>
        </form>
      </div>
    </MainLayout>
  );
}

/* ---------------- INPUT FIELD ---------------- */
function InputField({ label, ...props }) {
  return (
    <div>
      <label className="text-gray-700 text-sm font-medium">
        {label}
      </label>
      <input
        {...props}
        className="w-full mt-2 p-3 rounded-xl bg-gray-50 outline-none text-sm"
      />
    </div>
  );
}
