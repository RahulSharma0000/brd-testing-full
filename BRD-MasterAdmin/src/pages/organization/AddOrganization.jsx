import React, { useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import { organizationService } from "../../services/organizationService";

export default function AddOrganization() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    business_name: "",
    email: "",
    mobile_no: "",
    address: "",
    contact_person: "",
    loan_product: [],
    password: "",
    gst_in: "",
    pan: "",
    cin: "",
    isVerified: false,
    isDeleted: false,
    created_user: "master_admin",
    modified_user: "master_admin",
  });

  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState(null);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLoanProducts = (e) => {
    const value = e.target.value
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item !== "");
    setForm({ ...form, loan_product: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrors(null);

    try {
      const payload = {
      name: form.business_name,
      tenant_type: "NBFC", // or hardcode a default or map from frontend
      email: form.email,
      phone: form.mobile_no,
      address: form.address,
      city: "",     // leave blank or add extra field if you want
      state: "",    // leave blank
      pincode: "",  // leave blank
      is_active: true,
    };

      await organizationService.addOrganization(payload);

      navigate("/organizations");
    } catch (err) {
      setErrors("Something went wrong while saving organization.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => navigate(-1)}
          className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 transition border border-gray-200"
        >
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>

        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">
            Add New Organization
          </h1>
          <p className="text-gray-500 text-sm">
            Enter company details to register a new organization.
          </p>
        </div>
      </div>

      {/* FORM */}
      <div className="bg-white border border-gray-200 p-8 rounded-2xl shadow-sm max-w-4xl">

        {errors && (
          <div className="mb-6 p-4 bg-red-50 text-red-600 rounded-lg text-sm border border-red-200">
            {errors}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-10">

          {/* GRID FIELDS */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

            <InputField
              label="Business Name *"
              name="business_name"
              placeholder="ABC Finance Pvt Ltd"
              value={form.business_name}
              onChange={handleChange}
              required
            />

            <InputField
              label="Email Address *"
              name="email"
              type="email"
              placeholder="example@company.com"
              value={form.email}
              onChange={handleChange}
              required
            />

            <InputField
              label="Mobile Number *"
              name="mobile_no"
              placeholder="9876543210"
              value={form.mobile_no}
              onChange={handleChange}
              required
            />

            <InputField
              label="Contact Person *"
              name="contact_person"
              placeholder="Rahul Sharma"
              value={form.contact_person}
              onChange={handleChange}
              required
            />

            <InputField
              label="Password *"
              name="password"
              type="password"
              placeholder="Set login password"
              value={form.password}
              onChange={handleChange}
              required
            />

            <InputField
              label="GST Number"
              name="gst_in"
              placeholder="22AAAAA0000A1Z5"
              value={form.gst_in}
              onChange={handleChange}
              maxLength={15}
            />

            <InputField
              label="PAN Number"
              name="pan"
              placeholder="ABCDE1234F"
              value={form.pan}
              onChange={handleChange}
              maxLength={10}
            />

            <InputField
              label="CIN Number"
              name="cin"
              placeholder="U12345MH2020PTC123456"
              value={form.cin}
              onChange={handleChange}
            />
          </div>

          {/* ADDRESS */}
          <div>
            <label className="text-gray-700 text-sm font-medium">
              Full Address *
            </label>
            <textarea
              name="address"
              value={form.address}
              onChange={handleChange}
              required
              placeholder="Head Office Address"
              className="w-full mt-2 p-3 rounded-xl bg-gray-50 border border-gray-200 focus:bg-white outline-none text-sm"
            />
          </div>

          {/* LOAN PRODUCTS */}
          <div>
            <InputField
              label="Loan Products (comma separated) *"
              name="loan_product"
              placeholder="Gold Loan, Personal Loan"
              onChange={handleLoanProducts}
            />
          </div>

          {/* SUBMIT BUTTON */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold flex items-center justify-center gap-2 hover:bg-blue-700 transition text-sm"
          >
            <FiSave className="text-lg" />
            {loading ? "Saving..." : "Save Organization"}
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
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <input
        {...props}
        className="w-full mt-2 p-3 rounded-xl bg-gray-50 border border-gray-200 focus:bg-white outline-none text-sm"
      />
    </div>
  );
}
