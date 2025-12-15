import React, { useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import { organizationService } from "../../services/organizationService";

export default function AddOrganization() {
  const navigate = useNavigate();

  /* ---------------- STATE ---------------- */
  const [form, setForm] = useState({
    business_name: "",
    email: "",
    mobile_no: "",
    address: "",
    contact_person: "",
    loan_product: [],
    gst_in: "",
    pan: "",
    cin: "",
  });

  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState(null);

  // success popup
  const [successData, setSuccessData] = useState(null);
  const [showSuccess, setShowSuccess] = useState(false);

  /* ---------------- HANDLERS ---------------- */
  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLoanProducts = (e) => {
    const value = e.target.value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    setForm({ ...form, loan_product: value });
  };

  /* ---------------- VALIDATION ---------------- */
const validateForm = () => {
  // Business Name
  if (!form.business_name.trim())
    return "Business name is required";
  if (form.business_name.trim().length < 3)
    return "Business name must be at least 3 characters";

  // Email
  if (!form.email.trim())
    return "Email is required";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
    return "Enter a valid email address";

  // Mobile Number
  if (!form.mobile_no.trim())
    return "Mobile number is required";
  if (!/^[0-9]{10}$/.test(form.mobile_no))
    return "Mobile number must be exactly 10 digits";

  // Contact Person
  if (!form.contact_person.trim())
    return "Contact person is required";
  if (form.contact_person.trim().length < 3)
    return "Contact person must be at least 3 characters";

  // Address
  if (!form.address.trim())
    return "Address is required";
  if (form.address.trim().length < 10)
    return "Address must be at least 10 characters";

  // Loan Products
  if (!form.loan_product || form.loan_product.length === 0)
    return "At least one loan product is required";

  // GST (optional but validated if present)
  if (
    form.gst_in &&
    !/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/.test(
      form.gst_in.toUpperCase()
    )
  )
    return "Invalid GST number format";

  // PAN (optional but validated if present)
  if (
    form.pan &&
    !/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(form.pan.toUpperCase())
  )
    return "PAN must be in format ABCDE1234F";

  // CIN (optional but validated if present)
  if (
    form.cin &&
    !/^[A-Z]{1}[0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$/.test(
      form.cin.toUpperCase()
    )
  )
    return "Invalid CIN number format";

  return null;
};


  /* ---------------- SUBMIT ---------------- */
  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrors(null);

    const validationError = validateForm();
    if (validationError) {
      setErrors(validationError);
      return;
    }

    setLoading(true);

    try {
      const payload = {
        name: form.business_name,
        tenant_type: "NBFC",
        email: form.email,
        phone: form.mobile_no,
        address: form.address,
        city: "",
        state: "",
        pincode: "",
        is_active: true,
      };

      const response = await organizationService.addOrganization(payload);

      // ✅ confirm tenant_id received
      if (response?.data?.tenant_id) {
        setSuccessData(response.data);
        setShowSuccess(true);

        // ✅ auto redirect after 2 seconds
        setTimeout(() => {
          navigate("/organization/list");
        }, 100);
      } else {
        setErrors("Tenant added but tenant ID not received from server.");
      }
    } catch (err) {
      if (err.response?.data) {
        const firstError = Object.values(err.response.data)[0];
        setErrors(Array.isArray(firstError) ? firstError[0] : firstError);
      } else {
        setErrors("Something went wrong while saving organization.");
      }
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
          className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 transition"
        >
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>

        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">
            Add New Organization
          </h1>
          <p className="text-gray-500 text-sm">
            Enter company details to register a new organization
          </p>
        </div>
      </div>

      {/* FORM */}
      <div className="bg-white p-8 rounded-2xl shadow-sm max-w-4xl">
        {errors && (
          <div className="mb-6 p-4 bg-red-50 text-red-600 rounded-lg text-sm">
            {errors}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-10">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <InputField
              label="Business Name *"
              name="business_name"
              placeholder="ABC Finance Pvt Ltd"
              value={form.business_name}
              onChange={handleChange}
            />

            <InputField
              label="Email Address *"
              name="email"
              type="email"
              placeholder="example@company.com"
              value={form.email}
              onChange={handleChange}
            />

            <InputField
              label="Mobile Number *"
              name="mobile_no"
              placeholder="9876543210"
              value={form.mobile_no}
              onChange={handleChange}
            />

            <InputField
              label="Contact Person *"
              name="contact_person"
              placeholder="Rahul Sharma"
              value={form.contact_person}
              onChange={handleChange}
            />

            <InputField
              label="GST Number"
              name="gst_in"
              placeholder="22AAAAA0000A1Z5"
              value={form.gst_in}
              onChange={handleChange}
            />

            <InputField
              label="PAN Number"
              name="pan"
              placeholder="ABCDE1234F"
              value={form.pan}
              onChange={handleChange}
            />

            <InputField
              label="CIN Number"
              name="cin"
              placeholder="U12345MH2020PTC123456"
              value={form.cin}
              onChange={handleChange}
            />
          </div>

          <div>
            <label className="text-gray-700 text-sm font-medium">
              Full Address *
            </label>
            <textarea
              name="address"
              value={form.address}
              onChange={handleChange}
              placeholder="Head office complete address"
              className="w-full mt-2 p-3 rounded-xl bg-gray-50 outline-none text-sm"
            />
          </div>

          <InputField
            label="Loan Products"
            placeholder="Gold Loan, Personal Loan"
            onChange={handleLoanProducts}
          />

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold flex justify-center gap-2 hover:bg-blue-700 transition"
          >
            <FiSave className="text-lg" />
            {loading ? "Saving..." : "Save Organization"}
          </button>
        </form>
      </div>

      {/* SUCCESS POPUP (AUTO REDIRECT) */}
      {showSuccess && (
        <div className="fixed top-6 right-6 z-50">
          <div className="bg-green-600 text-white px-6 py-4 rounded-xl shadow-lg">
            <p className="font-semibold">
              ✅ Organization added successfully
            </p>
            {successData?.tenant_id && (
              <p className="text-xs mt-1 opacity-90">
                Tenant ID: {successData.tenant_id}
              </p>
            )}
            <p className="text-xs mt-1 opacity-80">
              Redirecting to organizations...
            </p>
          </div>
        </div>
      )}
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
        className="w-full mt-2 p-3 rounded-xl bg-gray-50 outline-none text-sm"
      />
    </div>
  );
}
