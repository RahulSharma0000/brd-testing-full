import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";
import subscriptionService from "../../services/subscriptionService";

export default function EditSubscription() {
  const navigate = useNavigate();
  const { uuid } = useParams();

  const [form, setForm] = useState({
    subscription_name: "",
    subscription_amount: "",
    no_of_borrowers: "",
    type_of: "Monthly",

    created_user: "",
    modified_user: "master_admin",
    isDeleted: false,
  });

  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState(null);

  // 🔥 Load existing subscription (FIXED)
  const loadSubscription = async () => {
    try {
      const data = await subscriptionService.getOne(uuid); // FIXED: direct data

      setForm({
        subscription_name: data.subscription_name,
        subscription_amount: data.subscription_amount,
        no_of_borrowers: data.no_of_borrowers,
        type_of: data.type_of,

        created_user: data.created_user,
        modified_user: "master_admin",
        isDeleted: data.isDeleted,
      });
    } catch (err) {
      console.error("Error loading subscription:", err);
      setErrors("Failed to load subscription details.");
    }
  };

  useEffect(() => {
    loadSubscription();
  }, []);

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  // 🔥 Submit Handler (unchanged)
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrors(null);

    try {
      await subscriptionService.update(uuid, form);
      navigate("/subscriptions/list");
    } catch (err) {
      setErrors("Something went wrong while updating the subscription.");
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
          className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 border border-gray-200 transition"
        >
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>

        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">
            Edit Subscription
          </h1>
          <p className="text-gray-500 text-sm">
            Update subscription details below.
          </p>
        </div>
      </div>

      {/* FORM CARD */}
      <div className="bg-white border border-gray-200 p-8 rounded-2xl shadow-sm max-w-4xl">
        {errors && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-600 rounded-lg text-sm">
            {errors}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-10">
          
          {/* GRID SECTION */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

            <InputField
              label="Subscription Name *"
              name="subscription_name"
              value={form.subscription_name}
              onChange={handleChange}
              required
            />

            <InputField
              label="Subscription Amount (₹) *"
              name="subscription_amount"
              type="number"
              value={form.subscription_amount}
              onChange={handleChange}
              required
            />

            <InputField
              label="No. of Borrowers *"
              name="no_of_borrowers"
              type="number"
              value={form.no_of_borrowers}
              onChange={handleChange}
              required
            />

            <SelectField
              label="Subscription Type *"
              name="type_of"
              value={form.type_of}
              onChange={handleChange}
              options={["Monthly", "Quarterly", "Yearly"]}
            />
          </div>

          {/* SAVE BUTTON */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold flex items-center justify-center gap-2 hover:bg-blue-700 transition text-sm"
          >
            <FiSave className="text-lg" />
            {loading ? "Saving..." : "Save Changes"}
          </button>
        </form>
      </div>
    </MainLayout>
  );
}

/* ---------------- INPUT COMPONENT ---------------- */
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

/* ---------------- SELECT COMPONENT ---------------- */
function SelectField({ label, options, ...props }) {
  return (
    <div>
      <label className="text-gray-700 text-sm font-medium">{label}</label>
      <select
        {...props}
        className="w-full mt-2 p-3 rounded-xl bg-gray-50 border border-gray-200 focus:bg-white outline-none text-sm"
      >
        {options.map((op) => (
          <option key={op} value={op}>
            {op}
          </option>
        ))}
      </select>
    </div>
  );
}
