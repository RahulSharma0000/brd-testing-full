import React, { useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import subscriptionService from "../../services/subscriptionService";

export default function AddSubscription() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    subscription_name: "",
    subscription_amount: "",
    no_of_borrowers: "",
    type_of: "Monthly",

    created_user: "master_admin",
    modified_user: "master_admin",
    isDeleted: false,
  });

  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState(null);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrors(null);

    try {
      await subscriptionService.create(form);

      navigate("/subscriptions");
    } catch (err) {
      setErrors("Something went wrong while saving subscription.");
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
            Add New Subscription
          </h1>
          <p className="text-gray-500 text-sm">
            Enter subscription details to create a new plan.
          </p>
        </div>
      </div>

      {/* FORM WRAPPER CARD */}
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
              label="Subscription Name *"
              name="subscription_name"
              placeholder="Gold Plan"
              value={form.subscription_name}
              onChange={handleChange}
              required
            />

            <InputField
              label="Amount (₹) *"
              name="subscription_amount"
              type="number"
              placeholder="2500"
              value={form.subscription_amount}
              onChange={handleChange}
              required
            />

            <InputField
              label="No. of Borrowers *"
              name="no_of_borrowers"
              type="number"
              placeholder="10"
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

          {/* SUBMIT BUTTON */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold flex items-center justify-center gap-2 hover:bg-blue-700 transition text-sm"
          >
            <FiSave className="text-lg" />
            {loading ? "Saving..." : "Save Subscription"}
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

/* ---------------- SELECT FIELD ---------------- */
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
