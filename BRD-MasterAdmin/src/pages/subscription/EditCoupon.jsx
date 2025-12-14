import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSave } from "react-icons/fi";
import { useNavigate, useParams } from "react-router-dom";

import couponService from "../../services/couponService";
import subscriptionService from "../../services/subscriptionService";

export default function EditCoupon() {
  const navigate = useNavigate();
  const { uuid } = useParams();

  const [subscriptions, setSubscriptions] = useState([]);

  const [form, setForm] = useState({
    coupon_code: "",
    coupon_value: "",
    date_from: "",
    date_to: "",
    subscription_id: [],
    created_user: "",
    modified_user: "master_admin",
    isDeleted: false,
  });

  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState(null);

  // Load subscription list
  const loadSubscriptions = async () => {
    try {
      const data = await subscriptionService.getAll();
      setSubscriptions(data);
    } catch (err) {
      console.error("Failed to load subscriptions", err);
    }
  };

  // Load coupon details
  const loadCoupon = async () => {
    try {
      const data = await couponService.getOne(uuid);

      setForm({
        coupon_code: data.coupon_code,
        coupon_value: data.coupon_value,
        date_from: data.date_from,
        date_to: data.date_to,
        subscription_id: data.subscription_id ?? [],
        created_user: data.created_user,
        modified_user: "master_admin",
        isDeleted: data.isDeleted,
      });
    } catch (err) {
      console.error("Failed to load coupon:", err);
    }
  };

  useEffect(() => {
    loadSubscriptions();
    loadCoupon();
  }, []);

  // Handle field input
  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  // Toggle subscription selection
  const toggleSubscription = (id) => {
    setForm((prev) => {
      const exists = prev.subscription_id.includes(id);

      return {
        ...prev,
        subscription_id: exists
          ? prev.subscription_id.filter((x) => x !== id)
          : [...prev.subscription_id, id],
      };
    });
  };

  // Submit update
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrors(null);

    try {
      await couponService.update(uuid, form);
      navigate("/coupons");
    } catch (err) {
      console.error("Update error:", err);
      setErrors("Something went wrong while updating the coupon.");
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
          className="p-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 "
        >
          <FiArrowLeft className="text-gray-700 text-lg" />
        </button>

        <div>
          <h1 className="text-[22px] font-semibold text-gray-900">Edit Coupon</h1>
          <p className="text-gray-500 text-sm">Update coupon details below.</p>
        </div>
      </div>

      {/* CARD */}
      <div className="bg-white   p-8 rounded-2xl shadow-sm max-w-4xl">
        {errors && (
          <div className="mb-6 p-4 bg-red-50   text-red-600 rounded-lg text-sm">
            {errors}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-10">
          {/* GRID */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <InputField
              label="Coupon Code *"
              name="coupon_code"
              value={form.coupon_code}
              onChange={handleChange}
              required
            />

            <InputField
              label="Coupon Value (₹) *"
              name="coupon_value"
              type="number"
              value={form.coupon_value}
              onChange={handleChange}
              required
            />

            <InputField
              label="Valid From *"
              name="date_from"
              type="date"
              value={form.date_from}
              onChange={handleChange}
              required
            />

            <InputField
              label="Valid To *"
              name="date_to"
              type="date"
              value={form.date_to}
              onChange={handleChange}
              required
            />
          </div>

          {/* SUBSCRIPTION CHECKBOXES */}
          <div>
            <label className="text-gray-700 text-sm font-medium">
              Applicable Subscriptions *
            </label>

            <div className="mt-3 space-y-2 bg-gray-50 p-4 rounded-xl ">
              {subscriptions.length === 0 ? (
                <p className="text-gray-500 text-sm">No subscriptions found.</p>
              ) : (
                subscriptions.map((sub) => (
                  <label
                    key={sub.id}
                    className="flex items-center gap-3 text-sm text-gray-700"
                  >
                    <input
                      type="checkbox"
                      checked={form.subscription_id.includes(sub.id)}
                      onChange={() => toggleSubscription(sub.id)}
                      className="w-4 h-4"
                    />
                    {sub.subscription_name}
                  </label>
                ))
              )}
            </div>
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
        className="w-full mt-2 p-3 rounded-xl bg-gray-50  focus:bg-white outline-none text-sm"
      />
    </div>
  );
}
