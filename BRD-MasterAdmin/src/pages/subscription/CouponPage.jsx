import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";

import {
  FiArrowLeft,
  FiSearch,
  FiPlus,
  FiEdit2,
  FiTrash2
} from "react-icons/fi";

import { useNavigate } from "react-router-dom";
import couponService from "../../services/couponService";

export default function CouponPage() {
  const [list, setList] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [search, setSearch] = useState("");

  const navigate = useNavigate();

  // Load coupons from backend
  const loadCoupons = async () => {
    try {
      const data = await couponService.getAll(); // FIXED
      setList(data);
      setFiltered(data);
    } catch (err) {
      console.error("Failed to load coupons:", err);
    }
  };

  useEffect(() => {
    loadCoupons();
  }, []);

  // Search filter
  const handleSearch = (e) => {
    const keyword = e.target.value.toLowerCase();
    setSearch(keyword);

    setFiltered(
      list.filter((item) =>
        item.coupon_code.toLowerCase().includes(keyword)
      )
    );
  };

  // Delete coupon
  const handleDelete = async (uuid) => {
    if (!window.confirm("Delete this coupon?")) return;

    await couponService.delete(uuid);
    loadCoupons();
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-white border hover:bg-gray-100"
        >
          <FiArrowLeft />
        </button>
        <h1 className="text-xl font-semibold">Coupons</h1>
      </div>

      {/* SEARCH + ADD */}
      <div className="flex justify-between items-center mb-6">
        <div className="flex items-center bg-white p-3 rounded-xl w-[85%] shadow-sm border">
          <FiSearch className="text-gray-400 mr-2" />
          <input
            type="text"
            placeholder="Search coupon..."
            className="outline-none w-full"
            value={search}
            onChange={handleSearch}
          />
        </div>

        <button
          onClick={() => navigate("/coupons/add")}
          className="px-4 py-3 bg-blue-600 text-white rounded-xl flex items-center gap-2 hover:bg-blue-700 shadow"
        >
          <FiPlus /> Add Coupon
        </button>
      </div>

      {/* COUPON LIST */}
      <div className="bg-white rounded-xl shadow-sm border p-6 mb-10">
        {filtered.length === 0 ? (
          <p className="text-gray-500 text-sm">No coupons found.</p>
        ) : (
          filtered.map((item) => (
            <div
              key={item.uuid}
              className="flex justify-between items-center py-4 border-b last:border-none"
            >
              {/* Coupon Info */}
              <div>
                <p className="text-lg font-medium">{item.coupon_code}</p>
                <p className="text-sm text-gray-500">
                  Value: ₹{item.coupon_value} | Valid: {item.date_from} → {item.date_to}
                </p>
              </div>

              {/* Edit & Delete Buttons */}
              <div className="flex items-center gap-3">
                <button
                  onClick={() => navigate(`/coupons/edit/${item.uuid}`)}
                  className="p-2 rounded-lg bg-ble-100 hover:bg-blue-200 text-blue-700"
                >
                  <FiEdit2 size={18} />
                </button>

                <button
                  onClick={() => handleDelete(item.uuid)}
                  className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600"
                >
                  <FiTrash2 size={18} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </MainLayout>
  );
}
