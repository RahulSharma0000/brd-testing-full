import React, { useEffect, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import subscriberService from "../../services/subscriberService";

import {
  FiArrowLeft,
  FiSearch,
  FiEdit2,
  FiTrash2,
  FiEye
} from "react-icons/fi";

import { useNavigate } from "react-router-dom";

export default function SubscribersPage() {
  const [list, setList] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [search, setSearch] = useState("");

  const navigate = useNavigate();

  // Load all subscribers
  const loadSubscribers = async () => {
    const res = await subscriberService.getAll(); // FIXED
    setList(res);
    setFiltered(res);
  };

  useEffect(() => {
    loadSubscribers();
  }, []);

  // Search handler
  const handleSearch = (e) => {
    const keyword = e.target.value.toLowerCase();
    setSearch(keyword);

    setFiltered(
      list.filter((item) =>
        item.tenant_id.toLowerCase().includes(keyword)
      )
    );
  };

  // Delete subscriber (soft delete)
  const handleDelete = async (uuid) => {
    if (!window.confirm("Are you sure you want to delete this subscriber?"))
      return;

    await subscriberService.delete(uuid); // FIXED
    loadSubscribers();
  };

  return (
    <MainLayout>
      {/* PAGE HEADER */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-xl bg-white border hover:bg-gray-100"
        >
          <FiArrowLeft />
        </button>
        <h1 className="text-xl font-semibold">Subscribers</h1>
      </div>

      {/* SEARCH BAR */}
      <div className="flex justify-between items-center mb-6">
        <div className="flex items-center bg-white p-3 rounded-xl w-full shadow-sm border">
          <FiSearch className="text-gray-400 mr-2" />
          <input
            type="text"
            placeholder="Search Tenant ID..."
            className="outline-none w-full"
            value={search}
            onChange={handleSearch}
          />
        </div>
      </div>

      {/* SUBSCRIBER LIST */}
      <div className="bg-white rounded-xl shadow-sm border p-6 mb-10">
        {filtered.length === 0 ? (
          <p className="text-gray-500 text-sm">No subscribers found.</p>
        ) : (
          filtered.map((item) => (
            <div
              key={item.uuid}
              className="flex justify-between items-center py-4 border-b last:border-none"
            >
              {/* LEFT INFO */}
              <div>
                <p className="text-lg font-medium">
                  Tenant ID: {item.tenant_id}
                </p>
                <p className="text-sm text-gray-500">
                  Subscription: {item.subscription_id}
                </p>
              </div>

              {/* ACTION BUTTONS */}
              <div className="flex items-center gap-3">
                {/* VIEW */}
                <button
                  onClick={() =>
                    navigate(`/subscribers/view/${item.uuid}`)
                  }
                  className="p-2 rounded-lg bg-blue-100 hover:bg-blue-200 text-blue-700"
                >
                  <FiEye size={18} />
                </button>

                {/* EDIT */}
                <button
                  onClick={() =>
                    navigate(`/subscribers/edit/${item.uuid}`)
                  }
                  className="p-2 rounded-lg bg-yellow-100 hover:bg-yellow-200 text-yellow-700"
                >
                  <FiEdit2 size={18} />
                </button>

                {/* DELETE */}
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
