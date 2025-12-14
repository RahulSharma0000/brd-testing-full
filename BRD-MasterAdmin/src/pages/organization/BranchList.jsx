// src/pages/branches/BranchList.jsx
import React, { useMemo, useState, useEffect } from "react";
import MainLayout from "../../layout/MainLayout";
import { useNavigate } from "react-router-dom";
import {
  FiArrowLeft,
  FiPlus,
  FiSearch,
  FiTrash2,
  FiEdit,
} from "react-icons/fi";
import { branchService } from "../../services/branchService"; // assume you have branchService similar to org

export default function BranchList() {
  const navigate = useNavigate();
  const [branches, setBranches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const data = await branchService.getBranches();
      setBranches(data || []);
    } catch (error) {
      console.error("Error loading branches:", error);
    } finally {
      setLoading(false);
    }
  };

  const filteredBranches = useMemo(() => {
    return branches.filter(
      (b) =>
        !search ||
        b.name.toLowerCase().includes(search.toLowerCase()) ||
        b.branch_code.toLowerCase().includes(search.toLowerCase()) ||
        (b.phone || "").includes(search) ||
        (b.address || "").toLowerCase().includes(search.toLowerCase()) ||
        (b.tenant?.name || "").toLowerCase().includes(search.toLowerCase())
    );
  }, [branches, search]);

  const handleDelete = async (id) => {
    if (!window.confirm("Are you sure you want to delete this branch?")) return;
    try {
      await branchService.deleteBranch(id);
      loadData();
    } catch (error) {
      console.error("Delete failed:", error);
    }
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6 gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 shadow-sm transition"
          >
            <FiArrowLeft className="text-gray-700 text-xl" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-800">Branches</h1>
            <p className="text-gray-500 text-sm">
              View and manage all branches in the system.
            </p>
          </div>
        </div>

        <button
          onClick={() => navigate("/organization/branches/create")}
          className="flex items-center gap-2 bg-blue-600 text-white py-2.5 px-4 rounded-xl text-sm font-medium hover:bg-blue-700 shadow-sm"
        >
          <FiPlus className="text-lg" />
          Add Branch
        </button>
      </div>

      {/* SEARCH BAR */}
      <div className="bg-white p-4 rounded-2xl shadow-sm mb-6 flex items-center gap-2 w-full">
        <FiSearch className="text-gray-400" />
        <input
          type="text"
          placeholder="Search by branch name, code, email, phone, or organization..."
          className="flex-1 bg-gray-50 rounded-xl px-3 py-2 outline-none text-sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* BRANCH LIST */}
      <div className="space-y-4">
        {loading ? (
          <p className="text-gray-500 text-center py-8 text-sm">
            Loading branches...
          </p>
        ) : filteredBranches.length === 0 ? (
          <p className="text-gray-500 text-center py-8 text-sm">
            No branches found. Try changing search or add a new branch.
          </p>
        ) : (
          filteredBranches.map((branch) => (
            <div
              key={branch.id || branch.branch_code}
              className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 p-5 rounded-2xl bg-white border border-gray-200 shadow hover:shadow-md transition"
            >
              {/* LEFT: Branch Info */}
              <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-xs font-medium">
                    Branch Name
                  </p>
                  <p className="font-semibold text-gray-800">{branch.name}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs font-medium">
                    Branch Code
                  </p>
                  <p className="text-gray-700 text-sm">{branch.branch_code}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs font-medium">Phone</p>
                  <p className="text-gray-700 text-sm">{branch.phone || "-"}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs font-medium">Address</p>
                  <p className="text-gray-700 text-sm">
                    {branch.address || "-"}
                  </p>
                </div>
              </div>

              {/* RIGHT: Actions */}
              <div className="flex items-center gap-3 mt-3 md:mt-0">
                {/* Edit Button */}
                <button
                  onClick={() =>
                    navigate(`/organization/branches/update/${branch.id}`)
                  }
                  className="p-2 rounded-full bg-gray-100 hover:bg-gray-200 transition"
                  title="Edit Branch"
                >
                  <FiEdit className="text-blue-600" />
                </button>

                {/* Delete Button */}
                <button
                  onClick={() => handleDelete(branch.id)}
                  className="p-2 rounded-full bg-red-100 hover:bg-red-200 transition"
                  title="Delete Branch"
                >
                  <FiTrash2 className="text-red-600" />
                </button>
                
              </div>
            </div>
          ))
        )}
      </div>
    </MainLayout>
  );
}
