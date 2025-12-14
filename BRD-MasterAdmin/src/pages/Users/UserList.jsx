import React, { useMemo, useState } from "react";
import MainLayout from "../../layout/MainLayout";
import { FiArrowLeft, FiSearch, FiTrash2, FiEdit3 } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import { useUsers } from "../../hooks/useUsers";

const UserList = () => {
  const navigate = useNavigate();
  // useUsers hook backend se data fetch karega
  const { users, loading, reload } = useUsers();

  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // FILTER LOGIC
  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      // Backend ke role/status fields ke hisab se filter
      const q = search.toLowerCase();
      const matchesSearch =
        !q ||
        u.email?.toLowerCase().includes(q) ||
        (u.role || "").toLowerCase().includes(q);

      const matchesRole =
        roleFilter === "ALL" ||
        (u.role || "").toLowerCase() === roleFilter.toLowerCase();

      // Backend returns is_active (boolean)
      const statusText = u.is_active ? "active" : "inactive";
      const matchesStatus =
        statusFilter === "ALL" || statusText === statusFilter.toLowerCase();

      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [users, search, roleFilter, statusFilter]);

  // DELETE USER
  const handleDelete = async (id) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      await userService.deleteUser(id);
      reload(); // List refresh karein
    } catch (error) {
      alert("Failed to delete user.");
    }
  };

  return (
    <MainLayout>
      {/* HEADER */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 shadow-sm transition">
            <FiArrowLeft className="text-gray-700 text-xl" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-800">User List</h1>
            <p className="text-gray-500 text-sm">View and manage all registered users.</p>
          </div>
        </div>
        <button onClick={() => navigate("/users/add")} className="bg-blue-600 text-white px-4 py-2 rounded-xl text-sm font-medium hover:bg-blue-700 shadow-sm">
          + Add New User
        </button>
      </div>

      {/* FILTER BAR */}
      <div className="bg-white p-4 rounded-2xl shadow-sm mb-6 flex flex-col md:flex-row gap-4 md:items-center md:justify-between">
        <div className="flex items-center gap-2 w-full md:max-w-md">
          <FiSearch className="text-gray-400" />
          <input
            type="text"
            placeholder="Search by email or role..."
            className="flex-1 bg-gray-50 rounded-xl px-3 py-2 outline-none"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-3">
          <select value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)} className="px-3 py-2 rounded-xl bg-gray-50 text-sm outline-none">
            <option value="ALL">All Roles</option>
            <option value="ADMIN">Admin</option>
            <option value="LOAN_OFFICER">Loan Officer</option>
            <option value="MASTER_ADMIN">Master Admin</option>
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="px-3 py-2 rounded-xl bg-gray-50 text-sm outline-none">
            <option value="ALL">All Status</option>
            <option value="Active">Active</option>
            <option value="Inactive">Inactive</option>
          </select>
        </div>
      </div>

      {/* LIST TABLE */}
      <div className="bg-white p-6 rounded-2xl shadow-md">
        {loading ? (
          <p className="text-center py-8 text-gray-500">Loading users...</p>
        ) : filteredUsers.length === 0 ? (
          <p className="text-center py-8 text-gray-500">No users found.</p>
        ) : (
          <div className="space-y-3">
            {filteredUsers.map((user) => (
              <div key={user.id} className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 p-4 rounded-xl bg-gray-50 hover:bg-gray-100 transition">
                <div>
                  <p className="font-semibold text-gray-800">{user.email}</p>
                  <p className="text-gray-500 text-xs mt-1">{user.phone || "No phone"}</p>
                  <p className="text-gray-600 text-sm mt-1">Role: {user.role}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`px-3 py-1 text-xs rounded-full ${user.is_active ? "bg-green-100 text-green-700" : "bg-red-100 text-red-600"}`}>
                    {user.is_active ? "Active" : "Inactive"}
                  </span>
                  <button onClick={() => navigate(`/users/edit/${user.id}`)} className="p-2 rounded-full bg-blue-100 hover:bg-blue-200">
                    <FiEdit3 className="text-blue-600" />
                  </button>
                  <button onClick={() => handleDelete(user.id)} className="p-2 rounded-full bg-red-100 hover:bg-red-200">
                    <FiTrash2 className="text-red-600" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </MainLayout>
  );
};

export default UserList;