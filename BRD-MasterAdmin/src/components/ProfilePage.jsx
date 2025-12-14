import React, { useState, useEffect } from "react";
import {
  FiArrowLeft,
  FiMail,
  FiPhone,
  FiCamera,
  FiLock,
} from "react-icons/fi";
import MainLayout from "../layout/MainLayout";

const ProfilePage = () => {
  // Load user from storage
  const storedUser =
    JSON.parse(localStorage.getItem("currentUser")) || {
      firstName: "Rahul",
      lastName: "Sharma",
      email: "rahul@example.com",
      phone: "9876543210",
      role: "Loan Officer",
      avatar: null,
    };

  const [user, setUser] = useState(storedUser);
  const [passwordData, setPasswordData] = useState({
    oldPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [msg, setMsg] = useState("");

  // Auto hide message after 3 seconds
  useEffect(() => {
    if (msg) {
      const timer = setTimeout(() => setMsg(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [msg]);

  // Save user updates to localStorage
  const updateLocalUser = (updated) => {
    localStorage.setItem("currentUser", JSON.stringify(updated));
  };

  // Update profile fields
  const handleProfileChange = (e) => {
    const updated = { ...user, [e.target.name]: e.target.value };
    setUser(updated);
    updateLocalUser(updated);
    setMsg("Profile updated successfully!");
  };

  // Upload avatar (Show preview + save)
  const handleAvatarUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const imgURL = URL.createObjectURL(file);
    const updated = { ...user, avatar: imgURL };

    setUser(updated);
    updateLocalUser(updated);
    setMsg("Profile picture updated!");
  };

  // Handle password change inputs
  const handlePasswordChange = (e) => {
    setPasswordData({ ...passwordData, [e.target.name]: e.target.value });
  };

  // Validate & update password
  const handlePasswordSubmit = () => {
    const { oldPassword, newPassword, confirmPassword } = passwordData;

    if (!oldPassword || !newPassword || !confirmPassword) {
      setMsg("Please fill all password fields");
      return;
    }

    if (newPassword !== confirmPassword) {
      setMsg("New passwords do not match");
      return;
    }

    setMsg("Password updated successfully!");
    setPasswordData({ oldPassword: "", newPassword: "", confirmPassword: "" });
  };

  // Delete account
  const handleDeleteAccount = () => {
    if (window.confirm("Are you sure? This action cannot be undone.")) {
      localStorage.removeItem("currentUser");
      setMsg("Account deleted!");
      setTimeout(() => {
        window.location.href = "/login";
      }, 800);
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">

        {/* HEADER */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => window.history.back()}
            className="p-2 rounded-xl bg-gray-100 hover:bg-gray-200"
          >
            <FiArrowLeft className="text-gray-700 text-xl" />
          </button>

          <div>
            <h1 className="text-2xl font-semibold text-gray-900">My Profile</h1>
            <p className="text-gray-500 text-sm">
              Manage your personal details & account preferences
            </p>
          </div>
        </div>

        {/* MESSAGE */}
        {msg && (
          <div className="p-3 bg-green-100 text-green-700 rounded-lg text-sm">
            {msg}
          </div>
        )}

        {/* PROFILE PHOTO */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6 flex items-center gap-6">
          <div className="relative">
            <img
              src={
                user.avatar ||
                "https://cdn-icons-png.flaticon.com/512/149/149071.png"
              }
              alt="profile"
              className="w-24 h-24 rounded-full object-cover border"
            />

            <label className="absolute bottom-0 right-0 p-2 bg-blue-600 rounded-full cursor-pointer hover:bg-blue-700">
              <FiCamera className="text-white text-sm" />
              <input type="file" onChange={handleAvatarUpload} className="hidden" />
            </label>
          </div>

          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              {user.firstName} {user.lastName}
            </h2>
            <p className="text-gray-500 text-sm">{user.role}</p>
          </div>
        </div>

        {/* PERSONAL INFO */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">
            Personal Information
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {/* First Name */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">First Name</label>
              <input
                name="firstName"
                value={user.firstName}
                onChange={handleProfileChange}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-600"
              />
            </div>

            {/* Last Name */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">Last Name</label>
              <input
                name="lastName"
                value={user.lastName}
                onChange={handleProfileChange}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-600"
              />
            </div>

            {/* Email */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">Email</label>
              <div className="flex items-center border rounded-lg px-3">
                <FiMail className="text-gray-500 mr-2" />
                <input
                  type="email"
                  name="email"
                  value={user.email}
                  onChange={handleProfileChange}
                  className="w-full py-2 outline-none"
                />
              </div>
            </div>

            {/* Phone */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">Phone</label>
              <div className="flex items-center border rounded-lg px-3">
                <FiPhone className="text-gray-500 mr-2" />
                <input
                  type="number"
                  name="phone"
                  value={user.phone}
                  onChange={handleProfileChange}
                  className="w-full py-2 outline-none"
                />
              </div>
            </div>
          </div>
        </div>

        {/* PASSWORD CHANGE */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">
            Change Password
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {/* Old Password */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">Old Password</label>
              <div className="flex items-center border rounded-lg px-3">
                <FiLock className="text-gray-500 mr-2" />
                <input
                  type="password"
                  name="oldPassword"
                  value={passwordData.oldPassword}
                  onChange={handlePasswordChange}
                  className="w-full py-2 outline-none"
                />
              </div>
            </div>

            {/* New Password */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">New Password</label>
              <div className="flex items-center border rounded-lg px-3">
                <FiLock className="text-gray-500 mr-2" />
                <input
                  type="password"
                  name="newPassword"
                  value={passwordData.newPassword}
                  onChange={handlePasswordChange}
                  className="w-full py-2 outline-none"
                />
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label className="text-sm text-gray-600 mb-1 block">Confirm Password</label>
              <div className="flex items-center border rounded-lg px-3">
                <FiLock className="text-gray-500 mr-2" />
                <input
                  type="password"
                  name="confirmPassword"
                  value={passwordData.confirmPassword}
                  onChange={handlePasswordChange}
                  className="w-full py-2 outline-none"
                />
              </div>
            </div>
          </div>

          <button
            onClick={handlePasswordSubmit}
            className="mt-6 px-6 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900"
          >
            Update Password
          </button>
        </div>

        {/* ACCOUNT SETTINGS */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">
            Account Settings
          </h2>

          <ul className="space-y-3">

            <li className="flex justify-between items-center">
              <span className="text-gray-700">Two-Factor Authentication</span>
              <button className="px-4 py-1 bg-gray-200 rounded-lg hover:bg-gray-300">
                Enable
              </button>
            </li>

            <li className="flex justify-between items-center">
              <span className="text-gray-700">Login Activity</span>
              <button className="px-4 py-1 bg-gray-200 rounded-lg hover:bg-gray-300">
                View
              </button>
            </li>

            <li className="flex justify-between items-center">
              <span className="text-gray-700">Delete Account</span>
              <button
                onClick={handleDeleteAccount}
                className="px-4 py-1 bg-red-600 text-white rounded-lg hover:bg-red-700"
              >
                Delete
              </button>
            </li>

          </ul>
        </div>
      </div>
    </MainLayout>
  );
};

export default ProfilePage;
