import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  FiHome,
  FiGrid,
  FiUsers,
  FiKey,
  FiBarChart2,
  FiShield,
  FiCreditCard,
  FiUserCheck,
  FiBriefcase,
  FiAward,
  FiLogOut,
} from "react-icons/fi";

const Sidebar = () => {
  const location = useLocation();

  const handleLogout = () => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = "/signup";
  };

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(path);

  const menuItemStyle = (path) =>
    `flex items-center gap-3 px-4 py-2.5 rounded-2xl text-md transition-all
     ${
       isActive(path)
         ? "bg-[#E8F1FF] text-[#0A66FF] font-medium"
         : "text-gray-700 hover:bg-gray-100"
     }`;

  // -------------------------
  // MENU CONFIG (with better icons)
  // -------------------------
  const menuItems = [
    { name: "Home", path: "/dashboard", icon: <FiHome size={18} /> },
    { name: "Organizations", path: "/organizations", icon: <FiGrid size={18} /> },
    { name: "Users", path: "/users", icon: <FiUsers size={18} /> },
    { name: "Roles", path: "/roles", icon: <FiKey size={18} /> },
    { name: "Reports", path: "/reports", icon: <FiBarChart2 size={18} /> },
    { name: "Audit", path: "/audit", icon: <FiShield size={18} /> },
    { name: "Subscription", path: "/subscriptions", icon: <FiCreditCard size={18} /> },

    // ===================
    // MASTER DATA SECTION
    // ===================
    {
      section: "Master Data",
    },
    {
      name: "Employment Types",
      path: "/employment-types",
      icon: <FiUserCheck size={18} />, // BETTER ICON
    },
    {
      name: "Occupation Types",
      path: "/occupation-types",
      icon: <FiBriefcase size={18} />, // PROFESSIONAL ICON
    },
  ];

  return (
    <div className="w-64 h-screen bg-white fixed left-0 top-0 flex flex-col justify-between">

      <div>
        {/* Title */}
        <div className="p-8 flex items-center gap-3">
          <span className="text-2xl font-semibold text-gray-900">
            Master Admin
          </span>
        </div>

        {/* MENU */}
        <nav className="px-3 mt-1 space-y-1">
          {menuItems.map((item, index) =>
            item.section ? (
              <p
                key={index}
                className="text-xs text-gray-500 uppercase font-semibold mt-4 mb-1 px-4"
              >
                {item.section}
              </p>
            ) : (
              <Link key={item.path} to={item.path} className={menuItemStyle(item.path)}>
                {item.icon} {item.name}
              </Link>
            )
          )}
        </nav>
      </div>

      {/* Logout */}
      <div className="p-4">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-4 py-2.5 rounded-xl text-red-600 hover:bg-red-50 transition"
        >
          <FiLogOut size={18} /> Logout
        </button>
      </div>

    </div>
  );
};

export default Sidebar;
