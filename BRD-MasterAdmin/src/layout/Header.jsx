import React from "react";
import { useNavigate } from "react-router-dom";

const Header = () => {
  const user = JSON.parse(localStorage.getItem("currentUser"));
  const navigate = useNavigate();

  return (
    <div className="w-full h-20 bg-white border-b border-gray-200 flex items-center justify-between px-6 sticky top-0 left-0 z-20">

      {/* Title */}
      <div>
        <h1 className="text-xl font-semibold text-gray-900">Xpertland.Ai</h1>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">

        {/* User Profile */}
        <div
          className="flex items-center gap-3 cursor-pointer"
          onClick={() => navigate("/profile")}
        >
          <span className="text-gray-700 text-sm">{user?.firstName}</span>

          {/* FIXED: Show profile image if available */}
          {user?.avatar ? (
            <img
              src={user.avatar}
              alt="profile"
              className="w-10 h-10 rounded-full object-cover border"
            />
          ) : (
            <div className="w-10 h-10 rounded-full bg-blue-600 text-white flex items-center justify-center text-lg font-medium">
              {user?.firstName?.charAt(0)}
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default Header;
