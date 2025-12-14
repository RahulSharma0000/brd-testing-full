import React from 'react'

import { FiUser, FiSettings, FiEdit3, FiBell } from "react-icons/fi";
const RecentActivity = () => {
  return (
    <div>  <div className="bg-white rounded-xl p-5 shadow-sm  flex flex-col">
    <div className="flex items-center justify-between mb-4">
      <h2 className="text-lg font-semibold text-gray-800">Recent Activities</h2>
      <span className="text-xs text-blue-600 cursor-pointer hover:underline">
        View all
      </span>
    </div>

    <div className="space-y-3 overflow-y-auto pr-1 custom-scroll h-[300px]">
      
      {/* Activity List */}
      {[
        {
          icon: <FiUser className="text-blue-600 text-xl" />,
          bg: "bg-blue-100",
          text: "John added a new loan request.",
          time: "5 minutes ago",
        },
        {
          icon: <FiSettings className="text-green-600 text-xl" />,
          bg: "bg-green-100",
          text: "System performed an API health check.",
          time: "12 minutes ago",
        },
        {
          icon: <FiEdit3 className="text-yellow-600 text-xl" />,
          bg: "bg-yellow-100",
          text: "Admin updated interest rate policy.",
          time: "30 minutes ago",
        },
        {
          icon: <FiBell className="text-red-600 text-xl" />,
          bg: "bg-red-100",
          text: "A critical alert was raised for loan server.",
          time: "1 hour ago",
        },
      ].map((item, i) => (
        <div
          key={i}
          className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg  hover:shadow-sm transition cursor-pointer"
        >
          {/* Icon */}
          <div
            className={`w-10 h-10 flex items-center justify-center rounded-full ${item.bg}`}
          >
            {item.icon}
          </div>

          {/* Content */}
          <div>
            <p className="text-gray-700 text-sm">{item.text}</p>
            <p className="text-xs text-gray-400 mt-1">{item.time}</p>
          </div>
        </div>
      ))}
    </div>
  </div></div>
  )
}

export default RecentActivity