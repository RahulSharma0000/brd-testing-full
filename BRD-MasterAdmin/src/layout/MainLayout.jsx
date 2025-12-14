import React from "react";
import Sidebar from "./Sidebar";
import Header from "./Header";

const MainLayout = ({ children }) => {
  return (
    <div>
      <Sidebar />
     
      <div className="ml-64   bg-gray-100 min-h-screen">
         <Header />
        <div className="px-10 py-5 ">{children}</div>
      </div>
    </div>
  );
};

export default MainLayout;
