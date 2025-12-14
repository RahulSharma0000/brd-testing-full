import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";

import Sidebar from "./components/Sidebar.jsx";
import Header from "./components/Header.jsx";

import Dashboard from "./pages/Dashboard.jsx";
import Branches from "./pages/Branches.jsx";
import Loans from "./pages/Loans.jsx"; // Loan Products

import Logs from "./pages/Logs.jsx";
import Calendar from "./pages/Calendar.jsx";
import RolesPermissions from "./pages/RolesPermissions.jsx";
import Users from "./pages/Users.jsx";
import Settings from "./pages/Settings.jsx";
import Profile from "./pages/Profile.jsx";
import Notifications from "./pages/Notifications.jsx";

import Signup from "./pages/Signup.jsx";
import Login from "./pages/Login.jsx";
import ForgotPassword from "./pages/ForgotPassword.jsx";
import SendLink from "./pages/SendLink.jsx";

import InternalTeamManagement from "./pages/InternalTeamManagement.jsx";
import Rules from "./pages/Rules.jsx";
import Categories from "./pages/Categories.jsx";
import Reports from "./pages/Reports.jsx";

import MySubscription from "./pages/MySubscription.jsx";

// ------------------------------------------------------
// MAIN CONTENT WRAPPER
// ------------------------------------------------------
function AppContent() {
  const location = useLocation();

  const isLoggedIn = () => !!localStorage.getItem("access");

  const authRoutes = ["/login", "/signup", "/forgot_password", "/sendlink"];

  const shouldShowLayout =
    isLoggedIn() && !authRoutes.includes(location.pathname);

  return (
    <div className="h-full bg-gray-50 flex text-gray-900">
      {/* Layout only when logged in */}
      {shouldShowLayout && (
        <>
          <Sidebar />
          <Header />
        </>
      )}

      <main className={shouldShowLayout ? "pl-64 pt-16 w-full" : "w-full"}>
        <Routes>
          {/* ---------------- AUTH ROUTES ---------------- */}
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/forgot_password" element={<ForgotPassword />} />
          <Route path="/sendlink" element={<SendLink />} />

          {/* Default */}
          <Route path="/" element={<Navigate to="/login" />} />

          {/* ---------------- PROTECTED ROUTES ---------------- */}
          <Route
            path="/dashboard"
            element={isLoggedIn() ? <Dashboard /> : <Navigate to="/login" />}
          />

          {/* ⭐ NEW: My Subscription Page */}
          <Route
            path="/my-subscription"
            element={
              isLoggedIn() ? <MySubscription /> : <Navigate to="/login" />
            }
          />

          <Route
            path="/branches"
            element={isLoggedIn() ? <Branches /> : <Navigate to="/login" />}
          />

          <Route
            path="/loans"
            element={isLoggedIn() ? <Loans /> : <Navigate to="/login" />}
          />

          <Route
            path="/logs"
            element={isLoggedIn() ? <Logs /> : <Navigate to="/login" />}
          />

          <Route
            path="/calendar"
            element={isLoggedIn() ? <Calendar /> : <Navigate to="/login" />}
          />

          <Route
            path="/roles_permissions"
            element={
              isLoggedIn() ? <RolesPermissions /> : <Navigate to="/login" />
            }
          />

          <Route
            path="/users"
            element={isLoggedIn() ? <Users /> : <Navigate to="/login" />}
          />

          <Route
            path="/settings"
            element={isLoggedIn() ? <Settings /> : <Navigate to="/login" />}
          />

          <Route
            path="/profile"
            element={isLoggedIn() ? <Profile /> : <Navigate to="/login" />}
          />

          <Route
            path="/notifications"
            element={
              isLoggedIn() ? <Notifications /> : <Navigate to="/login" />
            }
          />

          <Route
            path="/internal_team_management"
            element={
              isLoggedIn() ? (
                <InternalTeamManagement />
              ) : (
                <Navigate to="/login" />
              )
            }
          />

          <Route
            path="/rules-config"
            element={isLoggedIn() ? <Rules /> : <Navigate to="/login" />}
          />

          <Route
            path="/categories"
            element={isLoggedIn() ? <Categories /> : <Navigate to="/login" />}
          />

          <Route
            path="/reports"
            element={isLoggedIn() ? <Reports /> : <Navigate to="/login" />}
          />

          {/* ---------------- UNKNOWN ROUTES ---------------- */}
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </main>
    </div>
  );
}

// ------------------------------------------------------
// APP ROOT WRAPPER
// ------------------------------------------------------
export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
