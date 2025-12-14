import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  HomeIcon,
  UsersIcon,
  CalendarDaysIcon,
  DocumentTextIcon,
  CubeIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  Cog6ToothIcon,
  ArrowLeftOnRectangleIcon,
  LinkIcon,
  BanknotesIcon,
  UserCircleIcon,
  CreditCardIcon,
  KeyIcon,
} from "@heroicons/react/24/outline";

const items = [
  { path: "/dashboard", label: "Dashboard", icon: HomeIcon },
  { path: "/branches", label: "Branches", icon: ServerStackIcon },

  { path: "/loans", label: "Loans", icon: BanknotesIcon },

  // ⭐ Added Subscription here
  { path: "/my-subscription", label: "My Subscription", icon: CreditCardIcon },

  { path: "/users", label: "Users", icon: UserCircleIcon },
  { path: "/calendar", label: "Calendar", icon: CalendarDaysIcon },
  { path: "/rules-config", label: "Rules", icon: DocumentTextIcon },

  { path: "/roles_permissions", label: "Roles & Permissions", icon: KeyIcon },
  { path: "/settings", label: "System Settings", icon: Cog6ToothIcon },
];



export default function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();

  const activePath = location.pathname;

  const isActive = (path) =>
    path === "/"
      ? activePath === "/"
      : activePath.startsWith(path);

  const handleLogout = () => {
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    navigate("/login");
  };

  return (
    <aside className="fixed inset-y-0 left-0 w-64 bg-white border-r border-gray-200 h-screen flex flex-col">
      <div className="h-16 flex items-center px-4 gap-3 border-b border-gray-100">
        <div className="h-9 w-9 rounded-xl bg-primary-600 grid place-items-center text-white">
          <ShieldCheckIcon className="h-5 w-5" />
        </div>
        <div className="flex flex-col">
          <div className="text-base font-semibold">Tenant Admin</div>
          <div className="text-xs text-gray-500">LOS Platform</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-2">
        {items.map(({ path, label, icon: Icon }) => (
          <Link
            key={path}
            to={path}
            className={`w-full flex items-center gap-3 px-4 py-2 text-base rounded-lg ${
              isActive(path)
                ? "text-primary-700 bg-primary-50"
                : "text-gray-700 hover:bg-gray-50"
            }`}
          >
            <Icon className="h-5 w-5" />
            <span className="whitespace-nowrap">{label}</span>
          </Link>
        ))}

        {/* Internal team */}
        <Link
          to="/internal_team_management"
          className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg ${
            isActive("/internal_team_management")
              ? "text-primary-700 bg-primary-50"
              : "text-gray-700 hover:bg-gray-50"
          }`}
        >
          <UsersIcon className="h-5 w-5" />
          <span>Internal Team Management</span>
        </Link>

        {/* Rules */}
       

        {/* Categories */}
        <Link
          to="/categories"
          className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg ${
            isActive("/categories")
              ? "text-primary-700 bg-primary-50"
              : "text-gray-700 hover:bg-gray-50"
          }`}
        >
          <LinkIcon className="h-5 w-5" />
          <span>Type of Category</span>
        </Link>
      </nav>

      {/* Logout */}
      <div className="p-2 border-t border-gray-100">
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-4 py-2 text-base text-red-600 hover:bg-red-50 rounded-lg"
        >
          <ArrowLeftOnRectangleIcon className="h-5 w-5" />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}
