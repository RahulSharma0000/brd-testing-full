import { useEffect, useState } from "react";
import { subscriptionAPI } from "../services/subscriptionService";

export default function MySubscription() {
  const [sub, setSub] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null); // message to show inside page

  const load = async () => {
    setLoading(true);
    try {
      const res = await subscriptionAPI.getMySubscription();
      setSub(res.data);
    } catch (e) {
      setError(e.response?.data?.detail || "Unable to load subscription");
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, []);

  const doAction = async (action) => {
    if (
      !window.confirm(`Are you sure you want to ${action} this subscription?`)
    )
      return;

    setActionLoading(true);
    setMessage(null);
    try {
      const res = await subscriptionAPI.takeAction(action);
      setMessage(res.data.message); // show message inside page
      await load();
    } catch (e) {
      setMessage(e.response?.data?.detail || "Something went wrong");
    }
    setActionLoading(false);
  };

  const statusColors = {
    Active: "bg-green-100 text-green-800",
    Pause: "bg-yellow-100 text-yellow-800",
    Cancel: "bg-red-100 text-red-800",
  };

  if (loading)
    return (
      <div className="p-6 animate-pulse max-w-4xl mx-auto">
        <div className="h-6 bg-gray-200 rounded w-1/3 mb-4"></div>
        <div className="bg-gray-100 h-64 rounded-lg"></div>
      </div>
    );

  if (error)
    return <div className="p-6 max-w-4xl mx-auto text-red-500">{error}</div>;

  if (!sub)
    return (
      <div className="p-6 max-w-4xl mx-auto text-gray-500">
        No subscription found
      </div>
    );

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <h2 className="text-2xl font-semibold text-gray-900">My Subscription</h2>

      {/* message display */}
      {message && (
        <div className="bg-blue-100 text-blue-800 rounded p-3">{message}</div>
      )}

      {/* Top summary card */}
      <div className="bg-white shadow-lg rounded-xl p-6 flex flex-col md:flex-row justify-between items-center gap-6 border border-gray-100">
        <div className="flex flex-col md:flex-row items-center gap-6">
          <SummaryItem label="Subscription" value={sub.subscription_name} />
          <SummaryItem label="Amount" value={`₹${sub.subscription_amount}`} />
          <SummaryItem label="Borrowers" value={sub.no_of_borrowers} />
          <span
            className={`px-4 py-2 rounded-full font-semibold text-sm ${
              statusColors[sub.status] || "bg-gray-200 text-gray-700"
            }`}
          >
            {sub.status}
          </span>
        </div>

        {/* Action buttons container */}
        <div className="mt-4 md:mt-0 flex gap-2 w-full md:w-auto justify-center">
          {sub.status === "Pause" && (
            <ActionButton
              label="Resume"
              color="green"
              onClick={() => doAction("resume")}
              disabled={actionLoading}
            />
          )}

          {sub.status === "Active" && (
            <div className="flex gap-2">
              <ActionButton
                label="Pause"
                color="yellow"
                onClick={() => doAction("pause")}
                disabled={actionLoading}
              />
              <ActionButton
                label="Cancel"
                color="red"
                onClick={() => doAction("cancel")}
                disabled={actionLoading}
              />
            </div>
          )}

          {sub.status !== "Active" &&
            sub.status !== "Pause" &&
            sub.status !== "Cancel" && (
              <ActionButton
                label="Cancel"
                color="red"
                onClick={() => doAction("cancel")}
                disabled={actionLoading}
              />
            )}

          {sub.status === "Cancel" && (
            <div className="text-gray-400 text-center font-medium">
              Cancelled
            </div>
          )}
        </div>
      </div>

      {/* Full subscription details */}
      <div className="bg-white shadow-lg rounded-xl p-6 border border-gray-100 space-y-2">
        <DetailRow label="Type" value={sub.type_of} />
        <DetailRow label="Created By" value={sub.created_user} />
        <DetailRow label="Modified By" value={sub.modified_user} />
        <DetailRow
          label="Created At"
          value={new Date(sub.created_at).toLocaleString()}
        />
        <DetailRow
          label="Modified At"
          value={new Date(sub.modified_at).toLocaleString()}
        />
        <DetailRow label="UUID" value={sub.uuid} />
      </div>
    </div>
  );
}

// Summary small card
function SummaryItem({ label, value }) {
  return (
    <div className="flex flex-col items-center text-center">
      <span className="text-gray-500 text-sm">{label}</span>
      <span className="text-gray-900 font-semibold">{value}</span>
    </div>
  );
}

// Detail row
function DetailRow({ label, value }) {
  return (
    <div className="flex justify-between border-b border-gray-100 pb-1">
      <span className="text-gray-600">{label}</span>
      <span>{value}</span>
    </div>
  );
}

// Action button
function ActionButton({ label, color, onClick, disabled }) {
  const colors = {
    green: "bg-green-600 hover:bg-green-700",
    red: "bg-red-600 hover:bg-red-700",
    yellow: "bg-yellow-500 hover:bg-yellow-600",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-5 py-2 rounded-lg text-white font-medium ${colors[color]} transition-colors duration-200 disabled:opacity-50`}
    >
      {label}
    </button>
  );
}
