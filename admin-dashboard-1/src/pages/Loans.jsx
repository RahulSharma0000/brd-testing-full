// src/pages/Loans.jsx
import { useEffect, useMemo, useState } from "react";
import { loanAPI } from "../services/loanService";

export default function Loans() {
  const emptyForm = {
    name: "",
    loan_type: "personal",
    description: "",
    min_amount: "",
    max_amount: "",
    interest_rate: "",
    processing_fee: "",
    min_tenure_months: "",
    max_tenure_months: "",
  };

  const [items, setItems] = useState([]);
  const [search, setSearch] = useState("");

  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const [modalError, setModalError] = useState("");
  const [form, setForm] = useState(emptyForm);

  // ---------------- LOAD LOAN PRODUCTS ----------------
  const loadLoans = async () => {
    try {
      const res = await loanAPI.getAll();
      setItems(res.data || []);
    } catch {
      console.log("Error loading loans");
    }
  };

  useEffect(() => {
    loadLoans();
  }, []);

  // ---------------- SEARCH FILTER ----------------
  const filteredItems = useMemo(() => {
    const s = search.toLowerCase();
    if (!s) return items;
    return items.filter(
      (x) =>
        x.name.toLowerCase().includes(s) ||
        x.loan_type.toLowerCase().includes(s)
    );
  }, [items, search]);

  // ---------------- CREATE ----------------
  const createLoan = async () => {
    setModalError("");

    try {
      await loanAPI.create(form);
      setCreating(false);
      setForm(emptyForm);
      loadLoans();
    } catch {
      setModalError("Failed to create loan product");
    }
  };

  // ---------------- UPDATE ----------------
  const updateLoan = async () => {
    setModalError("");

    try {
      await loanAPI.update(editing.id, editing);
      setEditing(null);
      loadLoans();
    } catch {
      setModalError("Failed to update loan product");
    }
  };

  // ---------------- DELETE ----------------
  const deleteLoan = async () => {
    try {
      await loanAPI.delete(deleting.id);
      setDeleting(null);
      loadLoans();
    } catch {
      console.log("delete error");
    }
  };

  return (
    <div className="p-4 space-y-4">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Manage Loan Products</h1>

        <button
          className="h-9 px-4 rounded-lg bg-primary-600 text-white"
          onClick={() => {
            setForm(emptyForm);
            setCreating(true);
          }}
        >
          + Add Loan Product
        </button>
      </div>

      {/* SEARCH */}
      <input
        className="border px-3 py-2 rounded-lg w-64"
        placeholder="Search loan..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {/* TABLE */}
      <div className="bg-white rounded-lg border shadow-sm overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b text-gray-600">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Amount</th>
              <th className="px-4 py-3">Interest</th>
              <th className="px-4 py-3">Tenure</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>

          <tbody>
            {filteredItems.map((loan) => (
              <tr key={loan.id} className="border-t">
                <td className="px-4 py-3">{loan.name}</td>
                <td className="px-4 py-3">{loan.loan_type}</td>
                <td className="px-4 py-3">₹{loan.min_amount} - ₹{loan.max_amount}</td>
                <td className="px-4 py-3">{loan.interest_rate}%</td>
                <td className="px-4 py-3">
                  {loan.min_tenure_months}–{loan.max_tenure_months} months
                </td>

                <td className="px-4 py-3 flex gap-2">
                  <button
                    className="px-3 py-1 rounded border"
                    onClick={() => setEditing({ ...loan })}
                  >
                    Edit
                  </button>

                  <button
                    className="px-3 py-1 rounded border border-red-400 text-red-600"
                    onClick={() => setDeleting(loan)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}

            {!filteredItems.length && (
              <tr>
                <td colSpan={6} className="p-4 text-center text-gray-600">
                  No loans found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ------------------- CREATE MODAL ------------------- */}
      {creating && (
        <Modal title="Add Loan Product" onClose={() => setCreating(false)}>
          <LoanForm form={form} setForm={setForm} />

          {modalError && (
            <div className="bg-red-100 text-red-700 p-2 rounded mt-2">
              {modalError}
            </div>
          )}

          <div className="flex justify-end gap-2 mt-6">
            <button className="px-4 py-2 border rounded" onClick={() => setCreating(false)}>
              Cancel
            </button>

            <button
              className="px-4 py-2 bg-primary-600 text-white rounded"
              onClick={createLoan}
            >
              Save
            </button>
          </div>
        </Modal>
      )}

      {/* ------------------- EDIT MODAL ------------------- */}
      {editing && (
        <Modal title="Edit Loan Product" onClose={() => setEditing(null)}>
          <LoanForm form={editing} setForm={setEditing} />

          {modalError && (
            <div className="bg-red-100 text-red-700 p-2 rounded mt-2">
              {modalError}
            </div>
          )}

          <div className="flex justify-end gap-2 mt-6">
            <button onClick={() => setEditing(null)} className="px-4 py-2 border rounded">
              Cancel
            </button>

            <button
              className="px-4 py-2 bg-primary-600 text-white rounded"
              onClick={updateLoan}
            >
              Update
            </button>
          </div>
        </Modal>
      )}

      {/* ------------------- DELETE MODAL ------------------- */}
      {deleting && (
        <Modal title="Delete Loan Product?" onClose={() => setDeleting(null)}>
          <p className="text-gray-600">
            Are you sure you want to delete{" "}
            <b className="text-red-600">{deleting.name}</b>?
          </p>

          <div className="flex justify-end gap-2 mt-6">
            <button className="px-4 py-2 border rounded" onClick={() => setDeleting(null)}>
              Cancel
            </button>

            <button
              className="px-4 py-2 bg-red-600 text-white rounded"
              onClick={deleteLoan}
            >
              Delete
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

/* -------------------- FORM FIELDS -------------------- */
function LoanForm({ form, setForm }) {
  return (
    <div className="mt-4 space-y-3">
      <input
        className="border w-full rounded px-3 py-2"
        placeholder="Loan Name"
        value={form.name}
        onChange={(e) => setForm({ ...form, name: e.target.value })}
      />

      <textarea
        className="border w-full rounded px-3 py-2"
        placeholder="Description"
        value={form.description}
        onChange={(e) => setForm({ ...form, description: e.target.value })}
      />

      <div className="grid grid-cols-2 gap-2">
        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Min Amount"
          value={form.min_amount}
          onChange={(e) => setForm({ ...form, min_amount: e.target.value })}
        />

        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Max Amount"
          value={form.max_amount}
          onChange={(e) => setForm({ ...form, max_amount: e.target.value })}
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Interest Rate (%)"
          value={form.interest_rate}
          onChange={(e) => setForm({ ...form, interest_rate: e.target.value })}
        />

        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Processing Fee"
          value={form.processing_fee}
          onChange={(e) => setForm({ ...form, processing_fee: e.target.value })}
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Min Tenure"
          value={form.min_tenure_months}
          onChange={(e) =>
            setForm({ ...form, min_tenure_months: e.target.value })
          }
        />

        <input
          type="number"
          className="border w-full rounded px-3 py-2"
          placeholder="Max Tenure"
          value={form.max_tenure_months}
          onChange={(e) =>
            setForm({ ...form, max_tenure_months: e.target.value })
          }
        />
      </div>
    </div>
  );
}

/* -------------------- MODAL -------------------- */
function Modal({ title, children, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white w-full max-w-md rounded-xl p-6 shadow-lg relative">
        <h2 className="text-lg font-semibold">{title}</h2>

        <div className="mt-4">{children}</div>

        <button className="absolute top-3 right-4 text-lg" onClick={onClose}>
          ✕
        </button>
      </div>
    </div>
  );
}
