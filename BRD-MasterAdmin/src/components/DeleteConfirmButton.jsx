import { useState } from "react";
import { FiTrash2 } from "react-icons/fi";

export default function DeleteConfirmButton({
  title,
  message,
  onConfirm,
  onCancel,
}) {
  return (
    <div className="fixed inset-0 backdrop-blur-sm bg-black/30 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl p-6 w-full max-w-sm shadow-xl">
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="text-sm text-gray-600 mb-6">{message}</p>

        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-gray-100 rounded-xl"
          >
            Cancel
          </button>

          <button
            onClick={onConfirm}
            className="px-4 py-2 bg-red-600 text-white rounded-xl"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

