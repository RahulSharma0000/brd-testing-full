import { useState } from "react";
import axiosInstance from "../utils/axiosInstance";
import { ShieldCheckIcon, EnvelopeIcon } from "@heroicons/react/24/outline";
import { useNavigate } from "react-router-dom";

export default function Signup() {
  const navigate = useNavigate();

  const [businessName, setBusinessName] = useState("");
  const [contactPerson, setContactPerson] = useState("");
  const [mobile, setMobile] = useState("");
  const [address, setAddress] = useState("");
  const [loanProduct, setLoanProduct] = useState("");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const [formErrors, setFormErrors] = useState({});
  const [globalError, setGlobalError] = useState(null);
  const [status, setStatus] = useState(null);

  const FieldError = ({ error }) => {
    if (!error) return null;
    return <div className="mt-1 text-sm text-red-600">{error}</div>;
  };

  const validators = {
    business_name: (v) => {
      if (!v) return "Business name is required";
      if (v.trim().length < 3) return "Minimum 3 characters required";
      if (!/^[a-zA-Z0-9 .&-]+$/.test(v)) return "Invalid characters used";
      return null;
    },

    contact_person: (v) => {
      if (!v) return "Contact person is required";
      if (v.trim().length < 3) return "Minimum 3 characters required";
      if (!/^[a-zA-Z ]+$/.test(v)) return "Only letters allowed";
      return null;
    },

    mobile_no: (v) => {
      if (!v) return "Mobile number is required";
      if (!/^[6-9]\d{9}$/.test(v)) return "Enter valid 10-digit mobile number";
      return null;
    },

    address: (v) => {
      if (!v) return "Address is required";
      if (v.trim().length < 10) return "Address too short";
      return null;
    },

    loan_product: (v) => {
      if (!v) return "Loan product is required";
      if (v.trim().length < 3) return "Minimum 3 characters required";
      if (!/^[a-zA-Z ]+$/.test(v)) return "Only letters allowed";
      return null;
    },

    email: (v) => {
      if (!v) return "Email is required";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return "Invalid email format";
      return null;
    },

    password: (v) => {
      if (!v) return "Password is required";
      if (v.length < 8) return "Minimum 8 characters required";
      if (!/[A-Z]/.test(v)) return "At least one uppercase letter required";
      if (!/[a-z]/.test(v)) return "At least one lowercase letter required";
      if (!/\d/.test(v)) return "At least one number required";
      return null;
    },
  };

  const doSignup = async () => {
    setGlobalError(null);
    setStatus(null);
    setFormErrors({});

    const errors = {};

    errors.business_name = validators.business_name(businessName);
    errors.contact_person = validators.contact_person(contactPerson);
    errors.mobile_no = validators.mobile_no(mobile);
    errors.address = validators.address(address);
    errors.loan_product = validators.loan_product(loanProduct);
    errors.email = validators.email(email);
    errors.password = validators.password(password);

    if (password !== confirm) {
      errors.confirm = "Passwords do not match";
    }

    // Remove null values
    Object.keys(errors).forEach(
      (key) => errors[key] === null && delete errors[key]
    );

    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    try {
      await axiosInstance.post("tenants/signup/", {
        business_name: businessName.trim(),
        email: email.trim().toLowerCase(),
        password,
        mobile_no: mobile,
        address: address.trim(),
        contact_person: contactPerson.trim(),
        loan_product: [loanProduct.trim()],
      });

      setStatus("Signup successful! Redirecting to login...");
      setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      const data = err?.response?.data;
      if (data && typeof data === "object") {
        setFormErrors(data);
      } else {
        setGlobalError("Signup failed. Please try again.");
      }
    }
  };

  return (
    <div className="min-h-screen bg-white grid place-items-center">
      <div className="w-full max-w-md rounded-2xl border border-primary-200 bg-white shadow-card p-6">
        {/* Header */}
        <div className="grid place-items-center">
          <div className="h-12 w-12 rounded-full bg-primary-50 grid place-items-center text-primary-600">
            <ShieldCheckIcon className="h-6 w-6" />
          </div>
          <div className="mt-4 text-3xl font-semibold text-gray-900 text-center">
            Create your account
          </div>
          <div className="mt-1 text-sm text-gray-600 text-center">
            Sign up to access your dashboard
          </div>
        </div>

        {/* GLOBAL ERROR */}
        {globalError && (
          <div className="mt-3 bg-red-50 text-red-700 border border-red-200 rounded-lg p-3">
            {globalError}
          </div>
        )}

        {/* SUCCESS */}
        {status && (
          <div className="mt-3 bg-green-50 text-green-700 border border-green-200 rounded-lg p-3">
            {status}
          </div>
        )}

        {/* BUSINESS NAME */}
        <label className="block mt-6">
          <div className="text-sm text-gray-900">Business / Tenant Name</div>
          <input
            type="text"
            placeholder="e.g. ABC Finance Pvt Ltd"
            value={businessName}
            onChange={(e) => setBusinessName(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.business_name} />
        </label>

        {/* CONTACT PERSON */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Contact Person</div>
          <input
            type="text"
            placeholder="Owner / Manager Name"
            value={contactPerson}
            onChange={(e) => setContactPerson(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.contact_person} />
        </label>

        {/* MOBILE NO */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Mobile Number</div>
          <input
            type="tel"
            maxLength={10}
            inputMode="numeric"
            pattern="[6-9]{1}[0-9]{9}"
            placeholder="9876543210"
            value={mobile}
            onChange={(e) => setMobile(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.mobile_no} />
        </label>

        {/* ADDRESS */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Address</div>
          <input
            type="text"
            placeholder="Full business address"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.address} />
        </label>

        {/* LOAN PRODUCT */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Loan Product</div>
          <input
            type="text"
            placeholder="e.g. Personal Loan, Micro Loan"
            value={loanProduct}
            onChange={(e) => setLoanProduct(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.loan_product} />
        </label>

        {/* EMAIL */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Email</div>
          <input
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.email} />
        </label>

        {/* PASSWORD */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Password</div>
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.password} />
        </label>

        {/* CONFIRM PASSWORD */}
        <label className="block mt-4">
          <div className="text-sm text-gray-900">Confirm Password</div>
          <input
            type="password"
            placeholder="Re-enter password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="mt-1 w-full h-11 rounded-xl border px-3"
          />
          <FieldError error={formErrors.confirm} />
        </label>

        {/* SIGN UP BUTTON */}
        <div className="mt-6">
          <button
            className="h-11 w-full rounded-xl bg-primary-600 text-white hover:bg-primary-700"
            onClick={doSignup}
          >
            Sign Up
          </button>
        </div>

        {/* LOGIN LINK */}
        <div className="mt-6 text-center text-sm">
          <span className="text-gray-700">Already have an account? </span>
          <button
            className="text-primary-600"
            onClick={() => navigate("/login")}
          >
            Sign In
          </button>
        </div>
      </div>
    </div>
  );
}
