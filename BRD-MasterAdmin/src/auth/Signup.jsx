import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { authService } from "../services/authServices";

const Signup = () => {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
    confirmPassword: ""
  });

  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    // Email format check
    if (!formData.email.includes("@")) {
      alert("Please enter a valid email address.");
      setLoading(false);
      return;
    }

    // Password match check
    if (formData.password !== formData.confirmPassword) {
      alert("Passwords do not match!");
      setLoading(false);
      return;
    }

    // Minimum password strength
    if (formData.password.length < 8) {
      alert("Password must be at least 8 characters.");
      setLoading(false);
      return;
    }

    // Check if user already exists (localStorage)
    const storedUsers = JSON.parse(localStorage.getItem("registeredUsers")) || [];
    const emailExists = storedUsers.some(u => u.email === formData.email);

    if (emailExists) {
      alert("This email is already registered. Please login.");
      setLoading(false);
      return;
    }

    // Create user object
    const newUser = {
      id: Date.now(),
      firstName: formData.firstName,
      lastName: formData.lastName,
      email: formData.email.toLowerCase().trim(),
      password: formData.password,
      role: "MASTER_ADMIN",
      createdAt: new Date().toLocaleString()
    };

    try {
      // Save user (Backend-Ready)
      const result = await authService.signup(newUser);

      // Record activity
      await authService.recordActivity(
        "New account created",
        newUser.email
      );

      setLoading(false);
      alert("Account created successfully! Please login with your credentials.");
      navigate("/login");
    } catch (error) {
      console.error("Signup error:", error);
      setLoading(false);
      const errorMessage = error.response?.data?.email?.[0] || 
                          error.response?.data?.password?.[0] ||
                          error.response?.data?.detail ||
                          error.message ||
                          "Failed to create account. Please try again.";
      alert(errorMessage);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex justify-center items-center px-4">
      <div className="w-full max-w-md bg-white shadow-lg rounded-xl p-8">

        {/* Header */}
        <h2 className="text-3xl font-semibold text-blue-600 mb-1">
          Create account
        </h2>
        <p className="text-gray-500 mb-6">
          Make the most of your professional life
        </p>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">

          {/* First Name */}
          <div>
            <label className="block mb-1 font-medium">First name</label>
            <input
              type="text"
              name="firstName"
              className="w-full px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              placeholder="Enter first name"
              required
              value={formData.firstName}
              onChange={handleChange}
            />
          </div>

          {/* Last Name */}
          <div>
            <label className="block mb-1 font-medium">Last name</label>
            <input
              type="text"
              name="lastName"
              className="w-full px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              placeholder="Enter last name"
              required
              value={formData.lastName}
              onChange={handleChange}
            />
          </div>

          {/* Email */}
          <div>
            <label className="block mb-1 font-medium">Email Address</label>
            <input
              type="email"
              name="email"
              className="w-full px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              placeholder="Enter your email"
              required
              value={formData.email}
              onChange={handleChange}
            />
          </div>

          {/* Password */}
          <div>
            <label className="block mb-1 font-medium">Password (8+ chars)</label>
            <input
              type="password"
              name="password"
              className="w-full px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              placeholder="Create password"
              required
              value={formData.password}
              onChange={handleChange}
            />
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block mb-1 font-medium">Confirm password</label>
            <input
              type="password"
              name="confirmPassword"
              className="w-full px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              placeholder="Confirm password"
              required
              value={formData.confirmPassword}
              onChange={handleChange}
            />
          </div>

          {/* Terms */}
          <div className="flex items-start space-x-2">
            <input type="checkbox" required className="mt-1" />
            <p className="text-gray-600 text-sm">
              I agree to the{" "}
              <span className="text-blue-600 cursor-pointer">
                Xpertland.ai agreements
              </span>{" "}
              and privacy policy.
            </p>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 rounded-lg font-semibold hover:bg-blue-700 transition"
          >
            {loading ? "Creating account..." : "Agree and create account"}
          </button>
        </form>

        {/* Footer */}
        <p className="text-center mt-4 text-gray-600">
          Already have an account?{" "}
          <a href="/login" className="text-blue-600 hover:underline">
            Sign in
          </a>
        </p>

      </div>
    </div>
  );
};

export default Signup;
