import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { authService } from "../services/authServices.js";
import { FiMail, FiLock } from "react-icons/fi";

const Login = () => {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const { email, password } = formData;

    try {
      const user = await authService.login(email, password);

      if (!user) {
        await authService.recordLoginAttempt({ email, status: "Failed" });
        alert("Invalid email or password!");
        setLoading(false);
        return;
      }

      await authService.recordLoginAttempt({ email, status: "Success" });
      await authService.recordActivity("Logged in", user.email);

      setLoading(false);
      navigate("/dashboard");
    } catch (error) {
      console.error("Login error:", error);
      await authService.recordLoginAttempt({ email, status: "Failed" });
      setLoading(false);
      const errorMessage = error.message || "Invalid email or password. Please try again.";
      alert(errorMessage);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex justify-center items-center px-4">
      
      <div className="w-full max-w-md bg-white shadow-lg rounded-2xl p-8 border border-gray-200">

        {/* Header */}
        <div className="mb-6 text-center">
          <h2 className="text-3xl font-bold text-gray-900">Welcome Back</h2>
          <p className="text-gray-500 text-sm">Sign in to your account</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-5">

          {/* Email */}
          <div>
            <label className="block mb-1 text-gray-700 font-medium">Email</label>
            <div className="flex items-center border rounded-lg px-3 bg-gray-50">
              <FiMail className="text-gray-500" />
              <input
                type="email"
                name="email"
                placeholder="Enter your email"
                required
                value={formData.email}
                onChange={handleChange}
                className="w-full py-2 ml-2 bg-transparent outline-none"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="block mb-1 text-gray-700 font-medium">Password</label>

            <div className="flex items-center border rounded-lg px-3 bg-gray-50">
              <FiLock className="text-gray-500" />
              <input
                type="password"
                name="password"
                placeholder="Enter password"
                required
                value={formData.password}
                onChange={handleChange}
                className="w-full py-2 ml-2 bg-transparent outline-none"
              />
            </div>

            {/* Forgot password */}
            <p
              onClick={() => navigate("/forgot-password")}
              className="text-right text-sm text-blue-600 hover:underline cursor-pointer mt-1"
            >
              Forgot Password?
            </p>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2.5 rounded-lg font-semibold hover:bg-blue-700 transition"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        {/* Footer */}
        <p className="text-center mt-5 text-gray-600 text-sm">
          Don’t have an account?{" "}
          <span
            onClick={() => navigate("/signup")}
            className="text-blue-600 cursor-pointer hover:underline font-semibold"
          >
            Create one
          </span>
        </p>

      </div>
    </div>
  );
};

export default Login;
