import axios from "axios";
import axiosInstance from "../utils/axiosInstance";

// Login URL root par hai (/api/token/), isliye hum ROOT URL define karte hain
const ROOT_URL = "http://127.0.0.1:8000"; 

export const authService = {
  // LOGIN
  login: async (email, password) => {
    try {
      // Note: Login /api/v1 ke bahar hai, isliye direct axios use kar rahe hain
      const response = await axios.post(`${ROOT_URL}/api/token/`, {
        email: email.toLowerCase().trim(),
        password: password,
      });

      if (response.data?.access) {
        localStorage.setItem("access_token", response.data.access);
        localStorage.setItem("refresh_token", response.data.refresh);
        localStorage.setItem("user_email", email);
        return response.data;
      }
      return null;
    } catch (error) {
      console.error("Login Error:", error.response?.data || error.message);
      throw error;
    }
  },

  // SIGNUP
  signup: async (userData) => {
    try {
      // ✅ Fix: axiosInstance use karenge jo already '/api/v1' par set hai.
      // Isliye yahan sirf '/users/signup/' likhna hai.
      const response = await axiosInstance.post("/users/signup/", {
        email: userData.email,
        password: userData.password,
        role: "MASTER_ADMIN", // Default role
        first_name: userData.firstName,
        last_name: userData.lastName
      });
      return response.data;
    } catch (error) {
      console.error("Signup Error:", error.response?.data || error.message);
      throw error;
    }
  },

  // Helpers
  recordLoginAttempt: async () => {},
  recordActivity: async () => {},
};