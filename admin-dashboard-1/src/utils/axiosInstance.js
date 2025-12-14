// src/utils/axiosInstance.js
import axios from "axios";
import authService from "../services/authService";

const BASE_URL = import.meta.env.VITE_BASE_URL;

// Base config
const axiosInstance = axios.create({
  baseURL: `${BASE_URL}/api/v1/`,
  withCredentials: false,
});

// Public routes that don't require token
const noAuthUrls = ["token/", "token/refresh/", "tenants/signup/"];

// Request interceptor
axiosInstance.interceptors.request.use(
  (config) => {
    if (config.url.startsWith("/")) config.url = config.url.slice(1);

    if (noAuthUrls.some((u) => config.url.startsWith(u))) return config;

    const token = authService.getAccessToken();
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }

    config.headers["Content-Type"] = "application/json";
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 &&
      !noAuthUrls.some((u) => error.config.url.startsWith(u))
    ) {
      console.warn("🔐 Token expired → Logging out...");
      authService.logout();
    }
    return Promise.reject(error);
  }
);

export default axiosInstance;
