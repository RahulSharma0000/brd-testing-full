import axios from "axios";

// .env से URL उठा रहा है
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
});

// हर Request में Token जोड़ने के लिए Interceptor
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// (Optional) अगर Token expire हो जाए तो Auto Logout के लिए
axiosInstance.interceptors.response.use(
  res => res,
  async error => {
    if (error.response?.status === 401) {
      const refresh = localStorage.getItem("refresh_token");
      if (!refresh) {
        localStorage.clear();
        window.location.href = "/login";
        return;
      }

      try {
        const res = await axios.post("/api/token/refresh/", { refresh });
        localStorage.setItem("access_token", res.data.access);
        error.config.headers.Authorization = `Bearer ${res.data.access}`;
        return axiosInstance(error.config);
      } catch {
        localStorage.clear();
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);


export default axiosInstance;