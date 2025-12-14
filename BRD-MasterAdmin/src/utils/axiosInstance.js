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
  (response) => response,
  (error) => {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      // अगर Unauthorized है, तो logout कर सकते हैं
      // localStorage.clear();
      // window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default axiosInstance;