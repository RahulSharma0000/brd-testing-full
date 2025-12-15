import axios from "axios";
import axiosInstance from "../utils/axiosInstance";

const ROOT_URL = "http://127.0.0.1:8000";

export const authService = {
  login: async (email, password) => {
  const res = await axios.post(`${ROOT_URL}/api/token/`, { email, password });

  if (res.data.requires_2fa) {
    return { requires2FA: true };
  }

  localStorage.setItem("access_token", res.data.access);
  localStorage.setItem("refresh_token", res.data.refresh);
},

verify2FA: async (email, code) => {
  const res = await axios.post(`${ROOT_URL}/api/v1/users/2fa/login/`, {
    email,
    code,
  });

  localStorage.setItem("access_token", res.data.access);
  localStorage.setItem("refresh_token", res.data.refresh);
},

  signup: async (data) => {
    const response = await axiosInstance.post("/users/signup/", {
      email: data.email,
      password: data.password,
      first_name: data.firstName,
      last_name: data.lastName
    });

    return response.data;
  },
};
