import axios from "axios";

const tenantInstance = axios.create({
  baseURL: "http://127.0.0.1:8000/api/v1/tenants/",
  withCredentials: true,
});

tenantInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem("access");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const tenantAPI = {
  getAll: () => tenantInstance.get("/"),
  getById: (id) => tenantInstance.get(`${id}/`),
  create: (data) => tenantInstance.post("/", data),
  update: (id, data) => tenantInstance.put(`${id}/`, data),
  delete: (id) => tenantInstance.delete(`${id}/`),
};
