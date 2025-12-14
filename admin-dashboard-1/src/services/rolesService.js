import axiosInstance from "../utils/axiosInstance";

const BASE_URL = "adminpanel/roles/";

export const roleAPI = {
  async list() {
    return axiosInstance.get(BASE_URL);
  },
  async create(data) {
    return axiosInstance.post(BASE_URL, data);
  },
  async update(id, data) {
    return axiosInstance.put(`${BASE_URL}${id}/`, data);
  },
  async delete(id) {
    return axiosInstance.delete(`${BASE_URL}${id}/`);
  }
};
