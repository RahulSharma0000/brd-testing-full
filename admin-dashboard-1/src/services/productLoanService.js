// src/services/productLoanService.js
import axiosInstance from "../utils/axiosInstance";

const BASE_URL = "adminpanel/loan-products/";

export const productLoanAPI = {
  getAll() {
    return axiosInstance.get(BASE_URL);
  },

  create(data) {
    return axiosInstance.post(BASE_URL, data);
  },

  update(id, data) {
    return axiosInstance.put(`${BASE_URL}${id}/`, data);
  },

  delete(id) {
    return axiosInstance.delete(`${BASE_URL}${id}/`);
  },
};
