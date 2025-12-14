import axiosInstance from "../utils/axiosInstance";

// Correct base URL
const BASE_URL = "/adminpanel/subscriptions/";

const subscriptionService = {
  // GET ALL
  async getAll() {
    const res = await axiosInstance.get(BASE_URL);
    return res.data;
  },

  // GET ONE
  async getOne(uuid) {
    const res = await axiosInstance.get(`${BASE_URL}${uuid}/`);
    return res.data;
  },

  // CREATE
  async create(data) {
    const res = await axiosInstance.post(BASE_URL, data);
    return res.data;
  },

  // UPDATE
  async update(uuid, data) {
    const res = await axiosInstance.put(`${BASE_URL}${uuid}/`, data);
    return res.data;
  },

  // DELETE
  async delete(uuid) {
    await axiosInstance.delete(`${BASE_URL}${uuid}/`);
    return true;
  }
};

export default subscriptionService;
