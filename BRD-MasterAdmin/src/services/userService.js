import axiosInstance from "../utils/axiosInstance";

// Keep BASE_URL as router path ending with a slash
const BASE_URL = "/users/users/"; // ✅ trailing slash added

export const userService = {
  // GET ALL USERS
  async getUsers() {
    try {
      const res = await axiosInstance.get(BASE_URL);
      return res.data; 
    } catch (error) {
      console.error("Error fetching users:", error);
      return [];
    }
  },

  // GET SINGLE USER
  async getUser(id) {
    const res = await axiosInstance.get(`${BASE_URL}${id}/`); // ✅ id with trailing slash
    return res.data;
  },

  // ADD USER
  async addUser(data) {
    const res = await axiosInstance.post(BASE_URL, data); // ✅ POST to URL with trailing slash
    return res.data;
  },

  // UPDATE USER
  async updateUser(id, data) {
    const res = await axiosInstance.patch(`${BASE_URL}${id}/`, data); // ✅ trailing slash
    return res.data;
  },

  // DELETE USER
  async deleteUser(id) {
    return axiosInstance.delete(`${BASE_URL}${id}/`); // ✅ trailing slash
  },
};
