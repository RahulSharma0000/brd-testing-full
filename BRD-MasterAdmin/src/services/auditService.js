import axiosInstance from "../utils/axiosInstance";

const BASE_URL = "/users/audit-logs/";

export const auditService = {
  // GET ALL LOGS (with optional filters)
  async getLogs(params = {}) {
    try {
      const res = await axiosInstance.get(BASE_URL, { params });
      return res.data;
    } catch (error) {
      console.error("Fetch Audit Logs Error:", error);
      return [];
    }
  },

  // ADD LOG (Manual entry if needed)
  async addLog(payload) {
    try {
      const res = await axiosInstance.post(BASE_URL, payload);
      return res.data;
    } catch (error) {
      console.error("Add Audit Log Error:", error);
      throw error;
    }
  },

  // DELETE LOG
  async deleteLog(id) {
    await axiosInstance.delete(`${BASE_URL}${id}/`);
  },
  
  // UPDATE LOG
  async updateLog(id, payload) {
    const res = await axiosInstance.patch(`${BASE_URL}${id}/`, payload);
    return res.data;
  }
};