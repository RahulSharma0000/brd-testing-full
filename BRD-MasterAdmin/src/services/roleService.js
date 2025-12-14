import { api } from "./api";

// ✅ Fix: '/api/v1' हटा दिया गया है
const BASE_URL = "/adminpanel/role-masters/";

export const roleService = {

  // 1. GET ALL ROLES
  async getRoles() {
    try {
      const res = await api.get(BASE_URL);
      return res.data.map(r => ({
        id: r.id,
        roleName: r.name,
        description: r.description,
        createdAt: r.created_at
      }));
    } catch (error) {
      console.error("Fetch Roles Error:", error);
      return [];
    }
  },

  // 2. ADD ROLE
  async addRole(roleName) {
    try {
      const res = await api.post(BASE_URL, { name: roleName });
      return res.data;
    } catch (error) {
      throw error;
    }
  },

  // 3. DELETE ROLE
  async deleteRole(roleId) {
    try {
      await api.delete(`${BASE_URL}${roleId}/`);
      return true;
    } catch (error) {
      return false;
    }
  },

  // 4. GET PERMISSIONS
  async getPermissions(roleId) {
    try {
      const res = await api.get(`${BASE_URL}${roleId}/permissions/`);
      return res.data; 
    } catch (error) {
      console.error("Fetch Permissions Error:", error);
      return {};
    }
  },

  // 5. SAVE PERMISSIONS
  async savePermissions(roleId, permissions) {
    try {
      await api.post(`${BASE_URL}${roleId}/permissions/`, { permissions });
      return true;
    } catch (error) {
      console.error("Save Permissions Error:", error);
      throw error;
    }
  },
};