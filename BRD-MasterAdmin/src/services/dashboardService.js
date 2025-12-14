import axiosInstance from "../utils/axiosInstance";

export const dashboardService = {
  
  async getSummaryCards() {
    try {
      // ✅ Fix: '/api/v1' hata diya, sirf '/dashboard/full' rakha
      const res = await axiosInstance.get("/dashboard/full");
      const kpis = res.data?.kpis || {};
      
      return {
        totalOrganizations: kpis.totalTenants || 0,
        totalBranches: kpis.totalBranches || 0,
        activeUsers: kpis.activeUsers || 0,
        activeLoans: kpis.totalLoans || 0,
        dailyDisbursement: kpis.disbursedAmount || "₹0",
        apiStatus: kpis.apiStatus || "Online",
        alerts: (res.data?.alerts || []).length,
      };
    } catch (error) {
      return {
        totalOrganizations: 0, totalBranches: 0, activeUsers: 0, 
        activeLoans: 0, dailyDisbursement: "₹0", apiStatus: "Error", alerts: 0
      };
    }
  },

  async getLoanTrends() {
    try {
      const res = await axiosInstance.get("/dashboard/full");
      return res.data?.charts?.monthlyDisbursement || [];
    } catch (error) {
      return [];
    }
  },

  async getUsersPerBranch() {
    try {
      const res = await axiosInstance.get("/dashboard/full");
      return res.data?.charts?.usersPerBranch || [];
    } catch (error) {
      return [];
    }
  },

  async getActivities() {
    try {
      const res = await axiosInstance.get("/dashboard/full");
      return res.data?.charts?.recentActivity || [];
    } catch (error) {
      return [];
    }
  },

  async getAlerts() {
    try {
      const res = await axiosInstance.get("/dashboard/full");
      return res.data?.alerts || [];
    } catch (error) {
      return [];
    }
  },
};