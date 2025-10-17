import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

class ApiClient {
  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('authToken');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async login(credentials) {
    const response = await this.client.post('/auth/login', credentials);
    return response.data;
  }

  async getDashboardStats() {
    const response = await this.client.get('/api/dashboard/stats');
    return response.data;
  }

  async getScans() {
    const response = await this.client.get('/api/scans');
    return response.data;
  }

  async createScan(scanData) {
    const response = await this.client.post('/api/scans', scanData);
    return response.data;
  }

  async deleteScan(scanId) {
    const response = await this.client.delete(`/api/scans/${scanId}`);
    return response.data;
  }

  async getVulnerabilities(filters = {}) {
    const response = await this.client.get('/api/vulnerabilities', { params: filters });
    return response.data;
  }

  async getScanResults(scanId) {
    const response = await this.client.get(`/api/scans/${scanId}/results`);
    return response.data;
  }
}

export const apiClient = new ApiClient();
