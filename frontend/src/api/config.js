// Use environment variable, fallback to localhost for development
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const fetchDashboardData = async () => {
  try {
    const response = await fetch(`${API_URL}/api/dashboard`);
    if (!response.ok) throw new Error('Failed to fetch dashboard');
    return await response.json();
  } catch (error) {
    console.error('Dashboard error:', error);
    return null;
  }
};

export const runScanner = async () => {
  try {
    const response = await fetch(`${API_URL}/api/scanner/run`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Scanner failed');
    return await response.json();
  } catch (error) {
    console.error('Scanner error:', error);
    return null;
  }
};
