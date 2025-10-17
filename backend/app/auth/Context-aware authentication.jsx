import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (token) {
      // Здесь можно добавить проверку токена через API
      setIsAuthenticated(true);
      setUser({ username: 'admin' }); // Заменить на данные из токена
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    try {
      // Здесь будет вызов API для логина
      const response = await apiClient.login(credentials);
      localStorage.setItem('authToken', response.access_token);
      setIsAuthenticated(true);
      setUser({ username: credentials.username });
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    setIsAuthenticated(false);
    setUser(null);
  };

  const value = {
    isAuthenticated,
    user,
    login,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
