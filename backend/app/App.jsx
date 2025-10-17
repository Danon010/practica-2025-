import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import Dashboard from './components/Dashboard/Dashboard';
import ScanList from './components/Scans/ScanList';
import VulnerabilityList from './components/Vulnerabilities/VulnerabilityList';
import Login from './components/Auth/Login';
import Layout from './components/Common/Layout';
import { AuthProvider, useAuth } from './components/Auth/AuthContext';
import './styles/global.css';

const queryClient = new QueryClient();

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router>
          <div className="App">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }>
                <Route index element={<Dashboard />} />
                <Route path="scans" element={<ScanList />} />
                <Route path="vulnerabilities" element={<VulnerabilityList />} />
              </Route>
            </Routes>
          </div>
        </Router>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
