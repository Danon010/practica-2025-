import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import { useQuery } from 'react-query';
import { apiClient } from '../../services/apiClient';
import './Dashboard.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

const Dashboard = () => {
  const { data: stats, isLoading } = useQuery('dashboardStats', 
    () => apiClient.getDashboardStats()
  );

  const vulnerabilityTypeData = {
    labels: ['SQL Injection', 'XSS', 'CSRF', 'Info Disclosure', 'Auth Bypass'],
    datasets: [
      {
        data: [12, 19, 3, 5, 2],
        backgroundColor: [
          '#FF6384',
          '#36A2EB',
          '#FFCE56',
          '#4BC0C0',
          '#9966FF'
        ],
        borderWidth: 2,
        borderColor: '#fff'
      }
    ]
  };

  const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        label: 'Уязвимости',
        data: [8, 12, 15, 25],
        backgroundColor: [
          '#FF3333',
          '#FF9933',
          '#FFCC00',
          '#33CC33'
        ],
        borderWidth: 1
      }
    ]
  };

  const scanTrendData = {
    labels: ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн'],
    datasets: [
      {
        label: 'Запущенные сканирования',
        data: [12, 19, 15, 25, 22, 30],
        borderColor: '#36A2EB',
        backgroundColor: 'rgba(54, 162, 235, 0.1)',
        tension: 0.4,
        fill: true
      },
      {
        label: 'Найденные уязвимости',
        data: [5, 12, 8, 18, 15, 25],
        borderColor: '#FF6384',
        backgroundColor: 'rgba(255, 99, 132, 0.1)',
        tension: 0.4,
        fill: true
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Статистика сканирований'
      }
    }
  };

  if (isLoading) {
    return <div className="loading">Загрузка данных...</div>;
  }

  return (
    <div className="dashboard">
      <h1>Панель управления сканированием уязвимостей</h1>
      
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🔍</div>
          <div className="stat-content">
            <h3>Всего сканирований</h3>
            <p className="stat-number">{stats?.total_scans || 156}</p>
            <span className="stat-delta">+12 за месяц</span>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">🔄</div>
          <div className="stat-content">
            <h3>Активные сканирования</h3>
            <p className="stat-number">{stats?.active_scans || 3}</p>
            <span className="stat-delta negative">-2</span>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-content">
            <h3>Найденные уязвимости</h3>
            <p className="stat-number">{stats?.total_vulnerabilities || 42}</p>
            <span className="stat-delta">+5</span>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">🔴</div>
          <div className="stat-content">
            <h3>Критические уязвимости</h3>
            <p className="stat-number critical">{stats?.critical_vulnerabilities || 8}</p>
            <span className="stat-delta negative">+2</span>
          </div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-container">
          <h3>Распределение по типам уязвимостей</h3>
          <div className="chart-wrapper">
            <Doughnut 
              data={vulnerabilityTypeData} 
              options={{
                ...chartOptions,
                plugins: {
                  ...chartOptions.plugins,
                  title: { display: true, text: 'Типы уязвимостей' }
                }
              }} 
            />
          </div>
        </div>
        
        <div className="chart-container">
          <h3>Уязвимости по критичности</h3>
          <div className="chart-wrapper">
            <Bar 
              data={severityData} 
              options={{
                ...chartOptions,
                plugins: {
                  ...chartOptions.plugins,
                  title: { display: true, text: 'Критичность уязвимостей' }
                }
              }} 
            />
          </div>
        </div>
        
        <div className="chart-container full-width">
          <h3>Тренды сканирований</h3>
          <div className="chart-wrapper">
            <Line 
              data={scanTrendData} 
              options={{
                ...chartOptions,
                plugins: {
                  ...chartOptions.plugins,
                  title: { display: true, text: 'Динамика сканирований' }
                }
              }} 
            />
          </div>
        </div>
      </div>

      <div className="recent-activity">
        <h3>Последняя активность</h3>
        <div className="activity-list">
          <div className="activity-item">
            <div className="activity-icon">🔍</div>
            <div className="activity-content">
              <p>Запущено сканирование сети</p>
              <span>2 минуты назад • 192.168.1.0/24</span>
            </div>
          </div>
          <div className="activity-item">
            <div className="activity-icon">⚠️</div>
            <div className="activity-content">
              <p>Обнаружена критическая уязвимость</p>
              <span>15 минут назад • SQL Injection</span>
            </div>
          </div>
          <div className="activity-item">
            <div className="activity-icon">✅</div>
            <div className="activity-content">
              <p>Завершено сканирование веб-приложения</p>
              <span>1 час назад • example.com</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
