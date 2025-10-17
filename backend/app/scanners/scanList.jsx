import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { Bar } from 'react-chartjs-2';
import { apiClient } from '../../services/apiClient';
import NewScanModal from './NewScanModal';
import './ScanList.css';

const ScanList = () => {
  const [selectedScan, setSelectedScan] = useState(null);
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const queryClient = useQueryClient();

  const { data: scans, isLoading } = useQuery('scans', () => apiClient.getScans());

  const deleteScanMutation = useMutation(
    (scanId) => apiClient.deleteScan(scanId),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('scans');
      }
    }
  );

  const scanResultsData = selectedScan ? {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        label: 'Уязвимости',
        data: [
          selectedScan.vulnerabilities?.critical || 0,
          selectedScan.vulnerabilities?.high || 0,
          selectedScan.vulnerabilities?.medium || 0,
          selectedScan.vulnerabilities?.low || 0
        ],
        backgroundColor: ['#FF3333', '#FF9933', '#FFCC00', '#33CC33']
      }
    ]
  } : null;

  const getStatusBadge = (status) => {
    const statusConfig = {
      completed: { class: 'success', text: 'Завершено' },
      in_progress: { class: 'warning', text: 'В процессе' },
      failed: { class: 'error', text: 'Ошибка' },
      queued: { class: 'info', text: 'В очереди' }
    };
    return statusConfig[status] || statusConfig.queued;
  };

  if (isLoading) {
    return <div className="loading">Загрузка сканирований...</div>;
  }

  return (
    <div className="scan-list">
      <div className="scan-header">
        <h1>Управление сканированиями</h1>
        <button 
          className="btn btn-primary"
          onClick={() => setShowNewScanModal(true)}
        >
          🆕 Новое сканирование
        </button>
      </div>

      <div className="scans-container">
        <div className="scans-table-container">
          <table className="scans-table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Цель</th>
                <th>Тип</th>
                <th>Статус</th>
                <th>Время начала</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {scans?.map(scan => (
                <tr 
                  key={scan.id} 
                  className={selectedScan?.id === scan.id ? 'selected' : ''}
                  onClick={() => setSelectedScan(scan)}
                >
                  <td>{scan.name}</td>
                  <td className="target-cell">{scan.target}</td>
                  <td>
                    <span className="scan-type">{scan.type}</span>
                  </td>
                  <td>
                    <span className={`status-badge ${getStatusBadge(scan.status).class}`}>
                      {scan.status === 'in_progress' && scan.progress !== undefined 
                        ? `${getStatusBadge(scan.status).text} (${scan.progress}%)`
                        : getStatusBadge(scan.status).text
                      }
                    </span>
                  </td>
                  <td>{new Date(scan.start_time).toLocaleString()}</td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        className="btn btn-sm btn-info"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedScan(scan);
                        }}
                      >
                        Подробнее
                      </button>
                      {scan.status === 'in_progress' && (
                        <button 
                          className="btn btn-sm btn-warning"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Остановить
                        </button>
                      )}
                      <button 
                        className="btn btn-sm btn-danger"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm('Удалить сканирование?')) {
                            deleteScanMutation.mutate(scan.id);
                          }
                        }}
                      >
                        Удалить
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selectedScan && (
          <div className="scan-details">
            <h3>Детали сканирования</h3>
            <div className="scan-info">
              <div className="info-item">
                <label>Название:</label>
                <span>{selectedScan.name}</span>
              </div>
              <div className="info-item">
                <label>Цель:</label>
                <span>{selectedScan.target}</span>
              </div>
              <div className="info-item">
                <label>Тип:</label>
                <span>{selectedScan.type}</span>
              </div>
              <div className="info-item">
                <label>Статус:</label>
                <span className={`status-text ${getStatusBadge(selectedScan.status).class}`}>
                  {getStatusBadge(selectedScan.status).text}
                </span>
              </div>
            </div>

            {selectedScan.vulnerabilities && (
              <>
                <div className="results-chart">
                  <h4>Результаты сканирования</h4>
                  <Bar 
                    data={scanResultsData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          display: false
                        }
                      }
                    }}
                  />
                </div>
                
                <div className="vuln-stats">
                  <h4>Статистика уязвимостей</h4>
                  <div className="stats-grid">
                    <div className="vuln-stat">
                      <span className="stat-label">Всего уязвимостей:</span>
                      <span className="stat-value">
                        {Object.values(selectedScan.vulnerabilities).reduce((a, b) => a + b, 0)}
                      </span>
                    </div>
                    {Object.entries(selectedScan.vulnerabilities).map(([level, count]) => (
                      <div key={level} className={`vuln-stat severity-${level}`}>
                        <span className="stat-label">{level}:</span>
                        <span className="stat-value">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {showNewScanModal && (
        <NewScanModal onClose={() => setShowNewScanModal(false)} />
      )}
    </div>
  );
};

export default ScanList;
