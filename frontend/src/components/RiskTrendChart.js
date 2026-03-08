import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart
} from 'recharts';
import { format } from 'date-fns';

const RiskTrendChart = ({ data }) => {
  const formatDate = (timestamp) => {
    return format(new Date(timestamp), 'MM/dd HH:mm');
  };

  const getRiskColor = (score) => {
    if (score < 30) return '#00ff9d';
    if (score < 60) return '#ffd700';
    return '#ff4d4d';
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const score = payload[0].value;
      return (
        <div className="custom-tooltip">
          <p className="tooltip-date">{formatDate(label)}</p>
          <p className="tooltip-score" style={{ color: getRiskColor(score) }}>
            Risk Score: {score}
          </p>
          <p className="tooltip-level">
            Level: {score < 30 ? 'LOW' : score < 60 ? 'MEDIUM' : 'HIGH'}
          </p>
        </div>
      );
    }
    return null;
  };

  // Transform data for chart
  const chartData = data.map(item => ({
    timestamp: item.date,
    score: item.risk_score
  }));

  return (
    <div className="risk-trend-chart">
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff4d4d" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#00ff9d" stopOpacity={0.2}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={formatDate}
              stroke="#666"
              tick={{ fill: '#999' }}
            />
            <YAxis 
              domain={[0, 100]} 
              stroke="#666"
              tick={{ fill: '#999' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area 
              type="monotone" 
              dataKey="score" 
              stroke="#8884d8" 
              fillOpacity={1}
              fill="url(#colorScore)"
            />
          </AreaChart>
        </ResponsiveContainer>
      ) : (
        <div className="no-data">No historical data available</div>
      )}

      <div className="chart-legend">
        <div className="legend-item">
          <span className="legend-color low-risk"></span>
          <span>Low Risk (0-30)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color medium-risk"></span>
          <span>Medium Risk (31-60)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color high-risk"></span>
          <span>High Risk (61-100)</span>
        </div>
      </div>
    </div>
  );
};

export default RiskTrendChart;