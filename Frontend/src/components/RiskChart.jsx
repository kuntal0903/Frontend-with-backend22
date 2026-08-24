import { useState } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { useToast } from '../context/ToastContext';
import { ShieldAlert, AlertTriangle, Info } from 'lucide-react';

const CHART_TIMEFRAMES = {
  '7D': [
    { day: '17 Aug', critical: 8, high: 14, medium: 22 },
    { day: '18 Aug', critical: 7, high: 13, medium: 21 },
    { day: '19 Aug', critical: 9, high: 15, medium: 20 },
    { day: '20 Aug', critical: 6, high: 12, medium: 18 },
    { day: '21 Aug', critical: 5, high: 11, medium: 17 },
    { day: '22 Aug', critical: 4, high: 10, medium: 16 },
    { day: '23 Aug', critical: 4, high: 9,  medium: 15 },
  ],
  '30D': [
    { day: '27 Jul', critical: 16, high: 25, medium: 38 },
    { day: '03 Aug', critical: 12, high: 20, medium: 31 },
    { day: '10 Aug', critical: 9,  high: 15, medium: 24 },
    { day: '17 Aug', critical: 6,  high: 11, medium: 18 },
    { day: '23 Aug', critical: 4,  high: 9,  medium: 15 },
  ],
  '90D': [
    { day: 'Jun 2026', critical: 22, high: 32, medium: 48 },
    { day: 'Jul 2026', critical: 14, high: 22, medium: 32 },
    { day: 'Aug 2026', critical: 4,  high: 9,  medium: 15 },
  ]
};

export default function RiskChart() {
  const { addToast } = useToast();
  const [timeframe, setTimeframe] = useState('7D');
  const [visibleSeries, setVisibleSeries] = useState({
    critical: true,
    high: true,
    medium: true,
  });

  const handleTimeframeChange = (tf) => {
    setTimeframe(tf);
    addToast(`Updated Risk Velocity Chart view (${tf})`, 'info');
  };

  const toggleSeries = (key, label) => {
    setVisibleSeries(prev => {
      const next = { ...prev, [key]: !prev[key] };
      addToast(`${!prev[key] ? 'Showing' : 'Hiding'} ${label} risk trend line`, 'info');
      return next;
    });
  };

  const currentData = CHART_TIMEFRAMES[timeframe];
  const latestData = currentData[currentData.length - 1];

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="dash-card__header" style={{ marginBottom: 4, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h3 className="dash-card__title">Exposure Velocity & Vulnerability Breakdown</h3>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            Real-time severity distribution separated by Critical, High, and Medium threat vectors.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {['7D', '30D', '90D'].map((tf) => (
            <button
              key={tf}
              onClick={() => handleTimeframeChange(tf)}
              className={`port-tag ${timeframe === tf ? 'risk' : ''}`}
              style={{ cursor: 'pointer', padding: '4px 12px', fontSize: 11, fontWeight: 700 }}
            >
              {tf}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        <div
          onClick={() => toggleSeries('critical', 'Critical')}
          style={{
            background: visibleSeries.critical ? 'rgba(255, 8, 68, 0.12)' : 'var(--bg-surface)',
            border: visibleSeries.critical ? '1px solid rgba(255, 8, 68, 0.4)' : '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 14px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
            boxShadow: visibleSeries.critical ? '0 0 15px rgba(255, 8, 68, 0.2)' : 'none',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={16} color="var(--critical)" />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--critical)' }}>CRITICAL</span>
          </div>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 18, fontWeight: 800, color: 'var(--critical)' }}>
            {latestData.critical}
          </span>
        </div>

        <div
          onClick={() => toggleSeries('high', 'High')}
          style={{
            background: visibleSeries.high ? 'rgba(249, 115, 22, 0.12)' : 'var(--bg-surface)',
            border: visibleSeries.high ? '1px solid rgba(249, 115, 22, 0.4)' : '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 14px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
            boxShadow: visibleSeries.high ? '0 0 15px rgba(249, 115, 22, 0.2)' : 'none',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={16} color="var(--high)" />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--high)' }}>HIGH</span>
          </div>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 18, fontWeight: 800, color: 'var(--high)' }}>
            {latestData.high}
          </span>
        </div>

        <div
          onClick={() => toggleSeries('medium', 'Medium')}
          style={{
            background: visibleSeries.medium ? 'rgba(234, 179, 8, 0.12)' : 'var(--bg-surface)',
            border: visibleSeries.medium ? '1px solid rgba(234, 179, 8, 0.4)' : '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 14px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
            boxShadow: visibleSeries.medium ? '0 0 15px rgba(234, 179, 8, 0.2)' : 'none',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Info size={16} color="var(--medium)" />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--medium)' }}>MEDIUM</span>
          </div>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 18, fontWeight: 800, color: 'var(--medium)' }}>
            {latestData.medium}
          </span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 240, marginTop: 8 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={currentData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="criticalGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff0844" stopOpacity={0.5} />
                <stop offset="95%" stopColor="#ff0844" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="highGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f97316" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#f97316" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="mediumGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#eab308" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="day" stroke="var(--text-muted)" fontSize={12} tickLine={false} />
            <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} domain={[0, 'auto']} />
            <Tooltip
              contentStyle={{
                background: 'var(--bg-surface)',
                borderColor: 'var(--border-hover)',
                borderRadius: 12,
                color: 'var(--text-primary)',
                boxShadow: 'var(--glow-blue)',
                padding: '12px 16px'
              }}
            />
            <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12, fontWeight: 600 }} />

            {visibleSeries.critical && (
              <Area
                type="monotone"
                dataKey="critical"
                name="Critical Risk"
                stroke="#ff0844"
                strokeWidth={3}
                fillOpacity={1}
                fill="url(#criticalGlow)"
              />
            )}
            {visibleSeries.high && (
              <Area
                type="monotone"
                dataKey="high"
                name="High Risk"
                stroke="#f97316"
                strokeWidth={3}
                fillOpacity={1}
                fill="url(#highGlow)"
              />
            )}
            {visibleSeries.medium && (
              <Area
                type="monotone"
                dataKey="medium"
                name="Medium Risk"
                stroke="#eab308"
                strokeWidth={3}
                fillOpacity={1}
                fill="url(#mediumGlow)"
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
