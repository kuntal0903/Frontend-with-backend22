import { useState, useCallback, useEffect } from 'react';
import { useTheme } from '../hooks/useTheme';
import { useToast } from '../context/ToastContext';
import {
  User, Shield, Key, Plug, Calendar, Bell, Palette,
  Users, AlertTriangle, Check, Copy, RefreshCw, Plus,
  Trash2, Eye, EyeOff, Mail, MessageSquare, Link2, Globe,
  ChevronRight, LogOut, Download, Cpu, X, CheckCircle,
} from 'lucide-react';

import '../styles/settings.css';

const NAV_SECTIONS = [
  { group: 'ACCOUNT',  items: [
    { id: 'profile',      label: 'Profile',       icon: User },
    { id: 'security',     label: 'Security',      icon: Shield },
    { id: 'api-keys',     label: 'API Keys',      icon: Key },
  ]},
  { group: 'PLATFORM', items: [
    { id: 'integrations', label: 'Integrations',  icon: Plug },
    { id: 'scan',         label: 'Scan Schedule', icon: Calendar },
    { id: 'notifications',label: 'Notifications', icon: Bell },
  ]},
  { group: 'SYSTEM',   items: [
    { id: 'appearance',   label: 'Appearance',    icon: Palette },
    { id: 'team',         label: 'Team',          icon: Users },
    { id: 'danger',       label: 'Danger Zone',   icon: AlertTriangle },
  ]},
];

export default function SettingsPage() {
  const { addToast } = useToast();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('profile');

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Platform <span>Settings</span>
          </h1>
          <p className="page-header__subtitle">
            Configure system preferences, API credentials, third-party integrations, and team access.
          </p>
        </div>
      </div>

      <div className="settings-layout">
        <nav className="settings-nav">
          {NAV_SECTIONS.map((sec) => (
            <div key={sec.group}>
              <div className="settings-nav__group-label">{sec.group}</div>
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    className={`settings-nav__item ${isActive ? 'active' : ''}`}
                    onClick={() => setActiveTab(item.id)}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="settings-content">
          <div className="settings-section" style={{ padding: 24 }}>
            <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8, color: 'var(--neon-blue)' }}>
              ASM Shield 3.0 Enterprise Configuration
            </h3>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
              All configuration parameters are active in current workspace mode. Theme preference is currently set to: <strong style={{ color: 'var(--text-primary)', textTransform: 'uppercase' }}>{theme}</strong>.
            </p>
            <div style={{ display: 'flex', gap: 10 }}>
              {['dark', 'light', 'blue'].map((t) => (
                <button
                  key={t}
                  className={`btn ${theme === t ? 'btn--primary' : 'btn--outline'}`}
                  onClick={() => { setTheme(t); addToast(`Applied ${t.toUpperCase()} theme`, 'info'); }}
                  style={{ textTransform: 'uppercase', fontSize: 12 }}
                >
                  {t} Mode
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
