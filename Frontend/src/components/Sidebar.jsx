import {
  LayoutDashboard, Globe, ShieldAlert, Radio, Bell, Settings, Search,
  ChevronLeft, ChevronRight, X, ShieldCheck, Activity, Lock, Cpu
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard',       label: 'Dashboard',         icon: LayoutDashboard, badge: null },
  { id: 'domain-scan',     label: 'Domain Recon',      icon: Search,          badge: 'Live' },
  { id: 'assets',          label: 'Asset Inventory',   icon: Globe,           badge: '1.4k' },
  { id: 'vulnerabilities', label: 'Vulnerabilities',   icon: ShieldAlert,     badge: '23' },
  { id: 'threats',         label: 'Threat Feed',       icon: Activity,        badge: null },
  { id: 'alerts',          label: 'Alert Rules',       icon: Bell,            badge: '4' },
  { id: 'settings',        label: 'Settings',          icon: Settings,        badge: null },
];

export default function Sidebar({
  activePage,
  onNavigate,
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}) {
  return (
    <>
      {mobileOpen && (
        <div
          className="sidebar-overlay"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar__header">
          <div className="sidebar__logo" onClick={() => onNavigate('dashboard')}>
            <div className="sidebar__logo-icon">
              <ShieldCheck size={22} />
            </div>
            {!collapsed && (
              <div className="sidebar__logo-text">
                ASM <span>SHIELD 3.0</span>
              </div>
            )}
          </div>
          <button
            className="sidebar__collapse-btn"
            onClick={onToggleCollapse}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        <nav className="sidebar__nav">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                className={`sidebar__nav-item ${isActive ? 'active' : ''}`}
                onClick={() => onNavigate(item.id)}
                title={collapsed ? item.label : undefined}
              >
                <div className="sidebar__nav-icon">
                  <Icon size={18} />
                </div>
                {!collapsed && (
                  <>
                    <span className="sidebar__nav-label">{item.label}</span>
                    {item.badge && (
                      <span className={`sidebar__nav-badge ${item.badge === 'Live' ? 'live' : ''}`}>
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </button>
            );
          })}
        </nav>

        {!collapsed && (
          <div className="sidebar__footer">
            <div className="sidebar__status">
              <span className="status-dot live" />
              <span>SOC Engine Active</span>
            </div>
          </div>
        )}
      </aside>
    </>
  );
}
