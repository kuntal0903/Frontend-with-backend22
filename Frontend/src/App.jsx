import { useState, useCallback, useEffect } from 'react';
import { getSavedTheme }  from './hooks/useTheme';
import { ToastProvider, useToast } from './context/ToastContext';

import Sidebar         from './components/Sidebar';
import Topbar          from './components/Topbar';
import Dashboard          from './pages/Dashboard';
import SettingsPage       from './pages/SettingsPage';
import DomainScanPage     from './pages/DomainScanPage';
import AssetsPage         from './pages/AssetsPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import ThreatsPage        from './pages/ThreatsPage';
import AlertsPage         from './pages/AlertsPage';
import PlaceholderPage    from './pages/PlaceholderPage';
import NotificationsPanel from './components/NotificationsPanel';

import VulnerabilityModal from './components/VulnerabilityModal';
import AssetModal         from './components/AssetModal';
import ThreatModal        from './components/ThreatModal';
import AlertModal        from './components/AlertModal';
import SystemStatusModal  from './components/SystemStatusModal';

import './styles/layout.css';
import './styles/components.css';
import './styles/dashboard.css';
import './styles/settings.css';
import './styles/notifications.css';
import './styles/domainScan.css';

function PageRouter({ activePage, onExport, onNavigate, onOpenModal }) {
  if (activePage === 'dashboard') {
    return <Dashboard onExport={onExport} onVulnClick={() => onNavigate('vulnerabilities')} onOpenModal={onOpenModal} />;
  }
  if (activePage === 'assets') {
    return <AssetsPage onOpenModal={onOpenModal} />;
  }
  if (activePage === 'vulnerabilities') {
    return <VulnerabilitiesPage onOpenModal={onOpenModal} />;
  }
  if (activePage === 'threats') {
    return <ThreatsPage onOpenModal={onOpenModal} />;
  }
  if (activePage === 'alerts') {
    return <AlertsPage onOpenModal={onOpenModal} />;
  }
  if (activePage === 'settings') {
    return <SettingsPage />;
  }
  if (activePage === 'domain-scan') {
    return <DomainScanPage onOpenModal={onOpenModal} />;
  }
  return <PlaceholderPage pageId={activePage} />;
}

function MainApp() {
  const { addToast } = useToast();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileOpen,       setMobileOpen]       = useState(false);
  const [notifOpen,        setNotifOpen]        = useState(false);
  const [activePage,       setActivePage]       = useState('dashboard');
  const [searchQuery,      setSearchQuery]      = useState('');

  const [modalState, setModalState] = useState({
    type: null,
    data: null,
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', getSavedTheme());
  }, []);

  const handleToggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => !prev);
  }, []);

  const handleToggleMobile = useCallback(() => {
    setMobileOpen((prev) => !prev);
  }, []);

  const handleCloseMobile = useCallback(() => {
    setMobileOpen(false);
  }, []);

  const handleOpenNotifications = useCallback(() => {
    setNotifOpen((prev) => !prev);
  }, []);

  const handleCloseNotifications = useCallback(() => {
    setNotifOpen(false);
  }, []);

  const handleNavigate = useCallback((pageId) => {
    setActivePage(pageId);
    setMobileOpen(false);
  }, []);

  const handleOpenModal = useCallback((type, data = null) => {
    setModalState({ type, data });
  }, []);

  const handleCloseModal = useCallback(() => {
    setModalState({ type: null, data: null });
  }, []);

  const handleExport = useCallback((format = 'JSON') => {
    const reportData = {
      title: 'ASM Attack Surface Audit Report',
      timestamp: new Date().toISOString(),
      format,
      summary: {
        totalAssets: 1428,
        criticalVulnerabilities: 23,
        activeThreats: 12,
        securityScore: 84,
      },
    };
    const jsonStr = JSON.stringify(reportData, null, 2);
    const blob    = new Blob([jsonStr], { type: 'application/json' });
    const url     = URL.createObjectURL(blob);
    const a       = document.createElement('a');
    a.href        = url;
    a.download    = `asm-surface-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addToast(`Security report exported successfully (${format})`, 'success');
  }, [addToast]);

  return (
    <div className={`app-container ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <Sidebar
        activePage={activePage}
        onNavigate={handleNavigate}
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleSidebar}
        mobileOpen={mobileOpen}
        onCloseMobile={handleCloseMobile}
      />
      <div
        className={`sidebar-overlay ${mobileOpen ? 'visible' : ''}`}
        onClick={handleCloseMobile}
        aria-hidden="true"
      />
      <div className="main-wrapper">
        <Topbar
          activePage={activePage}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onNavigate={handleNavigate}
          onToggleSidebar={handleToggleSidebar}
          onToggleMobile={handleToggleMobile}
          onOpenNotifications={handleOpenNotifications}
          onOpenStatusModal={() => handleOpenModal('status')}
        />
        <main className="main-content">
          <PageRouter
            activePage={activePage}
            onExport={handleExport}
            onNavigate={handleNavigate}
            onOpenModal={handleOpenModal}
          />
        </main>
      </div>
      <NotificationsPanel
        isOpen={notifOpen}
        onClose={handleCloseNotifications}
        onNavigate={handleNavigate}
        onOpenModal={handleOpenModal}
      />

      {modalState.type === 'vulnerability' && (
        <VulnerabilityModal
          vuln={modalState.data}
          onClose={handleCloseModal}
        />
      )}
      {modalState.type === 'asset' && (
        <AssetModal
          asset={modalState.data}
          onClose={handleCloseModal}
        />
      )}
      {modalState.type === 'threat' && (
        <ThreatModal
          threat={modalState.data}
          onClose={handleCloseModal}
        />
      )}
      {modalState.type === 'alert' && (
        <AlertModal
          alert={modalState.data}
          onClose={handleCloseModal}
        />
      )}
      {modalState.type === 'status' && (
        <SystemStatusModal
          onClose={handleCloseModal}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <MainApp />
    </ToastProvider>
  );
}
