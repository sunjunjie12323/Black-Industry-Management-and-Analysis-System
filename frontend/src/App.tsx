import React, { useEffect, useState, useRef, useCallback, useMemo, Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ConfigProvider, App as AntApp, Layout, Dropdown, Input, Spin, Modal, List, Empty, Drawer, theme } from 'antd';
import type { InputRef } from 'antd';
import {
  SearchOutlined,
  LogoutOutlined, SettingOutlined, SafetyOutlined, UserOutlined,
  MenuFoldOutlined, MenuUnfoldOutlined,
  DashboardOutlined, ExperimentOutlined, MessageOutlined, AppstoreOutlined,
  CheckCircleOutlined, ApartmentOutlined, AimOutlined, AlertOutlined, MergeCellsOutlined,
} from '@ant-design/icons';
import zhCN from 'antd/locale/zh_CN';
import Login from './pages/Login';
import Register from './pages/Register';
import ErrorBoundary from './components/ErrorBoundary';
import NotFound from './pages/NotFound';
import { tokenStorage } from './utils/tokenStorage';
import { registerMessageApi, intelligenceApi, api } from './services/api';
import { DashboardSkeleton } from './components/PageSkeleton';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const IntelligenceHub = lazy(() => import('./pages/IntelligenceHub'));
const DeepAnalysis = lazy(() => import('./pages/DeepAnalysis'));
const ModelWorkshop = lazy(() => import('./pages/ModelWorkshop'));
const AIApplications = lazy(() => import('./pages/AIApplications'));
const SystemManagement = lazy(() => import('./pages/SystemManagement'));
const IntelligenceQuality = lazy(() => import('./pages/IntelligenceQuality'));
const EventCorrelation = lazy(() => import('./pages/EventCorrelation'));
const ThreatBehavior = lazy(() => import('./pages/ThreatBehavior'));
const RiskScoring = lazy(() => import('./pages/RiskScoring'));
const IntelligenceFusion = lazy(() => import('./pages/IntelligenceFusion'));

const { Sider, Content } = Layout;

const getToken = (): string | null => {
  const token = tokenStorage.getToken();
  if (!token) return null;
  if (tokenStorage.isTokenExpired()) { tokenStorage.clear(); return null; }
  return token;
};

const PAGE_MAP: Record<string, string> = {
  '/': '态势总览',
  '/intelligence': '情报中心',
  '/analysis': '深度分析',
  '/model-workshop': '黑话分析',
  '/ai-apps': 'AI应用',
  '/system': '系统管理',
  '/intelligence-quality': '情报质量',
  '/event-correlation': '事件关联',
  '/threat-behavior': '威胁画像',
  '/risk-scoring': '风险评分',
  '/intelligence-fusion': '情报融合',
};

const MENU_GROUPS = [
  {
    title: '核心',
    items: [
      { key: '/', label: '态势总览', icon: <DashboardOutlined /> },
      { key: '/intelligence', label: '情报中心', icon: <SearchOutlined /> },
      { key: '/analysis', label: '深度分析', icon: <ExperimentOutlined /> },
    ],
  },
  {
    title: '分析引擎',
    items: [
      { key: '/intelligence-quality', label: '情报质量', icon: <CheckCircleOutlined /> },
      { key: '/event-correlation', label: '事件关联', icon: <ApartmentOutlined /> },
      { key: '/threat-behavior', label: '威胁画像', icon: <AimOutlined /> },
      { key: '/risk-scoring', label: '风险评分', icon: <AlertOutlined /> },
      { key: '/intelligence-fusion', label: '情报融合', icon: <MergeCellsOutlined /> },
    ],
  },
  {
    title: '工具',
    items: [
      { key: '/model-workshop', label: '黑话分析', icon: <MessageOutlined /> },
      { key: '/ai-apps', label: 'AI应用', icon: <AppstoreOutlined /> },
    ],
  },
  {
    title: '管理',
    items: [
      { key: '/system', label: '系统管理', icon: <SettingOutlined /> },
    ],
  },
];

const roleMap: Record<string, string> = {
  admin: 'Admin',
  analyst: 'Analyst',
  viewer: 'Viewer',
};

const TYPE_LABEL: Record<string, string> = { intelligence: '情报', entity: '实体', alert: '告警' };
const TYPE_COLOR: Record<string, string> = { intelligence: '#6C5CE7', entity: '#6C5CE7', alert: '#FF4757' };

const PageFallback = () => (
  <div style={{ padding: 32 }}>
    <DashboardSkeleton />
  </div>
);

interface SearchResultItem {
  id: string;
  title: string;
  description: string;
  type: 'intelligence' | 'entity' | 'alert';
  route: string;
}

const GlobalSearchModal: React.FC<{
  open: boolean;
  onClose: () => void;
}> = ({ open, onClose }) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<InputRef>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => { mountedRef.current = false; };
  }, []);

  const doSearch = useCallback(async (q: string) => {
    if (!q.trim()) { setResults([]); return; }
    setLoading(true);
    const items: SearchResultItem[] = [];
    const [intelRes, alertRes] = await Promise.allSettled([
      intelligenceApi.list({ search: q, limit: 5 }),
      api.alerts.getActive(),
    ]);
    if (intelRes.status === 'fulfilled') {
      for (const item of intelRes.value.items) {
        items.push({
          id: item.id,
          title: item.content?.slice(0, 60) || '—',
          description: `${item.source || '未知来源'} · ${item.threat_level || '未知等级'}`,
          type: 'intelligence',
          route: '/intelligence?tab=intel',
        });
      }
    }
    if (alertRes.status === 'fulfilled') {
      const alerts = (alertRes.value as { alerts?: Array<{ id?: string; message?: string; severity?: string }> }).alerts || [];
      for (const a of alerts.slice(0, 5)) {
        items.push({
          id: a.id || '',
          title: a.message?.slice(0, 60) || '—',
          description: `告警 · ${a.severity || '未知'}`,
          type: 'alert',
          route: '/intelligence?tab=alerts',
        });
      }
    }
    if (mountedRef.current) {
      setResults(items);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setQuery('');
      setResults([]);
      const timer = setTimeout(() => inputRef.current?.focus(), 100);
      return () => clearTimeout(timer);
    }
  }, [open]);

  const handleSelect = (item: SearchResultItem) => {
    const [path, search] = item.route.split('?');
    navigate({ pathname: path, search: search ? `?${search}` : undefined });
    onClose();
  };

  return (
    <Modal
      open={open}
      onCancel={onClose}
      footer={null}
      closable={false}
      width={560}
      style={{ top: 120 }}
      styles={{ body: { padding: 0, borderRadius: 12, overflow: 'hidden', background: 'var(--bg-1)' } }}
    >
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
        <Input
          ref={inputRef}
          placeholder="搜索情报、告警、实体..."
          prefix={<SearchOutlined style={{ color: '#00D4FF', fontSize: 14 }} />}
          suffix={<span style={{ fontSize: 10, color: 'var(--text-2)', fontFamily: 'var(--font-mono)', letterSpacing: '0.04em' }}>ESC</span>}
          value={query}
          onChange={e => { setQuery(e.target.value); doSearch(e.target.value); }}
          onPressEnter={() => { if (results.length > 0) handleSelect(results[0]); }}
          style={{ fontSize: 13, borderRadius: 8, fontFamily: 'var(--font-body)', background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-0)' }}
          autoFocus
        />
      </div>
      <div style={{ maxHeight: 360, overflow: 'auto', padding: query.trim() ? '8px 12px' : 0 }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 32 }}><Spin /></div>
        ) : query.trim() && results.length === 0 ? (
          <Empty description="未找到相关结果" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '24px 0' }} />
        ) : (
          <List
            split
            dataSource={results}
            renderItem={(item) => (
              <List.Item
                style={{ cursor: 'pointer', padding: '10px 12px', borderRadius: 8, transition: 'background 0.15s' }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(108,92,231,0.08)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                onClick={() => handleSelect(item)}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', color: TYPE_COLOR[item.type], fontFamily: 'var(--font-number)', fontWeight: 700, background: `${TYPE_COLOR[item.type]}18`, padding: '1px 6px', borderRadius: 4, lineHeight: '16px' }}>{TYPE_LABEL[item.type]}</span>
                    <span style={{ fontSize: 13, color: 'var(--text-0)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-body)' }}>{item.title}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-2)', paddingLeft: 56, fontFamily: 'var(--font-number)', letterSpacing: '0.02em' }}>{item.description}</div>
                </div>
              </List.Item>
            )}
          />
        )}
      </div>
      {!query.trim() && (
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border)', textAlign: 'center', fontSize: 11, color: 'var(--text-2)', fontFamily: 'var(--font-number)', letterSpacing: '0.04em' }}>
          输入关键词搜索情报、告警等内容
        </div>
      )}
    </Modal>
  );
};

const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const user = tokenStorage.getUser<{ username: string; role: string }>();
  const [collapsed, setCollapsed] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [alertCount, setAlertCount] = useState(0);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);
  const siderW = isMobile ? 0 : (collapsed ? 64 : 260);

  const handleLogout = useCallback(() => { tokenStorage.clear(); navigate('/login', { replace: true }); }, [navigate]);

  const userMenuItems = useMemo(() => [
    { key: 'settings', icon: <SettingOutlined />, label: '系统设置', onClick: () => navigate('/system?tab=settings') },
    { type: 'divider' as const, key: 'ud' },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true, onClick: handleLogout },
  ], [navigate, handleLogout]);

  const currentPageLabel = PAGE_MAP[location.pathname] || '黑灰产情报分析';

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    let mounted = true;
    const fetchAlertCount = async () => {
      try {
        const res = await api.alerts.getActive();
        if (mounted) setAlertCount((res as { total?: number }).total || 0);
      } catch { /* ignore */ }
    };
    fetchAlertCount();
    const iv = setInterval(fetchAlertCount, 60000);
    return () => { mounted = false; clearInterval(iv); };
  }, []);

  useEffect(() => {
    document.title = `${currentPageLabel} - 黑灰产情报分析平台`;
  }, [currentPageLabel]);

  useEffect(() => {
    if (!contentRef.current) return;
    contentRef.current.style.opacity = '0';
    contentRef.current.style.transform = 'translateY(4px)';
    const rafId = requestAnimationFrame(() => {
      if (!contentRef.current) return;
      contentRef.current.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
      contentRef.current.style.opacity = '1';
      contentRef.current.style.transform = 'translateY(0)';
    });
    return () => cancelAnimationFrame(rafId);
  }, [location.pathname, location.search]);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
      if (e.key === 'Escape' && searchOpen) {
        setSearchOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchOpen]);

  const userInitials = (user?.username || 'U').slice(0, 2).toUpperCase();

  const renderBrandArea = (showFull: boolean) => (
    <div style={{
      padding: showFull ? '0 20px 24px' : '0 0 20px',
      display: 'flex',
      flexDirection: showFull ? 'row' : 'column',
      alignItems: 'center',
      justifyContent: showFull ? 'flex-start' : 'center',
      gap: showFull ? 12 : 0,
      transition: 'padding 0.25s ease, gap 0.25s ease',
    }}>
      <div style={{
        padding: 1.5,
        borderRadius: showFull ? 13.5 : 10.5,
        background: 'linear-gradient(135deg, #6C5CE7, #A78BFA, #6C5CE7)',
        flexShrink: 0,
        transition: 'border-radius 0.25s ease',
      }}>
        <div style={{
          width: showFull ? 36 : 30,
          height: showFull ? 36 : 30,
          borderRadius: showFull ? 12 : 10,
          background: 'linear-gradient(135deg, #6C5CE7, #8B7CF7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 4px 12px rgba(108,92,231,0.3), 0 0 20px rgba(108,92,231,0.15)',
          transition: 'width 0.25s ease, height 0.25s ease, border-radius 0.25s ease',
        }}>
          <SafetyOutlined style={{ fontSize: showFull ? 18 : 15, color: '#FFFFFF' }} />
        </div>
      </div>
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        overflow: 'hidden',
        whiteSpace: 'nowrap',
        opacity: showFull ? 1 : 0,
        maxWidth: showFull ? 200 : 0,
        transition: 'opacity 0.2s ease, max-width 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
      }}>
        <div style={{
            fontFamily: '"Syne", sans-serif',
            fontSize: 22,
            fontWeight: 700,
            letterSpacing: '-0.04em',
            color: 'var(--text-0)',
            lineHeight: 1,
          }}>
            NEXUS
          </div>
        <div style={{
          fontFamily: 'var(--font-body)',
          fontSize: 11,
          color: 'var(--text-2)',
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          lineHeight: 1,
        }}>
          威胁情报分析
        </div>
      </div>
    </div>
  );

  const renderMenuItems = (isDrawer: boolean = false) => {
    const showFull = !collapsed || isDrawer;
    return MENU_GROUPS.map((group, groupIdx) => (
      <React.Fragment key={group.title}>
        {showFull && (
          <div style={{
            fontSize: 11,
            fontWeight: 600,
            color: 'var(--text-2)',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            padding: groupIdx === 0 ? '8px 20px 6px' : '16px 20px 6px',
            fontFamily: 'var(--font-body)',
          }}>
            {group.title}
          </div>
        )}
        {group.items.map((item) => {
          const isActive = location.pathname === item.key;
          return (
            <div
              key={item.key}
              role="button"
              tabIndex={0}
              aria-label={item.label}
              aria-current={isActive ? 'page' : undefined}
              onClick={() => { navigate(item.key); if (isDrawer) setMobileMenuOpen(false); }}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(item.key); if (isDrawer) setMobileMenuOpen(false); } }}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: showFull ? 'flex-start' : 'center',
                height: 40,
                padding: showFull ? '0 12px' : '0',
                margin: showFull ? '2px 12px' : '2px 8px',
                borderRadius: 10,
                cursor: 'pointer',
                position: 'relative',
                transition: 'color 0.15s ease, background 0.15s ease',
                background: isActive ? 'var(--accent-dim)' : 'transparent',
                color: isActive ? 'var(--text-0)' : 'var(--text-2)',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                fontWeight: isActive ? 600 : 500,
                borderLeft: showFull ? (isActive ? '3px solid' : '3px solid transparent') : 'none',
                borderImage: isActive ? 'linear-gradient(to bottom, #6C5CE7, #A78BFA) 1' : undefined,
                whiteSpace: 'nowrap',
                gap: showFull ? 10 : 0,
                boxShadow: isActive ? 'inset 0 0 12px rgba(108,92,231,0.08)' : 'none',
                outline: 'none',
              }}
              onMouseEnter={e => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-0)';
                  e.currentTarget.style.background = 'linear-gradient(90deg, rgba(108,92,231,0.06), transparent)';
                }
              }}
              onMouseLeave={e => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-2)';
                  e.currentTarget.style.background = 'transparent';
                }
              }}
            >
              <span style={{
                fontSize: 16,
                color: isActive ? 'var(--accent)' : 'var(--text-2)',
                flexShrink: 0,
                transition: 'color 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                filter: isActive ? 'drop-shadow(0 0 4px rgba(108,92,231,0.4))' : 'none',
              }}>
                {item.icon}
              </span>
              <span style={{
                overflow: 'hidden',
                whiteSpace: 'nowrap',
                opacity: showFull ? 1 : 0,
                maxWidth: showFull ? 160 : 0,
                transition: 'opacity 0.2s ease, max-width 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
              }}>
                {item.label}
              </span>
            </div>
          );
        })}
      </React.Fragment>
    ));
  };

  const renderUserArea = (showFull: boolean) => (
    <div style={{
      padding: showFull ? '0' : '8px 0',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    }}>
      <div style={{
        width: showFull ? 'calc(100% - 40px)' : '60%',
        height: 1,
        background: 'var(--border)',
        margin: showFull ? '0 20px 12px' : '0 auto 8px',
      }} />
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: showFull ? 'flex-start' : 'center',
        gap: showFull ? 10 : 0,
        padding: showFull ? '0 20px' : '0',
        width: '100%',
      }}>
        <Dropdown menu={{ items: userMenuItems }} trigger={['click']}>
          <div style={{
            padding: 1.5,
            borderRadius: 9,
            background: 'linear-gradient(135deg, #6C5CE7, #A78BFA)',
            flexShrink: 0,
            cursor: 'pointer',
            transition: 'background 0.15s ease',
          }}
          aria-label="用户菜单"
          onMouseEnter={e => { e.currentTarget.style.background = 'linear-gradient(135deg, #7C6CF7, #B79BFA)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'linear-gradient(135deg, #6C5CE7, #A78BFA)'; }}
          >
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 7.5,
              background: 'var(--accent-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <UserOutlined style={{ fontSize: 14, color: 'var(--accent)' }} />
            </div>
          </div>
        </Dropdown>
        <div style={{
          flex: 1,
          minWidth: 0,
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          opacity: showFull ? 1 : 0,
          maxWidth: showFull ? 120 : 0,
          transition: 'opacity 0.2s ease, max-width 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
        }}>
          <span style={{
            fontSize: 13,
            fontWeight: 500,
            color: 'var(--text-0)',
            fontFamily: 'var(--font-body)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}>
            {user?.username || 'admin'}
          </span>
          <span style={{
            fontSize: 11,
            color: 'var(--text-2)',
            fontFamily: 'var(--font-body)',
          }}>
            {roleMap[user?.role || 'admin'] || 'Admin'}
          </span>
        </div>
        <div
          role="button"
          tabIndex={0}
          aria-label="退出登录"
          onClick={handleLogout}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleLogout(); } }}
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            color: 'var(--text-2)',
            transition: 'color 0.15s ease, background 0.15s ease, transform 0.15s ease',
            flexShrink: 0,
            opacity: showFull ? 1 : 0,
            maxWidth: showFull ? 32 : 0,
            overflow: 'hidden',
            outline: 'none',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = '#FF4757'; e.currentTarget.style.background = 'rgba(255,71,87,0.08)'; e.currentTarget.style.transform = 'scale(1.05)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-2)'; e.currentTarget.style.background = 'transparent'; e.currentTarget.style.transform = 'scale(1)'; }}
        >
          <LogoutOutlined style={{ fontSize: 14 }} />
        </div>
      </div>
      {!isMobile && (
        <div
          role="button"
          tabIndex={0}
          aria-label={collapsed ? '展开菜单' : '收起菜单'}
          onClick={() => setCollapsed(!collapsed)}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCollapsed(!collapsed); } }}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 32,
            height: 28,
            borderRadius: 6,
            cursor: 'pointer',
            color: 'var(--text-2)',
            marginTop: 8,
            transition: 'color 0.15s ease, background 0.15s ease',
            outline: 'none',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-0)'; e.currentTarget.style.background = 'rgba(108,92,231,0.06)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-2)'; e.currentTarget.style.background = 'transparent'; }}
        >
          {collapsed ? <MenuUnfoldOutlined style={{ fontSize: 13 }} /> : <MenuFoldOutlined style={{ fontSize: 13 }} />}
        </div>
      )}
    </div>
  );

  return (
    <Layout style={{ minHeight: '100vh', background: 'var(--bg-0)' }}>
      <Sider width={siderW} theme="dark" style={{
        background: '#0D0F1A',
        borderRight: '1px solid var(--border)',
        position: 'fixed',
        left: 0, top: 0, bottom: 0,
        zIndex: 100,
        overflow: 'hidden',
        transition: 'width 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
        display: isMobile ? 'none' : 'flex',
        flexDirection: 'column',
        padding: '20px 0',
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
          {renderBrandArea(!collapsed)}
          <div style={{
            height: 1,
            margin: collapsed ? '0 12px' : '0 20px',
            background: 'linear-gradient(90deg, #6C5CE7, #A78BFA, transparent)',
          }} />
          <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '8px 0', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderMenuItems()}
          </div>
          {renderUserArea(!collapsed)}
        </div>
        <div style={{
          position: 'absolute',
          bottom: -40,
          left: -40,
          width: 160,
          height: 160,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(108,92,231,0.08), transparent 70%)',
          pointerEvents: 'none',
        }} />
      </Sider>

      <Drawer
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        placement="left"
        width={260}
        styles={{ body: { padding: 0, background: '#0D0F1A' }, wrapper: {} }}
        title={null}
        closable={false}
      >
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '20px 0' }}>
          {renderBrandArea(true)}
          <div style={{
            height: 1,
            margin: '0 20px',
            background: 'linear-gradient(90deg, #6C5CE7, #A78BFA, transparent)',
          }} />
          <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '8px 0', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {renderMenuItems(true)}
          </div>
          {renderUserArea(true)}
        </div>
      </Drawer>

      <Layout style={{ flex: 1, marginLeft: siderW, background: 'var(--bg-0)', minHeight: '100vh', transition: 'margin-left 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)' }}>
        <div style={{
          padding: '0 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          background: 'rgba(11,13,23,0.85)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          height: 52,
          transition: 'background-color 0.3s ease',
          borderBottom: '1px solid rgba(108,92,231,0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {isMobile && (
              <MenuUnfoldOutlined
                style={{ fontSize: 14, cursor: 'pointer', color: 'var(--text-0)' }}
                onClick={() => setMobileMenuOpen(true)}
                aria-label="打开菜单"
              />
            )}
            <span style={{
              fontSize: 24,
              fontWeight: 700,
              fontStyle: 'normal',
              color: '#FFFFFF',
              fontFamily: 'var(--font-display)',
              letterSpacing: '-0.02em',
              transition: 'color 0.3s ease',
            }}>{currentPageLabel}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div
              role="button"
              tabIndex={0}
              aria-label="搜索"
              onClick={() => setSearchOpen(true)}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSearchOpen(true); } }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '5px 14px',
                borderRadius: 8,
                background: 'var(--bg-2)',
                border: '1px solid var(--border)',
                cursor: 'pointer',
                transition: 'border-color 0.15s ease, box-shadow 0.15s ease, background 0.15s ease',
                minWidth: 180,
                height: 32,
                outline: 'none',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(108,92,231,0.25)'; e.currentTarget.style.boxShadow = '0 0 0 2px rgba(108,92,231,0.08)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <SearchOutlined style={{ color: '#00D4FF', fontSize: 13 }} />
              <span style={{
                fontSize: 13,
                fontFamily: 'var(--font-body)',
                color: 'var(--text-2)',
                letterSpacing: '0.02em',
              }}>
                搜索... ⌘K
              </span>
            </div>
            <span
              role="button"
              tabIndex={0}
              aria-label={`告警: ${alertCount}`}
              onClick={() => navigate('/intelligence?tab=alerts')}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate('/intelligence?tab=alerts'); } }}
              style={{
                position: 'relative',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                transition: 'opacity 0.15s ease',
                outline: 'none',
              }}
              onMouseEnter={e => { e.currentTarget.style.opacity = '0.8'; }}
              onMouseLeave={e => { e.currentTarget.style.opacity = '1'; }}
            >
              {alertCount > 0 && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  minWidth: 18,
                  height: 18,
                  padding: '0 5px',
                  borderRadius: 9,
                  background: '#FF4757',
                  color: '#FFFFFF',
                  fontSize: 10,
                  fontWeight: 700,
                  fontFamily: 'var(--font-number)',
                  letterSpacing: '0.02em',
                  lineHeight: '18px',
                }}>
                  {alertCount > 99 ? '99+' : alertCount}
                </span>
              )}
            </span>
            <Dropdown menu={{ items: userMenuItems }} trigger={['click']}>
              <div style={{
                width: 36, height: 36,
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #6C5CE7, #00D4FF)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                transition: 'opacity 0.15s ease, box-shadow 0.15s ease',
                boxShadow: '0 2px 8px rgba(108,92,231,0.25)',
              }}
              aria-label="用户菜单"
              onMouseEnter={e => { e.currentTarget.style.opacity = '0.85'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(108,92,231,0.35)'; }}
              onMouseLeave={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(108,92,231,0.25)'; }}
              >
                <span style={{ fontSize: 13, fontWeight: 700, color: '#FFFFFF', fontFamily: 'var(--font-number)', letterSpacing: '0.04em' }}>{userInitials}</span>
              </div>
            </Dropdown>
          </div>
        </div>
        <div style={{
          height: 1,
          background: 'linear-gradient(90deg, rgba(108,92,231,0.3), rgba(0,212,255,0.15), transparent)',
        }} />
        <Content style={{ padding: '32px', overflow: 'auto', minHeight: 'calc(100vh - 53px)', background: 'var(--bg-0)' }}>
          <div ref={contentRef} key={`${location.pathname}-${location.search}`} className="fade-in-up">
            {children}
          </div>
        </Content>
      </Layout>

      <GlobalSearchModal open={searchOpen} onClose={() => setSearchOpen(false)} />
    </Layout>
  );
};

const AuthGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const token = getToken();
  if (!token) return <Navigate to="/login" replace />;
  return <AppLayout>{children}</AppLayout>;
};

const MessageRegistrar: React.FC = () => {
  const { message: msgApi } = AntApp.useApp();
  useEffect(() => {
    registerMessageApi(msgApi);
  }, [msgApi]);
  return null;
};

const App: React.FC = () => {
  useEffect(() => {
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      event.preventDefault();
    };
    window.addEventListener('unhandledrejection', handleUnhandledRejection);
    return () => window.removeEventListener('unhandledrejection', handleUnhandledRejection);
  }, []);

  return (
  <ConfigProvider locale={zhCN} theme={{
    algorithm: theme.darkAlgorithm,
    token: {
      colorPrimary: '#6C5CE7',
      colorInfo: '#6C5CE7',
      colorSuccess: '#00E676',
      colorWarning: '#FFB020',
      colorError: '#FF4757',
      borderRadius: 10,
      colorBgContainer: '#141625',
      colorBgElevated: '#1C1F35',
      colorText: '#E8E9ED',
      colorTextSecondary: '#7C7F9A',
      colorBorder: 'rgba(255,255,255,0.06)',
      colorBgBase: '#0B0D17',
      colorBgLayout: '#0B0D17',
      fontFamily: 'var(--font-body)',
      fontSize: 13,
      wireframe: false,
    },
    components: {
      Menu: { itemHeight: 34, darkItemBg: 'transparent' },
      Table: { cellPaddingBlock: 10 },
      Card: { borderRadiusLG: 14 },
      Modal: { borderRadiusLG: 14 },
      Tabs: { itemSelectedColor: '#6C5CE7', inkBarColor: '#6C5CE7' },
    },
  }}>
    <AntApp>
    <MessageRegistrar />
    <ErrorBoundary>
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<AuthGuard><Suspense fallback={<PageFallback />}><Dashboard /></Suspense></AuthGuard>} />
        <Route path="/intelligence" element={<AuthGuard><Suspense fallback={<PageFallback />}><IntelligenceHub /></Suspense></AuthGuard>} />
        <Route path="/analysis" element={<AuthGuard><Suspense fallback={<PageFallback />}><DeepAnalysis /></Suspense></AuthGuard>} />
        <Route path="/model-workshop" element={<AuthGuard><Suspense fallback={<PageFallback />}><ModelWorkshop /></Suspense></AuthGuard>} />
        <Route path="/ai-apps" element={<AuthGuard><Suspense fallback={<PageFallback />}><AIApplications /></Suspense></AuthGuard>} />
        <Route path="/system" element={<AuthGuard><Suspense fallback={<PageFallback />}><SystemManagement /></Suspense></AuthGuard>} />
        <Route path="/intelligence-quality" element={<AuthGuard><Suspense fallback={<PageFallback />}><IntelligenceQuality /></Suspense></AuthGuard>} />
        <Route path="/event-correlation" element={<AuthGuard><Suspense fallback={<PageFallback />}><EventCorrelation /></Suspense></AuthGuard>} />
        <Route path="/threat-behavior" element={<AuthGuard><Suspense fallback={<PageFallback />}><ThreatBehavior /></Suspense></AuthGuard>} />
        <Route path="/risk-scoring" element={<AuthGuard><Suspense fallback={<PageFallback />}><RiskScoring /></Suspense></AuthGuard>} />
        <Route path="/intelligence-fusion" element={<AuthGuard><Suspense fallback={<PageFallback />}><IntelligenceFusion /></Suspense></AuthGuard>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
    </ErrorBoundary>
    </AntApp>
  </ConfigProvider>
  );
};

export default App;
