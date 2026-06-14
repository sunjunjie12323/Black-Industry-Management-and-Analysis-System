import React, { Suspense, useEffect } from 'react';
import { Spin } from 'antd';
import { useSearchParams } from 'react-router-dom';
import {
  TeamOutlined, FileSearchOutlined, SettingOutlined,
} from '@ant-design/icons';

const DeploymentManage = React.lazy(() => import('./DeploymentManage'));
const AuditLog = React.lazy(() => import('./AuditLog'));
const Settings = React.lazy(() => import('./Settings'));

const TAB_MAP: Record<string, string> = {
  users: '0',
  logs: '1',
  settings: '2',
};

const TAB_MAP_REV: Record<string, string> = {
  '0': 'users',
  '1': 'logs',
  '2': 'settings',
};

const NAV_ITEMS = [
  { key: '0', label: '用户管理', icon: TeamOutlined, color: '#DC2626', desc: '用户账号与权限管理' },
  { key: '1', label: '系统日志', icon: FileSearchOutlined, color: '#F59E0B', desc: '操作审计与系统日志' },
  { key: '2', label: '系统设置', icon: SettingOutlined, color: '#4ADE80', desc: '平台配置与参数管理' },
];

const SystemManagement: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeKey = TAB_MAP[tabParam || 'users'] || '0';

  useEffect(() => {
    document.title = '系统管理 - 黑灰产情报分析平台';
  }, []);

  const activeItem = NAV_ITEMS.find(n => n.key === activeKey) || NAV_ITEMS[0];

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        background: '#141625',
        padding: '20px 32px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 36,
            height: 36,
            borderRadius: 10,
            background: 'rgba(220,38,38,0.10)',
            color: '#DC2626',
            fontSize: 18,
          }}>
            <SettingOutlined />
          </span>
          <div>
            <h1 style={{
              fontSize: 18,
              fontWeight: 700,
              fontFamily: 'var(--font-body)',
              color: '#E8E9ED',
              margin: 0,
              letterSpacing: '-0.01em',
            }}>
              系统管理
            </h1>
          </div>
        </div>
        <div style={{
          fontSize: 12,
          color: '#7C7F9A',
          fontFamily: 'var(--font-body)',
        }}>
          {activeItem.desc}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <nav style={{
          width: 220,
          background: 'rgba(20,22,37,0.50)',
          borderRight: '1px solid rgba(255,255,255,0.06)',
          padding: '16px 12px',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
          flexShrink: 0,
        }}>
          {NAV_ITEMS.map((item) => {
            const isActive = activeKey === item.key;
            const IconComp = item.icon;
            return (
              <button
                key={item.key}
                onClick={() => {
                  const tabName = TAB_MAP_REV[item.key];
                  setSearchParams(tabName ? { tab: tabName } : {});
                }}
                aria-label={item.label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '10px 12px',
                  borderRadius: 12,
                  border: 'none',
                  background: isActive ? `${item.color}15` : 'transparent',
                  cursor: 'pointer',
                  textAlign: 'left',
                  width: '100%',
                  transition: 'all 0.15s ease',
                  position: 'relative',
                  boxShadow: isActive ? '0 4px 16px rgba(0,0,0,0.25)' : 'none',
                }}
                onMouseEnter={(e) => {
                  if (!isActive) e.currentTarget.style.background = 'rgba(28,31,53,0.5)';
                }}
                onMouseLeave={(e) => {
                  if (!isActive) e.currentTarget.style.background = 'transparent';
                }}
              >
                {isActive && (
                  <span style={{
                    position: 'absolute',
                    left: 0,
                    top: 8,
                    bottom: 8,
                    width: 3,
                    borderRadius: 2,
                    background: item.color,
                  }} />
                )}
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: isActive ? `${item.color}12` : 'rgba(255,255,255,0.04)',
                  color: isActive ? item.color : '#7C7F9A',
                  fontSize: 15,
                  transition: 'all 0.15s ease',
                }}>
                  <IconComp />
                </span>
                <span style={{
                  fontFamily: 'var(--font-body)',
                  fontWeight: isActive ? 600 : 400,
                  fontSize: 13,
                  color: isActive ? '#E8E9ED' : '#7C7F9A',
                  transition: 'color 0.15s ease',
                }}>
                  {item.label}
                </span>
              </button>
            );
          })}
        </nav>

        <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          <Suspense fallback={
            <div style={{ padding: 64, textAlign: 'center' }}>
              <Spin />
            </div>
          }>
            {activeKey === '0' && <DeploymentManage />}
            {activeKey === '1' && <AuditLog />}
            {activeKey === '2' && <Settings />}
          </Suspense>
        </div>
      </div>
    </div>
  );
};

export default SystemManagement;
