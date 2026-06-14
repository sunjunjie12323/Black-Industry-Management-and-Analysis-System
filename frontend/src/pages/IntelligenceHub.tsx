import React, { Suspense, useEffect } from 'react';
import { Spin } from 'antd';
import { useSearchParams } from 'react-router-dom';
import {
  SearchOutlined, BellOutlined, DatabaseOutlined, ApartmentOutlined,
} from '@ant-design/icons';

const Intelligence = React.lazy(() => import('./Intelligence'));
const AlertCenter = React.lazy(() => import('./AlertCenter'));
const Entities = React.lazy(() => import('./Entities'));
const Graph = React.lazy(() => import('./Graph'));

const TAB_MAP: Record<string, string> = {
  intel: '0',
  alerts: '1',
  entities: '2',
  graph: '3',
};

const TAB_MAP_REV: Record<string, string> = {
  '0': 'intel',
  '1': 'alerts',
  '2': 'entities',
  '3': 'graph',
};

const NAV_ITEMS = [
  { key: '0', label: '情报列表', icon: SearchOutlined, color: '#6C5CE7', desc: '多源情报采集与管理' },
  { key: '1', label: '告警中心', icon: BellOutlined, color: '#EF4444', desc: '实时威胁告警监控' },
  { key: '2', label: '实体档案', icon: DatabaseOutlined, color: '#0090FF', desc: '黑产实体提取与管理' },
  { key: '3', label: '关联图谱', icon: ApartmentOutlined, color: '#22C55E', desc: '实体关系深度挖掘' },
];

const IntelligenceHub: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeKey = TAB_MAP[tabParam || 'intel'] || '0';

  useEffect(() => {
    document.title = '情报中心 - 黑灰产情报分析平台';
  }, []);

  const activeItem = NAV_ITEMS.find(n => n.key === activeKey) || NAV_ITEMS[0];

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        background: 'rgba(20,22,37,0.80)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '0 32px',
        display: 'flex',
        alignItems: 'stretch',
        gap: 0,
        height: 56,
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
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '0 20px',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? `2.5px solid ${item.color}` : '2.5px solid transparent',
                cursor: 'pointer',
                fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif',
                fontSize: 14,
                fontWeight: isActive ? 600 : 400,
                color: isActive ? item.color : '#7C7F9A',
                transition: 'all 0.2s ease',
                position: 'relative',
                whiteSpace: 'nowrap',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = item.color;
                  e.currentTarget.style.background = `${item.color}06`;
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = '#7C7F9A';
                  e.currentTarget.style.background = 'none';
                }
              }}
            >
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 28,
                height: 28,
                borderRadius: 7,
                background: isActive ? `${item.color}12` : 'transparent',
                color: isActive ? item.color : '#7C7F9A',
                fontSize: 14,
                transition: 'all 0.2s ease',
              }}>
                <IconComp />
              </span>
              {item.label}
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <Suspense fallback={
          <div style={{ padding: 64, textAlign: 'center' }}>
            <Spin />
          </div>
        }>
          {activeKey === '0' && <Intelligence />}
          {activeKey === '1' && <AlertCenter />}
          {activeKey === '2' && <Entities />}
          {activeKey === '3' && <Graph />}
        </Suspense>
      </div>
    </div>
  );
};

export default IntelligenceHub;
