import React, { Suspense, useEffect } from 'react';
import { Spin } from 'antd';
import { useSearchParams } from 'react-router-dom';
import {
  CompassOutlined, ClockCircleOutlined, LineChartOutlined, FileTextOutlined,
} from '@ant-design/icons';

const IntelPipeline = React.lazy(() => import('./IntelPipeline'));
const DataAnalytics = React.lazy(() => import('./DataAnalytics'));
const Reports = React.lazy(() => import('./Reports'));

const TAB_MAP: Record<string, string> = {
  timeline: '0',
  behavior: '1',
  report: '2',
};

const TAB_MAP_REV: Record<string, string> = {
  '0': 'timeline',
  '1': 'behavior',
  '2': 'report',
};

const TAB_CONFIG = [
  { key: '0', label: '时间线', icon: ClockCircleOutlined, color: '#14B8A6' },
  { key: '1', label: '行为分析', icon: LineChartOutlined, color: '#14B8A6' },
  { key: '2', label: '报告生成', icon: FileTextOutlined, color: '#14B8A6' },
];

const DeepAnalysis: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeKey = TAB_MAP[tabParam || 'timeline'] || '0';

  useEffect(() => {
    document.title = '深度分析 - 黑灰产情报分析平台';
  }, []);

  const renderContent = () => {
    if (activeKey === '0') return <IntelPipeline />;
    if (activeKey === '1') return <DataAnalytics />;
    if (activeKey === '2') return <Reports />;
    return null;
  };

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        height: 64,
        background: '#141625',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 32px',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <CompassOutlined style={{ fontSize: 20, color: '#14B8A6' }} />
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
            <span style={{
              fontSize: 18,
              fontWeight: 700,
              color: '#E8E9ED',
              letterSpacing: '-0.01em',
            }}>
              深度分析
            </span>
            <span style={{
              fontSize: 12,
              color: '#7C7F9A',
              fontWeight: 400,
            }}>
              时间线追踪 · 行为模式分析 · 智能报告
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {TAB_CONFIG.map((tab) => {
            const isActive = activeKey === tab.key;
            const IconComp = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => {
                  const tabName = TAB_MAP_REV[tab.key];
                  setSearchParams(tabName ? { tab: tabName } : {});
                }}
                aria-label={tab.label}
                aria-pressed={isActive}
                style={{
                  border: 'none',
                  cursor: 'pointer',
                  padding: '6px 18px',
                  borderRadius: 20,
                  fontSize: 13,
                  fontWeight: isActive ? 600 : 400,
                  fontFamily: 'inherit',
                  background: isActive ? '#14B8A6' : 'rgba(255,255,255,0.06)',
                  color: isActive ? '#FFFFFF' : '#7C7F9A',
                  transition: 'all 0.2s ease',
                  outline: 'none',
                  lineHeight: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
                  }
                }}
              >
                <IconComp style={{ fontSize: 14 }} />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      <div style={{
        borderTop: '1px solid rgba(255,255,255,0.06)',
        flex: 1,
      }}>
        <Suspense fallback={
          <div style={{ padding: 64, textAlign: 'center' }}>
            <Spin />
          </div>
        }>
          {renderContent()}
        </Suspense>
      </div>
    </div>
  );
};

export default DeepAnalysis;
