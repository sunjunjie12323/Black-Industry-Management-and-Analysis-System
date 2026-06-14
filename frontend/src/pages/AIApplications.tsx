import React, { Suspense, useEffect } from 'react';
import { Spin } from 'antd';
import { useSearchParams } from 'react-router-dom';
import {
  AppstoreOutlined, MessageOutlined, ScissorOutlined, FileSearchOutlined,
} from '@ant-design/icons';

const SmartQA = React.lazy(() => import('./SmartQA'));
const AiAssistant = React.lazy(() => import('./AiAssistant'));
const ContentGeneration = React.lazy(() => import('./ContentGeneration'));

const TAB_MAP: Record<string, string> = {
  chat: '0',
  extract: '1',
  summarize: '2',
};

const TAB_MAP_REV: Record<string, string> = {
  '0': 'chat',
  '1': 'extract',
  '2': 'summarize',
};

const TAB_CONFIG = [
  { key: '0', label: '智能问答', icon: MessageOutlined, color: '#8B5CF6' },
  { key: '1', label: '实体提取', icon: ScissorOutlined, color: '#EC4899' },
  { key: '2', label: '情报摘要', icon: FileSearchOutlined, color: '#06B6D4' },
];

const AIApplications: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeKey = TAB_MAP[tabParam || 'chat'] || '0';

  useEffect(() => {
    document.title = 'AI应用 - 黑灰产情报分析平台';
  }, []);

  const renderContent = () => {
    return (
      <Suspense fallback={
        <div style={{ padding: 64, textAlign: 'center' }}>
          <Spin />
        </div>
      }>
        {activeKey === '0' && <SmartQA />}
        {activeKey === '1' && <AiAssistant />}
        {activeKey === '2' && <ContentGeneration />}
      </Suspense>
    );
  };

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        background: '#141625',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '16px 32px',
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
            background: 'rgba(139,92,246,0.12)',
            color: '#8B5CF6',
            fontSize: 16,
          }}>
            <AppstoreOutlined />
          </span>
          <div>
            <h1 style={{
              fontSize: 18,
              fontWeight: 700,
              fontFamily: '"Space Grotesk", "PingFang SC", sans-serif',
              color: '#E8E9ED',
              margin: 0,
              letterSpacing: '-0.01em',
            }}>
              AI应用
            </h1>
          </div>
        </div>
      </div>

      <div style={{
        background: '#141625',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '0 32px',
        display: 'flex',
        alignItems: 'stretch',
        gap: 0,
        height: 48,
        flexShrink: 0,
      }}>
        {TAB_CONFIG.map((item) => {
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
                padding: '0 18px',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? `2px solid ${item.color}` : '2px solid transparent',
                cursor: 'pointer',
                fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif',
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                color: isActive ? item.color : '#7C7F9A',
                transition: 'all 0.2s ease',
              }}
              onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.color = '#B0B3C5'; }}
              onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.color = '#7C7F9A'; }}
            >
              <IconComp style={{ fontSize: 14 }} />
              {item.label}
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        {renderContent()}
      </div>
    </div>
  );
};

export default AIApplications;
