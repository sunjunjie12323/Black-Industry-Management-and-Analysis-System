import React from 'react';
import { Spin } from 'antd';
import type { AnalysisTypeStats } from '../types';
import StatCard from './StatCard';
import { WarningOutlined, CheckCircleOutlined, FieldNumberOutlined, ClockCircleOutlined } from '@ant-design/icons';

interface AnalysisStatCardsProps {
  stats: AnalysisTypeStats | null;
  loading: boolean;
  type: string;
}

const TYPE_CONFIG: Record<string, { icon1: React.ReactNode; icon2: React.ReactNode; label1: string; label2: string; color1: string; color2: string }> = {
  zero_day: { icon1: <WarningOutlined />, icon2: <CheckCircleOutlined />, label1: '0日检测数', label2: '检出数', color1: '#B91C1C', color2: '#DC2626' },
  attribution: { icon1: <FieldNumberOutlined />, icon2: <CheckCircleOutlined />, label1: '指纹数量', label2: '同源匹配', color1: '#1E40AF', color2: '#7C3AED' },
  provenance: { icon1: <CheckCircleOutlined />, icon2: <WarningOutlined />, label1: '已验证数', label2: '幻觉检出', color1: '#059669', color2: '#B91C1C' },
  decay: { icon1: <FieldNumberOutlined />, icon2: <WarningOutlined />, label1: '已分析数', label2: '需刷新数', color1: '#1E40AF', color2: '#D97706' },
  attack_prediction: { icon1: <FieldNumberOutlined />, icon2: <WarningOutlined />, label1: '预测数', label2: '预警信号', color1: '#B91C1C', color2: '#D97706' },
};

const AnalysisStatCards: React.FC<AnalysisStatCardsProps> = ({ stats, loading, type }) => {
  const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.zero_day;

  if (loading) {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
        {[1, 2, 3, 4].map(i => (
          <div key={i} style={{ background: 'var(--bg-2)', borderRadius: 8, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
            <Spin size="small" />
          </div>
        ))}
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
      <StatCard icon={cfg.icon1} label={cfg.label1} value={stats.total_count} color={cfg.color1} />
      <StatCard icon={cfg.icon2} label={cfg.label2} value={stats.detection_count} color={cfg.color2} />
      <StatCard icon={<FieldNumberOutlined />} label="平均置信度" value={Math.round(stats.avg_confidence * 100)} color="#0891B2" />
      <StatCard icon={<ClockCircleOutlined />} label="最近分析" value={stats.last_analyzed_at ? new Date(stats.last_analyzed_at).toLocaleDateString('zh-CN') : '-'} color="#6B7280" />
    </div>
  );
};

export default AnalysisStatCards;
