import React from 'react';
import { Table, Badge, Progress, Drawer, Spin, Empty, Button } from 'antd';
import type { AnalysisResultItem } from '../types';
import RenderStructuredData from './RenderStructuredData';

interface AnalysisResultTableProps {
  results: AnalysisResultItem[];
  loading: boolean;
  onViewDetail?: (result: AnalysisResultItem) => void;
}

const STATUS_MAP: Record<string, { color: string; text: string }> = {
  completed: { color: 'green', text: '已完成' },
  running: { color: 'blue', text: '运行中' },
  pending: { color: 'default', text: '待执行' },
  failed: { color: 'red', text: '失败' },
  timeout: { color: 'orange', text: '超时' },
  skipped: { color: 'default', text: '跳过' },
};

const TYPE_ZH: Record<string, string> = {
  zero_day: '0日检测',
  attribution: '溯源分析',
  provenance: '情报证实',
  decay: '衰减分析',
  attack_prediction: '攻击预测',
  deep_analysis: '深度分析',
};

const AnalysisResultTable: React.FC<AnalysisResultTableProps> = ({ results, loading, onViewDetail }) => {
  const columns = [
    { title: '目标ID', dataIndex: 'target_id', key: 'target_id', width: 120, ellipsis: true, render: (v: string) => v ? v.slice(0, 12) + '...' : '-' },
    { title: '摘要', dataIndex: 'result_summary', key: 'result_summary', ellipsis: true, width: 280 },
    { title: '置信度', dataIndex: 'confidence_score', key: 'confidence_score', width: 100, render: (v: number) => <Progress percent={Math.round(v * 100)} size="small" status={v > 0.7 ? 'success' : v > 0.4 ? 'normal' : 'exception'} /> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 80, render: (v: string) => { const s = STATUS_MAP[v] || { color: 'default', text: v }; return <Badge color={s.color} text={s.text} />; } },
    { title: '分析时间', dataIndex: 'analyzed_at', key: 'analyzed_at', width: 140, render: (v: string) => v ? new Date(v).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-' },
    {
      title: '操作', key: 'action', width: 80, render: (_: unknown, record: AnalysisResultItem) => (
        <Button size="small" type="link" onClick={() => onViewDetail?.(record)}>详情</Button>
      ),
    },
  ];

  return (
    <Table
      dataSource={results}
      columns={columns}
      loading={loading}
      rowKey="id"
      size="small"
      pagination={{ pageSize: 10, showSizeChanger: false }}
      style={{ background: '#fff', borderRadius: 12 }}
    />
  );
};

interface AnalysisDetailDrawerProps {
  visible: boolean;
  result: AnalysisResultItem | null;
  onClose: () => void;
}

export const AnalysisDetailDrawer: React.FC<AnalysisDetailDrawerProps> = ({ visible, result, onClose }) => {
  if (!result) return null;
  return (
    <Drawer title={`${TYPE_ZH[result.analysis_type] || result.analysis_type} - 分析详情`} open={visible} onClose={onClose} width={640}>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: '#6B7280', marginBottom: 4 }}>目标: {result.target_id}</div>
        <div style={{ fontSize: 13, color: '#6B7280', marginBottom: 4 }}>置信度: {(result.confidence_score * 100).toFixed(1)}%</div>
        <div style={{ fontSize: 13, color: '#6B7280', marginBottom: 4 }}>状态: {STATUS_MAP[result.status]?.text || result.status}</div>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>摘要</div>
        <div style={{ fontSize: 13, lineHeight: 1.6, color: '#374151', background: '#F9FAFB', padding: 12, borderRadius: 8 }}>{result.result_summary || '无摘要'}</div>
      </div>
      {result.findings && result.findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>发现</div>
          <RenderStructuredData data={result.findings} />
        </div>
      )}
      {result.iocs && result.iocs.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>IOC指标</div>
          <RenderStructuredData data={result.iocs} />
        </div>
      )}
      {result.recommendations && result.recommendations.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>建议</div>
          <ul style={{ margin: 0, paddingLeft: 16 }}>{result.recommendations.map((r, i) => <li key={i} style={{ fontSize: 13, lineHeight: 1.6 }}>{String(r)}</li>)}</ul>
        </div>
      )}
      {result.result_data && Object.keys(result.result_data).length > 0 && (
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>完整数据</div>
          <RenderStructuredData data={result.result_data} />
        </div>
      )}
    </Drawer>
  );
};

export default AnalysisResultTable;
