import React, { useState, useEffect, useMemo } from 'react';
import { Table, Tag, Input, Select, Space, Empty, Button, DatePicker, Collapse, Card, Statistic } from 'antd';
import { SearchOutlined, ReloadOutlined, ExportOutlined, AuditOutlined, FileSearchOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer } from 'recharts';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import { StaggeredBarShape } from '../components/AnimatedChart';

const { RangePicker } = DatePicker;

const ACTION_MAP: Record<string, { label: string; color: string; bg: string }> = {
  collect: { label: '采集', color: 'var(--blue)', bg: 'var(--blue-dim)' },
  analyze: { label: '分析', color: 'var(--green)', bg: 'var(--green-dim)' },
  report: { label: '报告', color: 'var(--yellow)', bg: 'var(--yellow-dim)' },
  chat: { label: '对话', color: 'var(--primary)', bg: 'var(--primary-dim)' },
  execute: { label: '执行', color: 'var(--blue)', bg: 'var(--blue-dim)' },
  decompose: { label: '分解', color: 'var(--orange)', bg: 'var(--orange-dim)' },
  completed: { label: '完成', color: 'var(--green)', bg: 'var(--green-dim)' },
  failed: { label: '失败', color: 'var(--red)', bg: 'var(--red-dim)' },
  running: { label: '运行中', color: 'var(--blue)', bg: 'var(--blue-dim)' },
};

interface LogEntry {
  id: string;
  timestamp: string;
  action: string;
  user: string;
  target: string;
  detail: string;
  ip: string;
  raw: Record<string, unknown>;
}

const AuditLog: React.FC = () => {
  const message = useAntdMessage();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState<string | undefined>();
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [keyword, setKeyword] = useState('');
  const [page, setPage] = useState(1);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = { offset: 0, limit: 100 };
      if (actionFilter) params.action = actionFilter;
      if (keyword) params.keyword = keyword;
      if (dateRange && dateRange[0]) params.date_from = dateRange[0].startOf('day').toISOString();
      if (dateRange && dateRange[1]) params.date_to = dateRange[1].endOf('day').toISOString();
      const res = await api.auditLog.list(params);
      const rawItems: unknown[] = ((res as Record<string, unknown>)?.items || []) as unknown[];
      const entries: LogEntry[] = rawItems.map((raw) => {
        const item = raw as Record<string, unknown>;
        const action = (item.action || 'unknown') as string;
        return {
          id: (item.id || `log-${Math.random().toString(36).slice(2)}`) as string,
          timestamp: (item.created_at || new Date().toISOString()) as string,
          action,
          user: (item.username || 'system') as string,
          target: (item.resource || '—') as string,
          detail: (item.detail || '') as string,
          ip: (item.ip_address || '—') as string,
          raw: item as Record<string, unknown>,
        };
      });
      setLogs(entries);
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); const iv = setInterval(fetchLogs, 60000); return () => clearInterval(iv); }, []);

  const filtered = useMemo(() => {
    let result = Array.isArray(logs) ? logs : [];
    if (keyword) { const kw = keyword.toLowerCase(); result = result.filter(l => l.target.toLowerCase().includes(kw) || l.user.toLowerCase().includes(kw) || l.detail.toLowerCase().includes(kw) || l.action.toLowerCase().includes(kw)); }
    if (actionFilter) { result = result.filter(l => l.action === actionFilter); }
    if (dateRange && dateRange[0] && dateRange[1]) { const start = dateRange[0].startOf('day'); const end = dateRange[1].endOf('day'); result = result.filter(l => { const d = dayjs(l.timestamp); return d.isAfter(start) && d.isBefore(end); }); }
    return result;
  }, [logs, keyword, actionFilter, dateRange]);

  const barData = useMemo(() => {
    const counts: Record<string, number> = {};
    filtered.forEach(l => { counts[l.action] = (counts[l.action] || 0) + 1; });
    return Object.entries(counts).map(([action, count]) => ({
      action: ACTION_MAP[action]?.label || action,
      count,
      key: action,
    }));
  }, [filtered]);

  const handleExport = () => {
    const headers = ['时间', '操作类型', '操作者', '目标', '详情', 'IP'];
    const rows = filtered.map(l => [dayjs(l.timestamp).format('YYYY-MM-DD HH:mm:ss'), l.action, l.user, l.target, l.detail, l.ip]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-log-${dayjs().format('YYYYMMDD-HHmmss')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    message.success('导出成功');
  };

  const actionOptions = useMemo(() => {
    const actions = new Set(logs.map(l => l.action));
    return Array.from(actions).map(a => { const cfg = ACTION_MAP[a]; return { label: cfg?.label || a, value: a }; });
  }, [logs]);

  const totalActions = logs.length;
  const uniqueUsers = new Set(logs.map(l => l.user)).size;
  const failedCount = logs.filter(l => l.action === 'failed').length;

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>审计日志</h1>
          <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>记录系统所有操作行为，支持合规审计追踪</p>
        </div>
        <Space size={8}>
          <Button icon={<ExportOutlined />} onClick={handleExport} style={{ border: '1px solid var(--primary-light)', color: 'var(--primary)', background: 'var(--primary-dim)' }}>导出CSV</Button>
          <Button icon={<ReloadOutlined />} onClick={fetchLogs} loading={loading}>刷新</Button>
        </Space>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>总操作数</span>} value={totalActions} valueStyle={{ color: 'var(--text-0)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<AuditOutlined />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>操作者</span>} value={uniqueUsers} valueStyle={{ color: 'var(--blue)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<FileSearchOutlined />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>失败操作</span>} value={failedCount} valueStyle={{ color: 'var(--red)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<ThunderboltOutlined />} />
        </Card>
      </div>

      <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>操作类型分布</div>
        {barData.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} margin={{ top: 5, right: 20, left: -10, bottom: 5 }} barCategoryGap="20%" barGap={4}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" vertical={false} />
              <XAxis dataKey="action" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <RTooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} />
              <Bar dataKey="count" fill="#1E293B" barSize={16} radius={[4, 4, 0, 0]} isAnimationActive={false} shape={<StaggeredBarShape radius={[4, 4, 0, 0]} />} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>暂无数据</span>} />
        )}
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>操作类型</label>
          <Select placeholder="全部类型" value={actionFilter} onChange={setActionFilter} allowClear style={{ width: 130 }} options={actionOptions} />
        </div>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>时间范围</label>
          <RangePicker value={dateRange} onChange={vals => setDateRange(vals)} style={{ width: 260 }} placeholder={['开始日期', '结束日期']} />
        </div>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>关键词</label>
          <Input placeholder="搜索操作内容..." prefix={<SearchOutlined style={{ color: 'var(--text-3)', fontSize: 12 }} />} value={keyword} onChange={e => setKeyword(e.target.value)} allowClear style={{ width: 200 }} />
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-3)', marginLeft: 'auto' }}>筛选后 {filtered.length} 条</span>
      </div>

      <Collapse
        defaultActiveKey={['logTable']}
        items={[{
          key: 'logTable',
          label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>日志列表</span>,
          children: (
            <Table
              dataSource={filtered}
              rowKey="id"
              size="middle"
              loading={loading}
              locale={{ emptyText: <Empty description={<span style={{ color: 'var(--text-3)', fontSize: 13 }}>暂无执行记录</span>} /> }}
              pagination={{ current: page, pageSize: 20, onChange: setPage, showTotal: t => `共 ${t} 条`, showSizeChanger: false }}
              expandable={{
                expandedRowRender: (record) => (
                  <pre style={{ whiteSpace: 'pre-wrap', fontSize: 11, color: 'var(--text-2)', background: 'var(--bg-2)', padding: 16, borderRadius: 'var(--radius)', border: '1px solid var(--border)', maxHeight: 300, overflow: 'auto' }}>
                    {JSON.stringify(record.raw, null, 2)}
                  </pre>
                ),
                rowExpandable: () => true,
              }}
              columns={[
                { title: '时间', dataIndex: 'timestamp', width: 150, render: (val: string) => <span style={{ color: 'var(--text-2)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>{val ? dayjs(val).format('YYYY-MM-DD HH:mm') : '—'}</span> },
                { title: '操作类型', dataIndex: 'action', width: 110, render: (val: string) => { const cfg = ACTION_MAP[val]; if (cfg) return <span style={{ display: 'inline-flex', alignItems: 'center', padding: '2px 10px', borderRadius: 9999, background: cfg.bg, color: cfg.color, fontSize: 11, fontWeight: 500 }}>{cfg.label}</span>; return <Tag style={{ margin: 0, borderRadius: 9999 }}>{val}</Tag>; } },
                { title: '操作者', dataIndex: 'user', width: 110, render: (val: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500, fontSize: 13 }}>{val}</span> },
                { title: '目标', dataIndex: 'target', ellipsis: true, render: (val: string) => <span style={{ color: 'var(--text-2)', fontSize: 13 }}>{val}</span> },
                { title: '详情', dataIndex: 'detail', ellipsis: true, render: (val: string) => <span style={{ color: 'var(--text-3)', fontSize: 12 }}>{val || '—'}</span> },
                { title: 'IP', dataIndex: 'ip', width: 130, render: (val: string) => <span style={{ color: 'var(--text-3)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>{val}</span> },
              ]}
            />
          ),
        }]}
      />
    </div>
  );
};

export default AuditLog;
