import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Table, Tag, Input, Select, Button, Space, Modal, Form, Spin, Collapse, Empty,
} from 'antd';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell,
} from 'recharts';
import {
  PlusOutlined, ClearOutlined, BulbOutlined, FileTextOutlined,
  CheckCircleOutlined, ExclamationCircleOutlined, DownloadOutlined,
} from '@ant-design/icons';
import {
  intelligenceApi, blacktalkApi, getErrorMessage,
} from '../services/api';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { useAntdMessage } from '../utils/hooks';
import type { IntelligenceItem, IntelligenceStats } from '../types';
import { StaggeredBarShape } from '../components/AnimatedChart';

const { TextArea } = Input;

const THREAT_TAG_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: '#DC2626', label: '严重' },
  high: { color: '#EA580C', label: '高危' },
  medium: { color: '#EAB308', label: '中危' },
  low: { color: '#16A34A', label: '低危' },
};

const STATUS_MAP: Record<string, { color: string; label: string }> = {
  raw: { color: '#64748B', label: '原始' },
  cleaned: { color: '#2563EB', label: '已清洗' },
  analyzed: { color: '#16A34A', label: '已分析' },
};

const SOURCE_OPTIONS = [
  { label: '暗网论坛', value: 'dark_web' },
  { label: '社交媒体', value: 'social_media' },
  { label: '开源情报', value: 'osint' },
  { label: '人工采集', value: 'manual' },
  { label: '威胁订阅', value: 'feed' },
];

const TOOLTIP_STYLE: React.CSSProperties = {
  background: '#FFFFFF',
  border: '1px solid #E2E8F0',
  borderRadius: 8,
  fontSize: 12,
  color: '#0F172A',
  fontFamily: 'var(--font-body)',
  padding: '10px 14px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
};

const PAGE_SIZE = 20;

const CountUpNumber: React.FC<{ value: number; style?: React.CSSProperties }> = ({ value, style }) => {
  const counterRef = useRef({ val: 0 });
  const [display, setDisplay] = useState(0);
  const hasAnimated = useRef(false);

  useEffect(() => {
    if (!hasAnimated.current) {
      hasAnimated.current = true;
      counterRef.current.val = 0;
      setDisplay(0);
      const tween = gsap.to(counterRef.current, {
        val: value,
        duration: ANIM_CONFIG.statCard.counterDuration,
        ease: 'power2.out',
        onUpdate: () => { setDisplay(Math.round(counterRef.current.val)); },
        onComplete: () => { setDisplay(value); },
      });
      return () => { tween.kill(); };
    } else {
      const tween = gsap.to(counterRef.current, {
        val: value,
        duration: 0.6,
        ease: 'power2.out',
        onUpdate: () => { setDisplay(Math.round(counterRef.current.val)); },
        onComplete: () => { setDisplay(value); },
      });
      return () => { tween.kill(); };
    }
  }, [value]);

  return <div style={style}>{display}</div>;
};

const Intelligence: React.FC = () => {
  const message = useAntdMessage();
  const [data, setData] = useState<IntelligenceItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<IntelligenceStats | null>(null);
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string | undefined>();
  const [threatFilter, setThreatFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [detailVisible, setDetailVisible] = useState(false);
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [decodeResult, setDecodeResult] = useState<{
    found_terms: Array<{ term: string; meaning: string; position: number[] }>;
    decoded_text: string;
  } | null>(null);
  const [createVisible, setCreateVisible] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [pipelineVisible, setPipelineVisible] = useState(false);
  const [pipelineMode, setPipelineMode] = useState<'clean' | 'analyze'>('clean');
  const [pipelineLoading, setPipelineLoading] = useState(false);
  const [pipelineResult, setPipelineResult] = useState<Record<string, unknown> | null>(null);
  const [pipelineText, setPipelineText] = useState('');
  const [form] = Form.useForm();

  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [debouncedKeyword, setDebouncedKeyword] = useState(keyword);

  useEffect(() => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setDebouncedKeyword(keyword), 400);
    return () => { if (searchTimerRef.current) clearTimeout(searchTimerRef.current); };
  }, [keyword]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    const [listRes, statsRes] = await Promise.allSettled([
      intelligenceApi.list({
        offset: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        search: debouncedKeyword || undefined,
        source: sourceFilter,
        threat_level: threatFilter,
        status: statusFilter,
      }),
      intelligenceApi.getStats(),
    ]);
    if (listRes.status === 'fulfilled') {
      setData(Array.isArray(listRes.value.items) ? listRes.value.items : []);
      setTotal(listRes.value.total ?? 0);
    }
    if (statsRes.status === 'fulfilled') {
      setStats(statsRes.value);
    }
    setLoading(false);
  }, [page, debouncedKeyword, sourceFilter, threatFilter, statusFilter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleViewDetail = async (id: string) => {
    setDetailVisible(true);
    setDetailLoading(true);
    setDecodeResult(null);
    try {
      const res = await intelligenceApi.get(id);
      const detailData = res as unknown as Record<string, unknown>;
      setDetail(detailData);
      const content = (detailData.data as Record<string, unknown>)?.content as string
        ?? detailData.content as string
        ?? '';
      if (content) {
        const decodeRes = await blacktalkApi.decode(content);
        setDecodeResult({
          found_terms: Array.isArray(decodeRes.found_terms) ? decodeRes.found_terms : [],
          decoded_text: decodeRes.decoded_text ?? '',
        });
      }
    } catch {
      message.error('获取详情失败');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      setCreateLoading(true);
      await intelligenceApi.create({
        source: values.source || undefined,
        content: values.content,
        source_url: values.source_url || undefined,
      });
      message.success('情报已创建');
      setCreateVisible(false);
      form.resetFields();
      fetchData();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in (err as object)) return;
      message.error(getErrorMessage(err));
    } finally {
      setCreateLoading(false);
    }
  };

  const openPipeline = (mode: 'clean' | 'analyze', content?: string) => {
    setPipelineMode(mode);
    setPipelineText(content ?? '');
    setPipelineResult(null);
    setPipelineVisible(true);
  };

  const handleBatchAction = (mode: 'clean' | 'analyze') => {
    if (selectedRowKeys.length === 0) {
      message.warning('请先选择情报');
      return;
    }
    const content = data
      .filter(d => selectedRowKeys.includes(d.id))
      .map(i => i.content)
      .join('\n---\n');
    openPipeline(mode, content);
  };

  const handleExportCSV = () => {
    if (data.length === 0) {
      message.warning('没有可导出的数据');
      return;
    }
    const headers = ['ID', '来源', '内容', '威胁等级', '状态', '采集时间'];
    const rows = data.map(item => [
      item.id,
      item.source || '',
      `"${(item.content || '').replace(/"/g, '""')}"`,
      (item.threat_level ? THREAT_TAG_MAP[item.threat_level]?.label : null) || item.threat_level || '',
      (item.status ? STATUS_MAP[item.status]?.label : null) || item.status || '',
      item.collected_at || '',
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intelligence_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    message.success(`已导出 ${data.length} 条情报`);
  };

  const handlePipelineExecute = async () => {
    if (!pipelineText.trim()) {
      message.warning('请输入内容');
      return;
    }
    setPipelineLoading(true);
    setPipelineResult(null);
    try {
      const res = pipelineMode === 'clean'
        ? await intelligenceApi.clean(pipelineText)
        : await intelligenceApi.analyze(pipelineText);
      setPipelineResult(res as unknown as Record<string, unknown>);
      message.success(pipelineMode === 'clean' ? '清洗完成' : '分析完成');
      fetchData();
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setPipelineLoading(false);
    }
  };

  const renderBlacktalkContent = (content: string) => {
    if (!decodeResult?.found_terms?.length) return content;
    const parts: React.ReactNode[] = [];
    let lastIdx = 0;
    const sorted = [...decodeResult.found_terms].sort(
      (a, b) => (a.position?.[0] ?? 0) - (b.position?.[0] ?? 0),
    );
    for (const term of sorted) {
      const start = term.position?.[0] ?? content.indexOf(term.term, lastIdx);
      if (start === -1 || start < lastIdx) continue;
      const end = start + term.term.length;
      if (start > lastIdx) parts.push(content.slice(lastIdx, start));
      parts.push(
        <span
          key={`${term.term}-${start}`}
          style={{
            background: '#F59E0B14',
            color: '#F59E0B',
            padding: '1px 4px',
            borderRadius: 3,
            cursor: 'help',
          }}
          title={term.meaning}
        >
          {term.term}
        </span>,
      );
      lastIdx = end;
    }
    if (lastIdx < content.length) parts.push(content.slice(lastIdx));
    return parts.length > 0 ? parts : content;
  };

  const statItems = [
    { label: '情报总量', value: stats?.total ?? total, icon: <FileTextOutlined style={{ fontSize: 18, color: '#1E40AF' }} />, color: '#1E40AF' },
    { label: '待处理', value: stats?.by_status?.raw ?? 0, icon: <ExclamationCircleOutlined style={{ fontSize: 18, color: '#F59E0B' }} />, color: '#F59E0B' },
    { label: '已分析', value: stats?.by_status?.analyzed ?? 0, icon: <CheckCircleOutlined style={{ fontSize: 18, color: '#16A34A' }} />, color: '#16A34A' },
    { label: '高危', value: stats?.by_threat_level?.critical ?? 0, icon: <ExclamationCircleOutlined style={{ fontSize: 18, color: '#DC2626' }} />, color: '#DC2626' },
  ];

  const threatPieData = Object.entries(stats?.by_threat_level || {}).map(([name, value]) => ({
    name: THREAT_TAG_MAP[name]?.label || name,
    value,
    color: THREAT_TAG_MAP[name]?.color || '#64748B',
  }));

  const sourceBarData = Object.entries(stats?.by_source || {}).map(([name, value]) => ({
    name: SOURCE_OPTIONS.find(s => s.value === name)?.label || name,
    value,
  }));

  const columns = [
    {
      title: '来源',
      dataIndex: 'source',
      width: 100,
      render: (v: string) => (
        <span style={{ color: '#334155', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {v || '未知'}
        </span>
      ),
    },
    {
      title: '内容',
      dataIndex: 'content',
      render: (v: string, record: IntelligenceItem) => {
        if (!v) return <span style={{ color: '#94A3B8' }}>—</span>;
        const truncated = v.length > 60 ? v.slice(0, 60) + '...' : v;
        return (
          <span style={{ color: '#334155', fontSize: 13 }}>
            {truncated}
            {v.length > 60 && (
              <a
                onClick={() => handleViewDetail(record.id)}
                style={{ color: '#1E40AF', fontSize: 12, marginLeft: 6, cursor: 'pointer' }}
              >
                展开
              </a>
            )}
          </span>
        );
      },
    },
    {
      title: '威胁等级',
      dataIndex: 'threat_level',
      width: 90,
      render: (v: string) => {
        const cfg = THREAT_TAG_MAP[v];
        return cfg ? (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>
            {cfg.label}
          </Tag>
        ) : <Tag style={{ background: '#E2E8F0', border: '1px solid #E2E8F0', color: '#64748B', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>未知</Tag>;
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 80,
      render: (v: string) => {
        const cfg = STATUS_MAP[v];
        return cfg ? (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>
            {cfg.label}
          </Tag>
        ) : <Tag style={{ background: '#E2E8F0', border: '1px solid #E2E8F0', color: '#64748B', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>{v}</Tag>;
      },
    },
    {
      title: '实体数',
      dataIndex: 'entities_count',
      width: 70,
      align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: '#334155', fontSize: 12 }}>
          {v ?? 0}
        </span>
      ),
    },
    {
      title: '黑话数',
      dataIndex: 'blacktalk_count',
      width: 70,
      align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: '#334155', fontSize: 12 }}>
          {v ?? 0}
        </span>
      ),
    },
    {
      title: '采集时间',
      dataIndex: 'collected_at',
      width: 140,
      render: (v: string) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: '#64748B', fontSize: 12 }}>
          {v
            ? new Date(v).toLocaleString('zh-CN', {
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
              })
            : '—'}
        </span>
      ),
    },
    {
      title: '操作',
      width: 120,
      render: (_: unknown, record: IntelligenceItem) => (
        <Space size={4}>
          <Button type="link" size="small" onClick={() => handleViewDetail(record.id)} style={{ color: '#1E40AF', fontSize: 12, padding: 0 }}>
            查看
          </Button>
          <Button type="link" size="small" onClick={() => openPipeline('analyze', record.content)} style={{ color: '#0D9488', fontSize: 12, padding: 0 }}>
            分析
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div style={{ minHeight: '100%', padding: 0, background: '#F8FAFC', overflowX: 'hidden' }}>
      <div style={{ padding: '32px 32px 8px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 600, fontFamily: 'var(--font-body)', color: '#0F172A', letterSpacing: '-0.025em', marginBottom: 4, lineHeight: 1.2 }}>
            情报中心
          </h1>
          <p style={{ fontSize: 14, color: '#64748B', margin: 0, fontFamily: 'var(--font-body)' }}>
            采集、清洗、分析多源黑灰产情报数据
          </p>
        </div>
        <Space size={8}>
          <Button icon={<DownloadOutlined />} onClick={handleExportCSV} disabled={data.length === 0}>
            导出CSV
          </Button>
          <Button icon={<ClearOutlined />} onClick={() => handleBatchAction('clean')} disabled={selectedRowKeys.length === 0}>
            批量清洗
          </Button>
          <Button icon={<BulbOutlined />} onClick={() => handleBatchAction('analyze')} disabled={selectedRowKeys.length === 0}>
            智能分析
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateVisible(true)}>
            录入情报
          </Button>
        </Space>
      </div>

      <div style={{ padding: '8px 32px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 16 }}>
          {statItems.map((item, idx) => (
            <div key={item.label} style={{ padding: '20px 24px', background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', gap: 14, transition: 'all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)', cursor: 'default', opacity: 0, transform: 'translateY(12px)' }} ref={(el) => { if (el) { gsap.fromTo(el, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, delay: idx * 0.08, ease: 'power2.out', clearProps: 'opacity,y' }); } }} onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.08)'; }} onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}>
              <div style={{ width: 44, height: 44, borderRadius: 10, background: `${item.color}10`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                {item.icon}
              </div>
              <div>
                <div style={{ fontSize: 12, color: '#94A3B8', fontWeight: 500, marginBottom: 4, fontFamily: 'var(--font-body)' }}>
                  {item.label}
                </div>
                <CountUpNumber value={item.value} style={{ fontSize: 24, fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#0F172A', letterSpacing: '-0.02em', lineHeight: 1 }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: '0 32px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
          <div className="chart-reveal chart-d-1" style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16, fontFamily: 'var(--font-body)' }}>
              威胁等级分布
            </div>
            {threatPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={threatPieData} layout="vertical" margin={{ top: 4, right: 20, left: 60, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" horizontal={false} vertical={false} />
                  <XAxis type="number" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={56} />
                  <RTooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                  <Bar dataKey="value" barSize={16} radius={[0, 6, 6, 0]} isAnimationActive={false} shape={<StaggeredBarShape layout="horizontal" radius={[0, 6, 6, 0]} />}>
                    {threatPieData.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </div>
            )}
          </div>

          <div className="chart-reveal chart-d-2" style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16, fontFamily: 'var(--font-body)' }}>
              来源分布
            </div>
            {sourceBarData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={sourceBarData} barCategoryGap="20%" barGap={4}>
                  <XAxis dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={36} />
                  <RTooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="#3A5F8A" barSize={16} radius={[4, 4, 0, 0]} name="数量" isAnimationActive={false} shape={<StaggeredBarShape radius={[4, 4, 0, 0]} />} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ padding: '0 32px', marginBottom: 16 }}>
        <div style={{ padding: '16px 20px', background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0', display: 'flex', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>来源</div>
            <Select
              placeholder="全部来源"
              value={sourceFilter}
              onChange={setSourceFilter}
              allowClear
              style={{ width: 140 }}
              options={SOURCE_OPTIONS}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>威胁等级</div>
            <Select
              placeholder="全部等级"
              value={threatFilter}
              onChange={setThreatFilter}
              allowClear
              style={{ width: 140 }}
              options={Object.entries(THREAT_TAG_MAP).map(([k, v]) => ({ label: v.label, value: k }))}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>状态</div>
            <Select
              placeholder="全部状态"
              value={statusFilter}
              onChange={setStatusFilter}
              allowClear
              style={{ width: 140 }}
              options={Object.entries(STATUS_MAP).map(([k, v]) => ({ label: v.label, value: k }))}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>搜索</div>
            <Input.Search
              placeholder="搜索情报内容..."
              value={keyword}
              onChange={e => setKeyword(e.target.value)}
              onSearch={v => setKeyword(v)}
              allowClear
              style={{ width: 240 }}
            />
          </div>
          <span style={{ marginLeft: 'auto', fontSize: 12, color: '#94A3B8', fontFamily: 'var(--font-mono)', paddingBottom: 4 }}>
            共 {total} 条
          </span>
        </div>
      </div>

      <div style={{ padding: '0 32px' }}>
        <div className="page-collapse fade-in-up stagger-5">
          <Collapse
            defaultActiveKey={['list']}
            items={[
              {
                key: 'list',
                label: <span style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>情报列表</span>,
                children: (
                  <div className="page-table">
                    <Table
                      dataSource={data}
                      columns={columns}
                      rowKey="id"
                      loading={loading}
                      size="middle"
                      rowSelection={{
                        selectedRowKeys,
                        onChange: setSelectedRowKeys,
                      }}
                      pagination={{
                        current: page,
                        total,
                        pageSize: PAGE_SIZE,
                        onChange: setPage,
                        showTotal: t => `共 ${t} 条`,
                        showSizeChanger: false,
                      }}
                    />
                  </div>
                ),
              },
            ]}
          />
        </div>
      </div>

      <Modal
        title="情报详情"
        open={detailVisible}
        onCancel={() => setDetailVisible(false)}
        footer={null}
        width={680}
      >
        <Spin spinning={detailLoading}>
          {detail ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                padding: 16,
                background: '#F8FAFC',
                borderRadius: 8,
                border: '1px solid #E2E8F0',
              }}>
                <div style={{ fontSize: 12, color: '#94A3B8', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>
                  情报内容
                </div>
                <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                  {(() => {
                    const content =
                      (detail.data as Record<string, unknown>)?.content as string
                      ?? (detail.content as string)
                      ?? '';
                    return renderBlacktalkContent(content);
                  })()}
                </div>
              </div>

              {decodeResult?.found_terms && decodeResult.found_terms.length > 0 && (
                <div style={{
                  padding: 16,
                  background: '#F8FAFC',
                  borderRadius: 8,
                  border: '1px solid #E2E8F0',
                }}>
                  <div style={{ fontSize: 12, color: '#F59E0B', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
                    识别到 {decodeResult.found_terms.length} 个黑话
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {decodeResult.found_terms.map((term, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Tag style={{
                          background: '#F59E0B14',
                          color: '#F59E0B',
                          border: '1px solid #F59E0B28',
                          fontSize: 11,
                          borderRadius: 20,
                          padding: '0 8px',
                          lineHeight: '20px',
                        }}>
                          {term.term}
                        </Tag>
                        <span style={{ color: '#94A3B8' }}>→</span>
                        <span style={{ color: '#334155', fontSize: 13 }}>{term.meaning}</span>
                      </div>
                    ))}
                  </div>
                  {decodeResult.decoded_text && (
                    <div style={{
                      marginTop: 12,
                      padding: 12,
                      background: '#F1F5F9',
                      borderRadius: 8,
                    }}>
                      <div style={{ fontSize: 11, color: '#94A3B8', fontWeight: 600, marginBottom: 6, letterSpacing: '0.05em' }}>翻译结果</div>
                      <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.6 }}>
                        {decodeResult.decoded_text}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#94A3B8' }}>暂无详情数据</div>
          )}
        </Spin>
      </Modal>

      <Modal
        title="录入情报"
        open={createVisible}
        onCancel={() => setCreateVisible(false)}
        onOk={handleCreate}
        confirmLoading={createLoading}
        okText="创建"
        width={520}
      >
        <Form form={form} layout="vertical" style={{ marginTop: 8 }}>
          <Form.Item name="source" label={<span style={{ color: '#334155', fontWeight: 500 }}>来源渠道</span>}
            extra="填写情报来源，如暗网论坛、社交媒体、人工采集等">
            <Input placeholder="如：暗网论坛 / 社交媒体 / 人工采集" />
          </Form.Item>
          <Form.Item name="source_url" label={<span style={{ color: '#334155', fontWeight: 500 }}>来源URL</span>}
            extra="原始情报的来源链接">
            <Input placeholder="https://..." />
          </Form.Item>
          <Form.Item
            name="content"
            label={<span style={{ color: '#334155', fontWeight: 500 }}>情报内容</span>}
            rules={[{ required: true, message: '请输入情报内容' }]}
            extra="输入威胁情报的原始文本内容，系统将自动清洗和分析"
          >
            <TextArea rows={6} placeholder="输入威胁情报原始内容..." />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={pipelineMode === 'clean' ? '批量清洗' : '智能分析'}
        open={pipelineVisible}
        onCancel={() => setPipelineVisible(false)}
        footer={null}
        width={640}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {selectedRowKeys.length > 0 && (
            <div style={{
              padding: '8px 12px',
              background: '#1E40AF10',
              borderRadius: 8,
              fontSize: 12,
              color: '#1E40AF',
              fontFamily: 'var(--font-body)',
            }}>
              已选择 {selectedRowKeys.length} 条情报，内容已合并
            </div>
          )}
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>
              {pipelineMode === 'clean' ? '待清洗内容' : '待分析内容'}
            </div>
            <TextArea
              rows={6}
              placeholder={`输入待${pipelineMode === 'clean' ? '清洗' : '分析'}的情报文本...`}
              value={pipelineText}
              onChange={e => setPipelineText(e.target.value)}
            />
          </div>
          <Button
            type="primary"
            block
            loading={pipelineLoading}
            onClick={handlePipelineExecute}
          >
            {pipelineMode === 'clean' ? '执行清洗' : '执行分析'}
          </Button>
          {pipelineResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {pipelineMode === 'clean' ? (
                <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>清洗结果</div>
                  <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                    {String(pipelineResult.cleaned_text || pipelineResult.result || pipelineResult.data || '')}
                  </div>
                  {(pipelineResult.removed_count != null || pipelineResult.entities_found != null) && (
                    <div style={{ display: 'flex', gap: 16, marginTop: 12, paddingTop: 12, borderTop: '1px solid #E2E8F0' }}>
                      {pipelineResult.removed_count != null && (
                        <div><span style={{ color: '#94A3B8', fontSize: 12 }}>移除项: </span><span style={{ fontWeight: 600, color: '#334155' }}>{String(pipelineResult.removed_count)}</span></div>
                      )}
                      {pipelineResult.entities_found != null && (
                        <div><span style={{ color: '#94A3B8', fontSize: 12 }}>发现实体: </span><span style={{ fontWeight: 600, color: '#334155' }}>{String(pipelineResult.entities_found)}</span></div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <>
                  {pipelineResult.threat_categories && Array.isArray(pipelineResult.threat_categories) && pipelineResult.threat_categories.length > 0 && (
                    <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>威胁分类</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {(pipelineResult.threat_categories as Array<Record<string, unknown>>).map((cat: Record<string, unknown>, i: number) => (
                          <Tag key={i} style={{ background: '#DC262614', color: '#DC2626', border: '1px solid #DC262628', borderRadius: 20, padding: '2px 10px' }}>
                            {String(cat.name || cat.category || cat)} {cat.confidence != null ? `(${Number(Number(cat.confidence) * 100).toFixed(0)}%)` : ''}
                          </Tag>
                        ))}
                      </div>
                    </div>
                  )}
                  {pipelineResult.entities && Array.isArray(pipelineResult.entities) && pipelineResult.entities.length > 0 && (
                    <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>提取实体 ({(pipelineResult.entities as Array<unknown>).length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {(pipelineResult.entities as Array<Record<string, unknown>>).slice(0, 20).map((ent: Record<string, unknown>, i: number) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                            <Tag style={{ background: '#2563EB14', color: '#2563EB', border: '1px solid #2563EB28', borderRadius: 4, fontSize: 11, padding: '0 6px' }}>
                              {String(ent.type || ent.entity_type || '未知')}
                            </Tag>
                            <span style={{ color: '#334155' }}>{String(ent.value || ent.text || '')}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {pipelineResult.analysis_summary && (
                    <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>分析摘要</div>
                      <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                        {String(pipelineResult.analysis_summary)}
                      </div>
                    </div>
                  )}
                  {pipelineResult.confidence != null && (
                    <div style={{ padding: 12, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', display: 'flex', gap: 16 }}>
                      <div><span style={{ color: '#94A3B8', fontSize: 12 }}>置信度: </span><span style={{ fontWeight: 600, color: '#334155' }}>{Number(Number(pipelineResult.confidence) * 100).toFixed(1)}%</span></div>
                      {pipelineResult.threat_level ? (
                        <div><span style={{ color: '#94A3B8', fontSize: 12 }}>威胁等级: </span><span style={{ fontWeight: 600, color: String(pipelineResult.threat_level) === 'critical' || String(pipelineResult.threat_level) === 'high' ? '#DC2626' : String(pipelineResult.threat_level) === 'medium' ? '#F59E0B' : '#16A34A' }}>{String(pipelineResult.threat_level)}</span></div>
                      ) : null}
                    </div>
                  )}
                  {pipelineResult.crime_patterns && Array.isArray(pipelineResult.crime_patterns) && pipelineResult.crime_patterns.length > 0 && (
                    <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>犯罪模式</div>
                      {(pipelineResult.crime_patterns as Array<Record<string, unknown>>).map((p: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ padding: '8px 0', borderBottom: i < (pipelineResult.crime_patterns as Array<unknown>).length - 1 ? '1px solid #E2E8F0' : 'none' }}>
                          <div style={{ fontWeight: 500, color: '#334155', fontSize: 13 }}>{String(p.name || p.pattern || '')}</div>
                          {p.description ? <div style={{ color: '#64748B', fontSize: 12, marginTop: 4 }}>{String(p.description)}</div> : null}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default Intelligence;
