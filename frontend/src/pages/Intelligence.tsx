import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import {
  Table, Tag, Input, Select, Button, Space, Modal, Form, Spin, Empty,
} from 'antd';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell,
} from 'recharts';
import {
  PlusOutlined, ClearOutlined, BulbOutlined, FileTextOutlined,
  CheckCircleOutlined, ExclamationCircleOutlined, DownloadOutlined,
  SearchOutlined, RadarChartOutlined, LinkOutlined,
} from '@ant-design/icons';
import {
  intelligenceApi, blacktalkApi, getErrorMessage, api,
} from '../services/api';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { useAntdMessage } from '../utils/hooks';
import type { IntelligenceItem, IntelligenceStats } from '../types';
import { StaggeredBarShape } from '../components/AnimatedChart';

const { TextArea } = Input;

const THREAT_TAG_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: '#EF4444', label: '严重' },
  high: { color: '#F97316', label: '高危' },
  medium: { color: '#F97316', label: '中危' },
  low: { color: '#22C55E', label: '低危' },
};

const STATUS_MAP: Record<string, { color: string; label: string }> = {
  raw: { color: '#7C7F9A', label: '原始' },
  cleaned: { color: '#6C5CE7', label: '已清洗' },
  analyzed: { color: '#22C55E', label: '已分析' },
};

const SOURCE_OPTIONS = [
  { label: '暗网论坛', value: 'dark_web' },
  { label: '社交媒体', value: 'social_media' },
  { label: '开源情报', value: 'osint' },
  { label: '人工采集', value: 'manual' },
  { label: '威胁订阅', value: 'feed' },
];

const TOOLTIP_STYLE: React.CSSProperties = {
  background: 'rgba(20,22,37,0.80)',
  border: '1px solid rgba(255,255,255,0.06)',
  borderRadius: 8,
  fontSize: 12,
  color: '#E8E9ED',
  fontFamily: 'var(--font-body)',
  padding: '10px 14px',
  boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
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
  const [traceVisible, setTraceVisible] = useState(false);
  const [traceData, setTraceData] = useState<Record<string, unknown> | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [sourcePreview, setSourcePreview] = useState<Record<string, unknown> | null>(null);

  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const [debouncedKeyword, setDebouncedKeyword] = useState(keyword);

  useEffect(() => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setDebouncedKeyword(keyword), 400);
    return () => { if (searchTimerRef.current) clearTimeout(searchTimerRef.current); };
  }, [keyword]);

  useEffect(() => {
    return () => { mountedRef.current = false; };
  }, []);

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
    if (!mountedRef.current) return;
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

  const handleViewDetail = useCallback(async (id: string) => {
    setDetailVisible(true);
    setDetailLoading(true);
    setDecodeResult(null);
    try {
      const res = await intelligenceApi.get(id);
      if (!mountedRef.current) return;
      const detailData = res as unknown as Record<string, unknown>;
      setDetail(detailData);
      const content = (detailData.data as Record<string, unknown>)?.content as string
        ?? detailData.content as string
        ?? '';
      if (content) {
        const decodeRes = await blacktalkApi.decode(content);
        if (!mountedRef.current) return;
        setDecodeResult({
          found_terms: Array.isArray(decodeRes.found_terms) ? decodeRes.found_terms : [],
          decoded_text: decodeRes.decoded_text ?? '',
        });
      }
    } catch {
      if (mountedRef.current) message.error('获取详情失败');
    } finally {
      if (mountedRef.current) setDetailLoading(false);
    }
  }, [message]);

  const handleCreate = useCallback(async () => {
    try {
      const values = await form.validateFields();
      setCreateLoading(true);
      await intelligenceApi.create({
        source: values.source || undefined,
        content: values.content,
        source_url: values.source_url || undefined,
      });
      if (!mountedRef.current) return;
      message.success('情报已创建');
      setCreateVisible(false);
      form.resetFields();
      fetchData();
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      if (err && typeof err === 'object' && 'errorFields' in (err as object)) return;
      message.error(getErrorMessage(err));
    } finally {
      if (mountedRef.current) setCreateLoading(false);
    }
  }, [form, fetchData, message]);

  const openPipeline = useCallback((mode: 'clean' | 'analyze', content?: string) => {
    setPipelineMode(mode);
    setPipelineText(content ?? '');
    setPipelineResult(null);
    setPipelineVisible(true);
  }, []);

  const openTrace = useCallback(async (record: IntelligenceItem) => {
    if (!record.id) return;
    setTraceVisible(true);
    setTraceLoading(true);
    setTraceData(null);
    setSourcePreview(null);
    try {
      const [traceRes, previewRes] = await Promise.allSettled([
        api.provenance.trace(record.id),
        api.provenance.sourcePreview(record.id),
      ]);
      if (!mountedRef.current) return;
      if (traceRes.status === 'fulfilled') setTraceData(traceRes.value);
      if (previewRes.status === 'fulfilled') setSourcePreview(previewRes.value);
    } catch {
      if (mountedRef.current) message.error('溯源信息加载失败');
    } finally {
      if (mountedRef.current) setTraceLoading(false);
    }
  }, [message]);

  const handleBatchAction = useCallback((mode: 'clean' | 'analyze') => {
    if (selectedRowKeys.length === 0) {
      message.warning('请先选择情报');
      return;
    }
    const content = data
      .filter(d => selectedRowKeys.includes(d.id))
      .map(i => i.content)
      .join('\n---\n');
    openPipeline(mode, content);
  }, [selectedRowKeys, data, openPipeline, message]);

  const handleExportCSV = useCallback(() => {
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
  }, [data, message]);

  const handlePipelineExecute = useCallback(async () => {
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
      if (!mountedRef.current) return;
      setPipelineResult(res as unknown as Record<string, unknown>);
      message.success(pipelineMode === 'clean' ? '清洗完成' : '分析完成');
      fetchData();
    } catch (err) {
      if (mountedRef.current) message.error(getErrorMessage(err));
    } finally {
      if (mountedRef.current) setPipelineLoading(false);
    }
  }, [pipelineText, pipelineMode, fetchData, message]);

  const renderBlacktalkContent = useCallback((content: string) => {
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
            background: '#F9731614',
            color: '#F97316',
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
  }, [decodeResult]);

  const statItems = useMemo(() => [
    { label: '情报总量', value: stats?.total ?? total, icon: <FileTextOutlined style={{ fontSize: 16, color: '#6C5CE7' }} />, color: '#6C5CE7' },
    { label: '待处理', value: stats?.by_status?.raw ?? 0, icon: <ExclamationCircleOutlined style={{ fontSize: 16, color: '#F97316' }} />, color: '#F97316' },
    { label: '已分析', value: stats?.by_status?.analyzed ?? 0, icon: <CheckCircleOutlined style={{ fontSize: 16, color: '#22C55E' }} />, color: '#22C55E' },
    { label: '高危', value: stats?.by_threat_level?.critical ?? 0, icon: <ExclamationCircleOutlined style={{ fontSize: 16, color: '#EF4444' }} />, color: '#EF4444' },
  ], [stats, total]);

  const threatPieData = useMemo(() => Object.entries(stats?.by_threat_level || {}).map(([name, value]) => ({
    name: THREAT_TAG_MAP[name]?.label || name,
    value,
    color: THREAT_TAG_MAP[name]?.color || '#7C7F9A',
  })), [stats]);

  const sourceBarData = useMemo(() => Object.entries(stats?.by_source || {}).map(([name, value]) => ({
    name: SOURCE_OPTIONS.find(s => s.value === name)?.label || name,
    value,
  })), [stats]);

  const columns = useMemo(() => [
    {
      title: '来源',
      dataIndex: 'source',
      width: 100,
      render: (v: string) => (
        <span style={{ color: '#E8E9ED', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {v || '未知'}
        </span>
      ),
    },
    {
      title: '内容',
      dataIndex: 'content',
      render: (v: string, record: IntelligenceItem) => {
        if (!v) return <span style={{ color: '#7C7F9A' }}>—</span>;
        const truncated = v.length > 60 ? v.slice(0, 60) + '...' : v;
        return (
          <span style={{ color: '#E8E9ED', fontSize: 13 }}>
            {truncated}
            {v.length > 60 && (
              <a
                onClick={() => handleViewDetail(record.id)}
                style={{ color: '#6C5CE7', fontSize: 12, marginLeft: 6, cursor: 'pointer' }}
                role="button"
                tabIndex={0}
                aria-label={`查看情报详情 ${record.id}`}
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
        ) : <Tag style={{ background: 'rgba(28,31,53,0.5)', border: '1px solid rgba(255,255,255,0.06)', color: '#7C7F9A', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>未知</Tag>;
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
        ) : <Tag style={{ background: 'rgba(28,31,53,0.5)', border: '1px solid rgba(255,255,255,0.06)', color: '#7C7F9A', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>{v}</Tag>;
      },
    },
    {
      title: '实体数',
      dataIndex: 'entities_count',
      width: 70,
      align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: '#E8E9ED', fontSize: 12 }}>
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
        <span style={{ fontFamily: 'var(--font-mono)', color: '#E8E9ED', fontSize: 12 }}>
          {v ?? 0}
        </span>
      ),
    },
    {
      title: '采集时间',
      dataIndex: 'collected_at',
      width: 140,
      render: (v: string) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: '#7C7F9A', fontSize: 12 }}>
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
          <Button type="link" size="small" onClick={() => handleViewDetail(record.id)} style={{ color: '#6C5CE7', fontSize: 12, padding: 0 }} aria-label={`查看 ${record.id}`}>
            查看
          </Button>
          <Button type="link" size="small" onClick={() => openPipeline('analyze', record.content)} style={{ color: '#6C5CE7', fontSize: 12, padding: 0 }} aria-label={`分析 ${record.id}`}>
            分析
          </Button>
        </Space>
      ),
    },
    {
      title: '溯源',
      key: 'trace',
      width: 80,
      render: (_: unknown, record: IntelligenceItem) => (
        <Button
          type="link"
          size="small"
          icon={<LinkOutlined />}
          onClick={(e) => { e.stopPropagation(); openTrace(record); }}
          style={{ color: '#00D4FF', padding: 0, fontSize: 12 }}
          aria-label={`溯源 ${record.id}`}
        >
          溯源
        </Button>
      ),
    },
  ], [handleViewDetail, openPipeline, openTrace]);

  return (
    <div style={{ display: 'flex', minHeight: '100%', background: '#0B0D17' }}>
      <div style={{
        width: 260,
        minWidth: 260,
        background: '#141625',
        borderRight: '1px solid rgba(255,255,255,0.06)',
        padding: '24px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 20,
        overflowY: 'auto',
        position: 'sticky',
        top: 0,
        height: '100vh',
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 16, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{
            width: 36,
            height: 36,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #6C5CE7, #8B7CF7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            <RadarChartOutlined style={{ fontSize: 18, color: '#FFFFFF' }} />
          </div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#E8E9ED', fontFamily: 'var(--font-body)', lineHeight: 1.2 }}>
              情报中心
            </div>
            <div style={{ fontSize: 11, color: '#7C7F9A', fontFamily: 'var(--font-body)', marginTop: 2 }}>
              多源黑灰产情报
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#7C7F9A', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 2 }}>
            数据概览
          </div>
          {statItems.map((item, idx) => (
            <div
              key={item.label}
              style={{
                padding: '10px 12px',
                background: 'rgba(28,31,53,0.5)',
                borderRadius: 8,
                border: '1px solid rgba(255,255,255,0.06)',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                transition: 'all 0.2s ease',
                cursor: 'default',
                opacity: 0,
                transform: 'translateX(-8px)',
              }}
              ref={(el) => {
                if (el) {
                  gsap.fromTo(el, { x: -8, opacity: 0 }, { x: 0, opacity: 1, duration: 0.35, delay: idx * 0.06, ease: 'power2.out', clearProps: 'opacity,x' });
                }
              }}
            >
              <div style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: `${item.color}10`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                {item.icon}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, color: '#7C7F9A', fontWeight: 500, lineHeight: 1 }}>
                  {item.label}
                </div>
                <CountUpNumber
                  value={item.value}
                  style={{ fontSize: 20, fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#E8E9ED', letterSpacing: '-0.02em', lineHeight: 1.3 }}
                />
              </div>
              <div style={{
                width: 4,
                height: 24,
                borderRadius: 2,
                background: item.color,
                opacity: 0.6,
              }} />
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#7C7F9A', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 2 }}>
            筛选条件
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#7C7F9A', marginBottom: 4, fontWeight: 500 }}>来源</div>
            <Select
              placeholder="全部来源"
              value={sourceFilter}
              onChange={setSourceFilter}
              allowClear
              style={{ width: '100%' }}
              options={SOURCE_OPTIONS}
              size="small"
              aria-label="筛选来源"
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#7C7F9A', marginBottom: 4, fontWeight: 500 }}>威胁等级</div>
            <Select
              placeholder="全部等级"
              value={threatFilter}
              onChange={setThreatFilter}
              allowClear
              style={{ width: '100%' }}
              options={Object.entries(THREAT_TAG_MAP).map(([k, v]) => ({ label: v.label, value: k }))}
              size="small"
              aria-label="筛选威胁等级"
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#7C7F9A', marginBottom: 4, fontWeight: 500 }}>状态</div>
            <Select
              placeholder="全部状态"
              value={statusFilter}
              onChange={setStatusFilter}
              allowClear
              style={{ width: '100%' }}
              options={Object.entries(STATUS_MAP).map(([k, v]) => ({ label: v.label, value: k }))}
              size="small"
              aria-label="筛选状态"
            />
          </div>
        </div>

        <div style={{ marginTop: 'auto' }}>
          <Input
            placeholder="搜索情报内容..."
            value={keyword}
            onChange={e => setKeyword(e.target.value)}
            allowClear
            prefix={<SearchOutlined style={{ color: '#7C7F9A', fontSize: 13 }} />}
            style={{ borderRadius: 8 }}
            size="small"
            aria-label="搜索情报内容"
          />
          <div style={{ fontSize: 11, color: '#7C7F9A', marginTop: 10, textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
            共 {total} 条情报
          </div>
        </div>
      </div>

      <div style={{ flex: 1, padding: '24px 28px', overflowY: 'auto', minHeight: '100vh' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 20,
        }}>
          <div style={{ fontSize: 13, color: '#7C7F9A', fontFamily: 'var(--font-body)' }}>
            采集、清洗、分析多源黑灰产情报数据
          </div>
          <Space size={8}>
            <Button
              icon={<DownloadOutlined />}
              onClick={handleExportCSV}
              disabled={data.length === 0}
              size="small"
              style={{ borderRadius: 6, fontSize: 12 }}
              aria-label="导出CSV"
            >
              导出CSV
            </Button>
            <Button
              icon={<ClearOutlined />}
              onClick={() => handleBatchAction('clean')}
              disabled={selectedRowKeys.length === 0}
              size="small"
              style={{ borderRadius: 6, fontSize: 12 }}
              aria-label="批量清洗"
            >
              批量清洗
            </Button>
            <Button
              icon={<BulbOutlined />}
              onClick={() => handleBatchAction('analyze')}
              disabled={selectedRowKeys.length === 0}
              size="small"
              style={{ borderRadius: 6, fontSize: 12 }}
              aria-label="智能分析"
            >
              智能分析
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setCreateVisible(true)}
              size="small"
              style={{ borderRadius: 6, fontSize: 12, background: '#6C5CE7', borderColor: '#6C5CE7' }}
              aria-label="录入情报"
            >
              录入情报
            </Button>
          </Space>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div style={{
            padding: '14px 18px',
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#E8E9ED', marginBottom: 10, fontFamily: 'var(--font-body)' }}>
              威胁等级分布
            </div>
            {threatPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <BarChart data={threatPieData} layout="vertical" margin={{ top: 4, right: 16, left: 48, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} vertical={false} />
                  <XAxis type="number" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} width={44} />
                  <RTooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  <Bar dataKey="value" barSize={14} radius={[0, 6, 6, 0]} isAnimationActive={false} shape={<StaggeredBarShape layout="horizontal" radius={[0, 6, 6, 0]} />}>
                    {threatPieData.map((_, i) => <Cell key={i} fill={['#7C7F9A', '#F97316', '#6C5CE7', '#22C55E'][i % 4]} fillOpacity={0.85} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 150, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </div>
            )}
          </div>

          <div style={{
            padding: '14px 18px',
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#E8E9ED', marginBottom: 10, fontFamily: 'var(--font-body)' }}>
              来源分布
            </div>
            {sourceBarData.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <BarChart data={sourceBarData} barCategoryGap="20%" barGap={4}>
                  <XAxis dataKey="name" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} width={32} />
                  <RTooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="#6C5CE7" barSize={14} radius={[4, 4, 0, 0]} name="数量" isAnimationActive={false} shape={<StaggeredBarShape radius={[4, 4, 0, 0]} />} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 150, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </div>
            )}
          </div>
        </div>

        <div style={{
          background: 'rgba(20,22,37,0.80)',
          borderRadius: 12,
          border: '1px solid rgba(255,255,255,0.06)',
          boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '12px 18px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}>
            <div style={{ width: 3, height: 14, borderRadius: 2, background: '#6C5CE7' }} />
            <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: 'var(--font-body)' }}>
              情报列表
            </span>
            <span style={{ fontSize: 11, color: '#7C7F9A', fontFamily: 'var(--font-mono)', marginLeft: 4 }}>
              {selectedRowKeys.length > 0 ? `已选 ${selectedRowKeys.length} 条` : ''}
            </span>
          </div>
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
            style={{ fontSize: 13 }}
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
                background: 'rgba(28,31,53,0.5)',
                borderRadius: 8,
                border: '1px solid rgba(255,255,255,0.06)',
              }}>
                <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>
                  情报内容
                </div>
                <div style={{ color: '#E8E9ED', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
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
                  background: 'rgba(28,31,53,0.5)',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <div style={{ fontSize: 12, color: '#F97316', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
                    识别到 {decodeResult.found_terms.length} 个黑话
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {decodeResult.found_terms.map((term, i) => (
                      <div key={`${term.term}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Tag style={{
                          background: '#F9731614',
                          color: '#F97316',
                          border: '1px solid #F9731628',
                          fontSize: 11,
                          borderRadius: 20,
                          padding: '0 8px',
                          lineHeight: '20px',
                        }}>
                          {term.term}
                        </Tag>
                        <span style={{ color: '#7C7F9A' }}>→</span>
                        <span style={{ color: '#E8E9ED', fontSize: 13 }}>{term.meaning}</span>
                      </div>
                    ))}
                  </div>
                  {decodeResult.decoded_text && (
                    <div style={{
                      marginTop: 12,
                      padding: 12,
                      background: 'rgba(28,31,53,0.5)',
                      borderRadius: 8,
                    }}>
                      <div style={{ fontSize: 11, color: '#7C7F9A', fontWeight: 600, marginBottom: 6, letterSpacing: '0.05em' }}>翻译结果</div>
                      <div style={{ color: '#E8E9ED', fontSize: 13, lineHeight: 1.6 }}>
                        {decodeResult.decoded_text}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#7C7F9A' }}>暂无详情数据</div>
          )}
        </Spin>
      </Modal>

      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <LinkOutlined style={{ color: '#00D4FF' }} />
            <span>情报溯源</span>
          </div>
        }
        open={traceVisible}
        onCancel={() => setTraceVisible(false)}
        footer={null}
        width={720}
      >
        <Spin spinning={traceLoading}>
          {traceData ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {!!traceData.source_url && (
                <div style={{
                  padding: 16,
                  background: 'rgba(28,31,53,0.5)',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
                    来源网站
                  </div>
                  {sourcePreview && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                      {!!sourcePreview.favicon_url && (
                        <img
                          src={sourcePreview.favicon_url as string}
                          alt=""
                          style={{ width: 20, height: 20, borderRadius: 4 }}
                          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
                        />
                      )}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {(sourcePreview.title as string) || (traceData.source_url as string)}
                        </div>
                        {!!sourcePreview.site_name && (
                          <div style={{ fontSize: 11, color: '#7C7F9A', marginTop: 2 }}>{sourcePreview.site_name as string}</div>
                        )}
                      </div>
                    </div>
                  )}
                  {!!sourcePreview?.description && (
                    <div style={{ fontSize: 12, color: '#7C7F9A', lineHeight: 1.6, marginBottom: 12 }}>
                      {sourcePreview.description as string}
                    </div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <a
                      href={traceData.source_url as string}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 6,
                        padding: '6px 14px',
                        background: 'linear-gradient(135deg, #6C5CE7, #00D4FF)',
                        borderRadius: 6,
                        color: '#FFFFFF',
                        fontSize: 13,
                        fontWeight: 600,
                        textDecoration: 'none',
                        transition: 'opacity 0.15s ease',
                      }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.opacity = '0.85'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.opacity = '1'; }}
                      aria-label="访问原始网站"
                    >
                      <LinkOutlined /> 访问原始网站
                    </a>
                    {traceData.url_accessible === true && (
                      <Tag style={{ background: '#00E67614', color: '#00E676', border: '1px solid #00E67628', borderRadius: 20, fontSize: 11 }}>网站可访问</Tag>
                    )}
                    {traceData.url_accessible === false && (
                      <Tag style={{ background: '#FF475714', color: '#FF4757', border: '1px solid #FF475728', borderRadius: 20, fontSize: 11 }}>网站不可访问</Tag>
                    )}
                    {!!traceData.source_type && (
                      <Tag style={{ background: '#6C5CE714', color: '#6C5CE7', border: '1px solid #6C5CE728', borderRadius: 20, fontSize: 11 }}>
                        {traceData.source_type as string}
                      </Tag>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 8, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {traceData.source_url as string}
                  </div>
                </div>
              )}

              {!traceData.source_url && (
                <div style={{
                  padding: 16,
                  background: 'rgba(28,31,53,0.5)',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center',
                  color: '#7C7F9A',
                  fontSize: 13,
                }}>
                  该情报没有关联的来源URL
                </div>
              )}

              {!!traceData.content_preview && (
                <div style={{
                  padding: 16,
                  background: 'rgba(28,31,53,0.5)',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>
                    内容预览
                  </div>
                  <div style={{ color: '#E8E9ED', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                    {traceData.content_preview as string}
                  </div>
                </div>
              )}

              {Array.isArray(traceData.chain_stages) && (traceData.chain_stages as Array<Record<string, unknown>>).length > 0 && (
                <div style={{
                  padding: 16,
                  background: 'rgba(28,31,53,0.5)',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 12, letterSpacing: '0.05em' }}>
                    处理链路
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                    {(traceData.chain_stages as Array<Record<string, unknown>>).map((stage, i) => (
                      <div key={String(stage.stage || i)} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <div style={{
                            width: 10, height: 10, borderRadius: '50%',
                            background: i === 0 ? '#00D4FF' : i === (traceData.chain_stages as Array<unknown>).length - 1 ? '#00E676' : '#6C5CE7',
                          }} />
                          {i < (traceData.chain_stages as Array<unknown>).length - 1 && (
                            <div style={{ width: 2, height: 28, background: 'rgba(255,255,255,0.1)' }} />
                          )}
                        </div>
                        <div style={{ flex: 1 }}>
                          <span style={{ color: '#E8E9ED', fontSize: 13, fontWeight: 500 }}>{stage.stage as string}</span>
                          {!!stage.timestamp && (
                            <span style={{ color: 'var(--text-2)', fontSize: 11, marginLeft: 8, fontFamily: 'var(--font-mono)' }}>
                              {new Date(stage.timestamp as string).toLocaleString('zh-CN')}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {!!traceData.collected_at && (
                <div style={{ fontSize: 11, color: 'var(--text-2)', textAlign: 'right' }}>
                  采集时间: {new Date(traceData.collected_at as string).toLocaleString('zh-CN')}
                </div>
              )}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: '#7C7F9A' }}>暂无溯源数据</div>
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
          <Form.Item name="source" label={<span style={{ color: '#E8E9ED', fontWeight: 500 }}>来源渠道</span>}
            extra="填写情报来源，如暗网论坛、社交媒体、人工采集等">
            <Input placeholder="如：暗网论坛 / 社交媒体 / 人工采集" />
          </Form.Item>
          <Form.Item name="source_url" label={<span style={{ color: '#E8E9ED', fontWeight: 500 }}>来源URL</span>}
            extra="原始情报的来源链接">
            <Input placeholder="https://..." />
          </Form.Item>
          <Form.Item
            name="content"
            label={<span style={{ color: '#E8E9ED', fontWeight: 500 }}>情报内容</span>}
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
              background: '#6C5CE710',
              borderRadius: 8,
              fontSize: 12,
              color: '#6C5CE7',
              fontFamily: 'var(--font-body)',
            }}>
              已选择 {selectedRowKeys.length} 条情报，内容已合并
            </div>
          )}
          <div>
            <div style={{ fontSize: 12, color: '#7C7F9A', marginBottom: 4, fontWeight: 500 }}>
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
                <div style={{ padding: 16, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>清洗结果</div>
                  <div style={{ color: '#E8E9ED', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                    {String(pipelineResult.cleaned_text || pipelineResult.result || pipelineResult.data || '')}
                  </div>
                  {(pipelineResult.removed_count != null || pipelineResult.entities_found != null) && (
                    <div style={{ display: 'flex', gap: 16, marginTop: 12, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                      {pipelineResult.removed_count != null && (
                        <div><span style={{ color: '#7C7F9A', fontSize: 12 }}>移除项: </span><span style={{ fontWeight: 600, color: '#E8E9ED' }}>{String(pipelineResult.removed_count)}</span></div>
                      )}
                      {pipelineResult.entities_found != null && (
                        <div><span style={{ color: '#7C7F9A', fontSize: 12 }}>发现实体: </span><span style={{ fontWeight: 600, color: '#E8E9ED' }}>{String(pipelineResult.entities_found)}</span></div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <>
                  {pipelineResult.threat_categories && Array.isArray(pipelineResult.threat_categories) && pipelineResult.threat_categories.length > 0 && (
                    <div style={{ padding: 16, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>威胁分类</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {(pipelineResult.threat_categories as Array<Record<string, unknown>>).map((cat: Record<string, unknown>, i: number) => (
                          <Tag key={i} style={{ background: '#EF444414', color: '#EF4444', border: '1px solid #EF444428', borderRadius: 20, padding: '2px 10px' }}>
                            {String(cat.name || cat.category || cat)} {cat.confidence != null ? `(${Number(Number(cat.confidence) * 100).toFixed(0)}%)` : ''}
                          </Tag>
                        ))}
                      </div>
                    </div>
                  )}
                  {pipelineResult.entities && Array.isArray(pipelineResult.entities) && pipelineResult.entities.length > 0 && (
                    <div style={{ padding: 16, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>提取实体 ({(pipelineResult.entities as Array<unknown>).length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {(pipelineResult.entities as Array<Record<string, unknown>>).slice(0, 20).map((ent: Record<string, unknown>, i: number) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                            <Tag style={{ background: '#6C5CE714', color: '#6C5CE7', border: '1px solid #6C5CE728', borderRadius: 4, fontSize: 11, padding: '0 6px' }}>
                              {String(ent.type || ent.entity_type || '未知')}
                            </Tag>
                            <span style={{ color: '#E8E9ED' }}>{String(ent.value || ent.text || '')}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {pipelineResult.analysis_summary && (
                    <div style={{ padding: 16, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>分析摘要</div>
                      <div style={{ color: '#E8E9ED', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
                        {String(pipelineResult.analysis_summary)}
                      </div>
                    </div>
                  )}
                  {pipelineResult.confidence != null && (
                    <div style={{ padding: 12, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 16 }}>
                      <div><span style={{ color: '#7C7F9A', fontSize: 12 }}>置信度: </span><span style={{ fontWeight: 600, color: '#E8E9ED' }}>{Number(Number(pipelineResult.confidence) * 100).toFixed(1)}%</span></div>
                      {pipelineResult.threat_level ? (
                        <div><span style={{ color: '#7C7F9A', fontSize: 12 }}>威胁等级: </span><span style={{ fontWeight: 600, color: String(pipelineResult.threat_level) === 'critical' || String(pipelineResult.threat_level) === 'high' ? '#EF4444' : String(pipelineResult.threat_level) === 'medium' ? '#F97316' : '#22C55E' }}>{String(pipelineResult.threat_level)}</span></div>
                      ) : null}
                    </div>
                  )}
                  {pipelineResult.crime_patterns && Array.isArray(pipelineResult.crime_patterns) && pipelineResult.crime_patterns.length > 0 && (
                    <div style={{ padding: 16, background: 'rgba(28,31,53,0.5)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div style={{ fontSize: 12, color: '#7C7F9A', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>犯罪模式</div>
                      {(pipelineResult.crime_patterns as Array<Record<string, unknown>>).map((p: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ padding: '8px 0', borderBottom: i < (pipelineResult.crime_patterns as Array<unknown>).length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none' }}>
                          <div style={{ fontWeight: 500, color: '#E8E9ED', fontSize: 13 }}>{String(p.name || p.pattern || '')}</div>
                          {p.description ? <div style={{ color: '#7C7F9A', fontSize: 12, marginTop: 4 }}>{String(p.description)}</div> : null}
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
