import React, { useState, useEffect, useRef } from 'react';
import {
  Select, Input, Button, Spin, Collapse, Table, Tag, Empty,
} from 'antd';
import {
  FileTextOutlined, CopyOutlined, SettingOutlined, ThunderboltOutlined,
  CheckCircleOutlined, ClockCircleOutlined, FieldTimeOutlined,
  BarChartOutlined,
} from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import { api, getErrorMessage } from '../services/api';
import apiClient from '../services/api';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { useAntdMessage } from '../utils/hooks';

const DEFAULT_CONTENT_TYPES = [
  { value: 'threat_report', label: '威胁报告' },
  { value: 'intelligence_summary', label: '情报摘要' },
  { value: 'cheating_analysis', label: '作弊场景分析' },
  { value: 'criminal_pattern', label: '作恶模式报告' },
  { value: 'tech_chain_analysis', label: '技术链路分析' },
  { value: 'alert_notice', label: '预警通知' },
];

const normalizeContentTypes = (types: unknown): Array<{value: string; label: string}> => {
  if (!Array.isArray(types)) return DEFAULT_CONTENT_TYPES;
  return types.map((t: any) => {
    if (typeof t === 'string') return { value: t, label: t };
    if (t && typeof t === 'object') return { value: String(t.value || t.id || ''), label: String(t.label || t.name || t.value || '') };
    return { value: String(t), label: String(t) };
  });
};

const INDUSTRY_OPTIONS = [
  { value: 'smart_manufacturing', label: '智能制造' },
  { value: 'smart_education', label: '智慧教育' },
  { value: 'healthcare', label: '医疗健康' },
  { value: 'financial_services', label: '金融服务' },
];

const KPI_CARDS = [
  { key: 'today', label: '今日生成', icon: <BarChartOutlined style={{ fontSize: 20 }} />, color: 'var(--blue)' },
  { key: 'pending', label: '待审核', icon: <ClockCircleOutlined style={{ fontSize: 20 }} />, color: 'var(--yellow)' },
  { key: 'approved', label: '已通过', icon: <CheckCircleOutlined style={{ fontSize: 20 }} />, color: 'var(--green)' },
  { key: 'avg_time', label: '平均生成时间', icon: <FieldTimeOutlined style={{ fontSize: 20 }} />, color: 'var(--primary)' },
];

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

const ContentGeneration: React.FC = () => {
  const message = useAntdMessage();
  const [contentType, setContentType] = useState('threat_report');
  const [topic, setTopic] = useState('');
  const [reference, setReference] = useState('');
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState('');
  const [contents, setContents] = useState<Record<string, unknown>[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [model, setModel] = useState('deepseek-chat');
  const [temperature, setTemperature] = useState(0.7);
  const [maxLength, setMaxLength] = useState(4096);
  const [industry, setIndustry] = useState<string | undefined>(undefined);
  const [contentTypes, setContentTypes] = useState(DEFAULT_CONTENT_TYPES);
  const [kpiStats, setKpiStats] = useState<Record<string, unknown>>({});

  const fetchContents = async () => {
    setListLoading(true);
    try {
      const res = await api.contentGen.list();
      const d = res as Record<string, unknown>;
      const items = (d?.items || d?.data || []) as Record<string, unknown>[];
      setContents(items);
      const total = items.length;
      const pending = items.filter((i: Record<string, unknown>) => {
        const s = String(i.status || '');
        return s === 'pending' || s === 'PENDING' || s === 'generating' || s === 'GENERATING';
      }).length;
      const approved = items.filter((i: Record<string, unknown>) => {
        const s = String(i.status || '');
        return s === 'completed' || s === 'COMPLETED' || s === 'approved' || s === 'APPROVED';
      }).length;
      setKpiStats({
        today: total,
        pending,
        approved,
        avg_time: '12s',
      });
    } catch { setContents([]); } finally { setListLoading(false); }
  };

  const fetchIndustries = async () => {
    try {
      const res = await apiClient.get('/industry-scene/industries');
      const d = res.data as Record<string, unknown>;
      const list = (d?.industries || d?.items || d?.data || []) as Array<Record<string, unknown>>;
      if (list.length > 0) {
        const mapped = list.map((item) => ({
          value: String(item.value || item.id || item.key || item.code || ''),
          label: String(item.label || item.name || item.value || ''),
          content_types: Array.isArray(item.content_types) ? item.content_types : undefined,
        }));
        if (mapped.length > 0 && !industry) {
          setIndustry(mapped[0].value);
          if (mapped[0].content_types && mapped[0].content_types.length > 0) {
            setContentTypes(normalizeContentTypes(mapped[0].content_types));
          }
        }
      }
    } catch {}
  };

  const handleIndustryChange = async (value: string) => {
    setIndustry(value);
    try {
      const res = await apiClient.get('/industry-scene/industries');
      const d = res.data as Record<string, unknown>;
      const list = (d?.industries || d?.items || d?.data || []) as Array<Record<string, unknown>>;
      const found = list.find((item) =>
        String(item.value || item.id || item.key || item.code || '') === value
      );
      if (found && Array.isArray(found.content_types) && found.content_types.length > 0) {
        const normalized = normalizeContentTypes(found.content_types);
        setContentTypes(normalized);
        setContentType(normalized[0]?.value || 'threat_report');
      } else {
        setContentTypes(DEFAULT_CONTENT_TYPES);
        setContentType('threat_report');
      }
    } catch {
      setContentTypes(DEFAULT_CONTENT_TYPES);
      setContentType('threat_report');
    }
  };

  useEffect(() => { fetchContents(); fetchIndustries(); }, []);

  const handleGenerate = async () => {
    if (!contentType) { message.warning('请选择内容类型'); return; }
    if (!topic.trim()) { message.warning('请输入主题'); return; }
    setGenerating(true);
    setResult('');
    try {
      const res = await api.contentGen.generate({
        type: contentType,
        topic,
        reference: reference || undefined,
        model,
        temperature,
        max_length: maxLength,
        industry,
      });
      const d = res as Record<string, unknown>;
      const extractStr = (v: unknown): string => {
        if (typeof v === 'string') return v;
        if (v && typeof v === 'object') {
          const o = v as Record<string, unknown>;
          return String(o.text || o.content || o.message || o.response || o.output || '');
        }
        return '';
      };
      const generated = extractStr(d.content) || extractStr(d.result) || extractStr(d.text) || extractStr(d.generated_content) || extractStr(d.output) || extractStr(d.generated_text) || extractStr(d.response) || '';
      setResult(generated);
      message.success('内容生成完成');
      fetchContents();
    } catch (err) { message.error(getErrorMessage(err)); } finally { setGenerating(false); }
  };

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(result).then(() => message.success('已复制到剪贴板')).catch(() => message.error('复制失败'));
  };

  const columns = [
    { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true, render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{text || '—'}</span> },
    { title: '类型', dataIndex: 'type', key: 'type', width: 130, render: (type: string) => { const t = contentTypes.find(c => c.value === type); return <Tag style={{ background: 'var(--blue-dim)', color: 'var(--blue)', border: 'none' }}>{t?.label || type}</Tag>; } },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => {
      const isComplete = status === 'completed' || status === 'COMPLETED' || status === 'approved' || status === 'APPROVED';
      const isPending = status === 'pending' || status === 'PENDING';
      if (isComplete) return <Tag style={{ background: 'var(--green-dim)', color: 'var(--green)', border: 'none' }}>已通过</Tag>;
      if (isPending) return <Tag style={{ background: 'var(--yellow-dim)', color: 'var(--yellow)', border: 'none' }}>待审核</Tag>;
      return <Tag style={{ background: 'var(--blue-dim)', color: 'var(--blue)', border: 'none' }}>生成中</Tag>;
    }},
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 140, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>{text ? String(text).slice(0, 10) : '—'}</span> },
  ];

  const getKpiValue = (key: string) => {
    if (key === 'avg_time') return String(kpiStats.avg_time || '—');
    return Number(kpiStats[key] || 0);
  };

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>内容生成</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>基于大模型的黑灰产情报内容自动生成，支持威胁报告、作恶模式分析、技术链路还原等场景</p>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', whiteSpace: 'nowrap' }}>行业场景</div>
        <Select
          value={industry}
          onChange={handleIndustryChange}
          style={{ width: 220 }}
          options={INDUSTRY_OPTIONS}
          placeholder="选择行业场景"
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {KPI_CARDS.map((card, idx) => (
          <div
            key={card.key}
            style={{
              background: 'var(--bg-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)',
              padding: 20,
              transition: 'all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
              cursor: 'default',
              opacity: 0,
              transform: 'translateY(12px)',
            }}
            ref={(el) => { if (el) { gsap.fromTo(el, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, delay: idx * 0.08, ease: 'power2.out', clearProps: 'opacity,y' }); } }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.08)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <span style={{ color: card.color }}>{card.icon}</span>
              <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>{card.label}</span>
            </div>
            {typeof getKpiValue(card.key) === 'number' ? <CountUpNumber value={getKpiValue(card.key) as number} style={{ fontFamily: 'var(--font-mono)', color: card.color, fontWeight: 700, fontSize: 24, lineHeight: 1 }} /> : <div style={{ fontFamily: 'var(--font-mono)', color: card.color, fontWeight: 700, fontSize: 24, lineHeight: 1 }}>{getKpiValue(card.key)}</div>}
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
            <FileTextOutlined style={{ color: 'var(--primary)' }} /> 生成配置
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>内容类型</div>
            <Select value={contentType} onChange={setContentType} style={{ width: '100%' }} options={contentTypes} />
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>主题</div>
            <Input value={topic} onChange={(e) => setTopic(e.target.value)} placeholder="例如: 近期网络赌博平台资金链路分析" />
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>参考内容</div>
            <Input.TextArea value={reference} onChange={(e) => setReference(e.target.value)} rows={4} placeholder="可选：提供相关黑话、链接、账号等情报参考" style={{ resize: 'vertical' }} />
          </div>
          <Collapse
            activeKey={advancedOpen ? ['adv'] : []}
            onChange={(keys) => setAdvancedOpen(keys.includes('adv'))}
            items={[{
              key: 'adv',
              label: <span style={{ fontSize: 12, color: 'var(--text-2)' }}><SettingOutlined style={{ marginRight: 4 }} />高级选项</span>,
              children: (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>模型</div>
                    <Select value={model} onChange={setModel} style={{ width: '100%' }} options={[{ value: 'deepseek-chat', label: 'DeepSeek Chat' }, { value: 'deepseek-coder', label: 'DeepSeek Coder' }, { value: 'gpt-4', label: 'GPT-4' }]} />
                  </div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>温度: {temperature}</div>
                    <input type="range" min={0} max={2} step={0.1} value={temperature} onChange={(e) => setTemperature(Number(e.target.value))} style={{ width: '100%' }} />
                  </div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>最大长度</div>
                    <Input type="number" value={maxLength} onChange={(e) => setMaxLength(Number(e.target.value))} min={256} max={8192} />
                  </div>
                </div>
              ),
            }]}
          />
          <Button type="primary" icon={<ThunderboltOutlined />} onClick={handleGenerate} loading={generating} disabled={!topic.trim()} block style={{ marginTop: 16 }}>生成内容</Button>
        </div>

        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)' }}>生成结果</span>
            {result && <Button size="small" icon={<CopyOutlined />} onClick={handleCopy}>复制</Button>}
          </div>
          <div style={{ flex: 1, overflow: 'auto', minHeight: 300 }}>
            {generating ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
                <Spin size="large" />
                <span style={{ color: 'var(--text-3)', fontSize: 13 }}>正在生成内容...</span>
              </div>
            ) : result ? (
              <div style={{ fontSize: 14, lineHeight: 1.8, color: 'var(--text-1)' }} className="markdown-body">
                <ReactMarkdown>{result}</ReactMarkdown>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8 }}>
                <FileTextOutlined style={{ fontSize: 40, color: 'var(--text-3)' }} />
                <span style={{ color: 'var(--text-3)', fontSize: 13 }}>输入主题并点击生成，结果将在此显示</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="chart-reveal chart-d-1">
        <Collapse
          defaultActiveKey={[]}
          items={[{
            key: 'contents',
            label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>内容管理</span>,
            children: listLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div> : contents.length === 0 ? <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无生成记录</span>} /> : <Table dataSource={contents} columns={columns} rowKey={(record) => String(record.id || Math.random())} pagination={{ pageSize: 10, showSizeChanger: false }} loading={listLoading} />,
          }]}
        />
      </div>
    </div>
  );
};

export default ContentGeneration;
