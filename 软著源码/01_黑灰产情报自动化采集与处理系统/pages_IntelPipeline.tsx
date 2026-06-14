import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Table, Tag, Input, Select, Button, Space, Modal, Spin, Empty, Progress,
  Tabs, Tooltip, Switch, Upload, Popconfirm, message as antMessage,
} from 'antd';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell,
} from 'recharts';
import {
  ThunderboltOutlined, CloudUploadOutlined, DatabaseOutlined,
  ScheduleOutlined, SearchOutlined, ExperimentOutlined,
  DeleteOutlined, PlayCircleOutlined, PlusOutlined,
  ReloadOutlined, EyeOutlined, BookOutlined,
  WarningOutlined, SafetyCertificateOutlined, ApiOutlined,
} from '@ant-design/icons';
import { api, getErrorMessage } from '../services/api';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { useDebounce, useAntdMessage } from '../utils/hooks';

const { TextArea } = Input;

const INTENT_MAP: Record<string, { color: string; label: string; bg: string }> = {
  benign: { color: '#16A34A', label: '正常', bg: '#16A34A14' },
  suspicious: { color: '#EAB308', label: '可疑', bg: '#EAB30814' },
  malicious: { color: '#EA580C', label: '恶意', bg: '#EA580C14' },
  critical: { color: '#DC2626', label: '高危', bg: '#DC262614' },
};

const THREAT_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: '#DC2626', label: '严重' },
  high: { color: '#EA580C', label: '高危' },
  medium: { color: '#EAB308', label: '中危' },
  low: { color: '#16A34A', label: '低危' },
  info: { color: '#64748B', label: '信息' },
};

const SOURCE_TYPE_MAP: Record<string, string> = {
  forum: '论坛', wechat: '微信', telegram: 'Telegram',
  darkweb: '暗网', commercial: '商业', manual: '手动',
};

const PRIORITY_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: '#DC2626', label: '紧急' },
  high: { color: '#EA580C', label: '高' },
  medium: { color: '#EAB308', label: '中' },
  low: { color: '#16A34A', label: '低' },
};

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

const IntelPipeline: React.FC = () => {
  const msg = useAntdMessage();
  const [activeTab, setActiveTab] = useState('analyze');

  const [analyzeText, setAnalyzeText] = useState('');
  const [analyzeSource, setAnalyzeSource] = useState('manual');
  const [useLlm, setUseLlm] = useState(true);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [batchAnalyzing, setBatchAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState<Record<string, unknown> | null>(null);

  const [pipelineStats, setPipelineStats] = useState<Record<string, unknown> | null>(null);
  const [schedulerStats, setSchedulerStats] = useState<Record<string, unknown> | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);

  const [sources, setSources] = useState<Array<Record<string, unknown>>>([]);
  const [sourcesLoading, setSourcesLoading] = useState(false);
  const [sourceModalVisible, setSourceModalVisible] = useState(false);
  const [sourceForm, setSourceForm] = useState<Record<string, unknown>>({});

  const [scenarios, setScenarios] = useState<Array<Record<string, unknown>>>([]);
  const [slangData, setSlangData] = useState<Array<Record<string, unknown>>>([]);
  const [slangKeyword, setSlangKeyword] = useState('');
  const [slangLoading, setSlangLoading] = useState(false);

  const [batchItems, setBatchItems] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState<Record<string, unknown> | null>(null);

  const [historyData, setHistoryData] = useState<Array<Record<string, unknown>>>([]);

  const debouncedSlangKeyword = useDebounce(slangKeyword, 400);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    const [pRes, sRes] = await Promise.allSettled([
      api.intelPipeline.getPipelineStats(),
      api.intelPipeline.getSchedulerStats(),
    ]);
    if (pRes.status === 'fulfilled') setPipelineStats(pRes.value?.data as Record<string, unknown> ?? null);
    if (sRes.status === 'fulfilled') setSchedulerStats(sRes.value?.data as Record<string, unknown> ?? null);
    setStatsLoading(false);
  }, []);

  const fetchSources = useCallback(async () => {
    setSourcesLoading(true);
    try {
      const res = await api.intelPipeline.listSources();
      setSources(Array.isArray(res?.data) ? res.data : []);
    } catch { /* ignore */ }
    setSourcesLoading(false);
  }, []);

  const fetchScenarios = useCallback(async () => {
    try {
      const res = await api.intelPipeline.getCheatingScenarios();
      setScenarios(Array.isArray(res?.data) ? res.data : []);
    } catch { /* ignore */ }
  }, []);

  const fetchSlang = useCallback(async (keyword?: string) => {
    setSlangLoading(true);
    try {
      const res = await api.intelPipeline.getSlangDictionary(keyword || undefined);
      setSlangData(Array.isArray(res?.data) ? res.data : []);
    } catch { /* ignore */ }
    setSlangLoading(false);
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await api.intelPipeline.getCollectionHistory(20);
      setHistoryData(Array.isArray(res?.data) ? res.data : []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchSources();
    fetchScenarios();
    fetchSlang();
    fetchHistory();
  }, [fetchStats, fetchSources, fetchScenarios, fetchSlang, fetchHistory]);

  useEffect(() => {
    fetchSlang(debouncedSlangKeyword);
  }, [debouncedSlangKeyword, fetchSlang]);

  const handleAnalyze = async () => {
    if (!analyzeText.trim()) {
      msg.warning('请输入情报内容');
      return;
    }
    setAnalyzeLoading(true);
    setAnalyzing(true);
    setAnalyzeResult(null);
    try {
      const res = await api.intelPipeline.analyzeSingle(analyzeText, analyzeSource, useLlm);
      if (res?.status === 'error') {
        msg.error(String(res.detail || '分析失败'));
      } else {
        setAnalyzeResult(res?.data as Record<string, unknown> ?? null);
        msg.success('分析完成');
        fetchStats();
      }
    } catch (err) {
      msg.error(getErrorMessage(err));
    } finally {
      setAnalyzeLoading(false);
      setAnalyzing(false);
    }
  };

  const handleBatchAnalyze = async () => {
    if (!window.confirm('确认对选中情报执行批量分析？')) return;
    if (!batchItems.trim()) {
      msg.warning('请输入批量情报内容');
      return;
    }
    const items = batchItems.split('\n').filter(l => l.trim()).map((line, i) => ({
      content: line.trim(),
      source: 'batch_manual',
      id: `batch_${i}_${Date.now()}`,
    }));
    if (items.length === 0) {
      msg.warning('未检测到有效内容');
      return;
    }
    setBatchLoading(true);
    setBatchAnalyzing(true);
    setBatchResult(null);
    try {
      const res = await api.intelPipeline.analyzeBatch(items, useLlm);
      setBatchResult(res?.data as Record<string, unknown> ?? null);
      msg.success('批量分析完成');
      fetchStats();
    } catch (err) {
      msg.error(getErrorMessage(err));
    } finally {
      setBatchLoading(false);
      setBatchAnalyzing(false);
    }
  };

  const handleTriggerSource = async (sourceId: string) => {
    try {
      await api.intelPipeline.triggerSource(sourceId);
      msg.success('采集已触发');
      fetchSources();
      fetchStats();
    } catch (err) {
      msg.error(getErrorMessage(err));
    }
  };

  const handleTriggerAll = async () => {
    try {
      await api.intelPipeline.triggerAll();
      msg.success('全部采集源已触发');
      fetchSources();
      fetchStats();
    } catch (err) {
      msg.error(getErrorMessage(err));
    }
  };

  const handleDeleteSource = async (sourceId: string) => {
    try {
      await api.intelPipeline.deleteSource(sourceId);
      msg.success('数据源已删除');
      fetchSources();
    } catch (err) {
      msg.error(getErrorMessage(err));
    }
  };

  const handleCreateSource = async () => {
    if (!sourceForm.source_id || !sourceForm.name || !sourceForm.source_type) {
      msg.warning('请填写必填字段');
      return;
    }
    try {
      const payload: Record<string, unknown> = { ...sourceForm };
      if (sourceForm.keywords_text && typeof sourceForm.keywords_text === 'string') {
        payload.keywords = (sourceForm.keywords_text as string).split(/[,，]/).map(k => k.trim()).filter(Boolean);
        delete payload.keywords_text;
      } else {
        payload.keywords = [];
        delete payload.keywords_text;
      }
      await api.intelPipeline.createSource(payload);
      msg.success('采集源已创建');
      setSourceModalVisible(false);
      setSourceForm({});
      fetchSources();
    } catch (err) {
      msg.error(getErrorMessage(err));
    }
  };

  const handleFileImport = async (file: File) => {
    try {
      const res = await api.intelPipeline.importFile(file);
      msg.success(`导入成功: ${res?.filename || file.name}`);
      fetchStats();
    } catch (err) {
      msg.error(getErrorMessage(err));
    }
    return false;
  };

  const pStats = pipelineStats as Record<string, unknown> | null;
  const sStats = schedulerStats as Record<string, unknown> | null;

  const totalProcessed = Number(pStats?.total_processed ?? 0);
  const totalDuplicates = Number(pStats?.total_duplicates ?? 0);
  const totalAll = totalProcessed + totalDuplicates;

  const statItems = [
    { label: '已处理', value: totalAll, icon: <DatabaseOutlined style={{ fontSize: 18, color: '#1E40AF' }} />, color: '#1E40AF' },
    { label: '去重数', value: totalDuplicates, icon: <SafetyCertificateOutlined style={{ fontSize: 18, color: '#0D9488' }} />, color: '#0D9488' },
    { label: '高危数', value: Number(pStats?.total_high_risk ?? 0), icon: <WarningOutlined style={{ fontSize: 18, color: '#DC2626' }} />, color: '#DC2626' },
    { label: '采集源', value: Number(sStats?.total_sources ?? sources.length), icon: <ApiOutlined style={{ fontSize: 18, color: '#7C3AED' }} />, color: '#7C3AED' },
  ];

  const intentDistribution = Object.entries(
    (pStats?.by_intent as Record<string, number>) ?? {}
  ).map(([name, value]) => ({
    name: INTENT_MAP[name]?.label || name,
    value,
    color: INTENT_MAP[name]?.color || '#64748B',
  }));

  const renderRiskScore = (score: number) => {
    const pct = Math.round(score * 100);
    const color = pct >= 70 ? '#DC2626' : pct >= 40 ? '#EA580C' : pct >= 20 ? '#EAB308' : '#16A34A';
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Progress percent={pct} size="small" strokeColor={color} showInfo={false} style={{ width: 80, marginBottom: 0 }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color }}>{pct}%</span>
      </div>
    );
  };

  const renderAnalyzeResult = () => {
    if (!analyzeResult) return null;
    const r = analyzeResult;
    const intentLevel = String(r.intent_level || 'benign');
    const riskScore = Number(r.risk_score ?? 0);
    const qualityScore = Number(r.quality_score ?? 0);
    const entities = Array.isArray(r.entities) ? r.entities : [];
    const cheatingScenarios = Array.isArray(r.cheating_scenarios) ? r.cheating_scenarios : [];
    const threatCategories = Array.isArray(r.threat_categories) ? r.threat_categories : [];
    const intentIndicators = Array.isArray(r.intent_indicators) ? r.intent_indicators : [];
    const isDuplicate = Boolean(r.is_duplicate);

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>
        {isDuplicate && (
          <div style={{ padding: '10px 16px', background: '#EAB30814', borderRadius: 10, border: '1px solid #EAB30828', display: 'flex', alignItems: 'center', gap: 8 }}>
            <SafetyCertificateOutlined style={{ color: '#EAB308' }} />
            <span style={{ color: '#EAB308', fontSize: 13, fontWeight: 500 }}>此情报与已有记录重复（相似来源: {String(r.duplicate_of || '未知')}），以下为基于规则的分析结果</span>
          </div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0', textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: '#94A3B8', fontWeight: 600, letterSpacing: '0.05em', marginBottom: 8 }}>意图等级</div>
            <Tag style={{
              background: INTENT_MAP[intentLevel]?.bg || '#64748B14',
              color: INTENT_MAP[intentLevel]?.color || '#64748B',
              border: `1px solid ${INTENT_MAP[intentLevel]?.color || '#64748B'}28`,
              fontSize: 14, fontWeight: 700, borderRadius: 20, padding: '4px 16px',
            }}>
              {INTENT_MAP[intentLevel]?.label || intentLevel}
            </Tag>
          </div>
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0', textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: '#94A3B8', fontWeight: 600, letterSpacing: '0.05em', marginBottom: 8 }}>风险评分</div>
            {renderRiskScore(riskScore)}
          </div>
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0', textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: '#94A3B8', fontWeight: 600, letterSpacing: '0.05em', marginBottom: 8 }}>质量评分</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 20, fontWeight: 700, color: '#0F172A' }}>
              {Math.round(qualityScore * 100)}%
            </span>
          </div>
        </div>

        {r.cleaned_content ? (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>清洗后内容</div>
            <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
              {String(r.cleaned_content)}
            </div>
          </div>
        ) : null}

        {cheatingScenarios.length > 0 && (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#DC2626', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
              <WarningOutlined style={{ marginRight: 4 }} />作弊场景 ({cheatingScenarios.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {cheatingScenarios.map((s: unknown, i: number) => {
                const sc = s as Record<string, unknown>;
                return (
                  <Tag key={i} style={{
                    background: '#DC262614', color: '#DC2626',
                    border: '1px solid #DC262628', borderRadius: 20, padding: '2px 12px', fontSize: 12,
                  }}>
                    {String(sc.label || sc.scenario_id || sc)}
                  </Tag>
                );
              })}
            </div>
          </div>
        )}

        {threatCategories.length > 0 && (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>威胁分类</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {threatCategories.map((c: unknown, i: number) => {
                const cat = c as Record<string, unknown>;
                return (
                  <Tag key={i} style={{
                    background: '#EA580C14', color: '#EA580C',
                    border: '1px solid #EA580C28', borderRadius: 20, padding: '2px 12px', fontSize: 12,
                  }}>
                    {String(cat.category_label || cat.name || cat.category || cat)}
                  </Tag>
                );
              })}
            </div>
          </div>
        )}

        {entities.length > 0 && (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#2563EB', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
              关键实体 ({entities.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {entities.slice(0, 30).map((e: unknown, i: number) => {
                const ent = e as Record<string, unknown>;
                const typeColor: Record<string, string> = {
                  url: '#2563EB', account: '#7C3AED', crypto: '#EA580C', crypto_address: '#EA580C',
                  tool: '#DC2626', slang: '#EAB308', contact: '#0D9488',
                  organization: '#1E40AF', ip: '#64748B', email: '#0D9488', phone: '#0D9488',
                };
                const et = String(ent.type || ent.entity_type || 'unknown');
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                    <Tag style={{
                      background: `${typeColor[et] || '#64748B'}14`,
                      color: typeColor[et] || '#64748B',
                      border: `1px solid ${typeColor[et] || '#64748B'}28`,
                      borderRadius: 4, fontSize: 11, padding: '0 6px', minWidth: 56, textAlign: 'center',
                    }}>
                      {et}
                    </Tag>
                    <span style={{ color: '#334155', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      {String(ent.value || ent.text || '')}
                    </span>
                    {Boolean((ent.metadata as Record<string, unknown>)?.meaning || ent.meaning) && (
                      <span style={{ color: '#94A3B8', fontSize: 12 }}>— {String((ent.metadata as Record<string, unknown>)?.meaning || ent.meaning)}</span>
                    )}
                  </div>
                );
              })}
              {entities.length > 30 && (
                <div style={{ color: '#94A3B8', fontSize: 12, textAlign: 'center', paddingTop: 4 }}>
                  ...还有 {entities.length - 30} 个实体
                </div>
              )}
            </div>
          </div>
        )}

        {intentIndicators.length > 0 && (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#EA580C', fontWeight: 600, marginBottom: 10, letterSpacing: '0.05em' }}>
              意图指标 ({intentIndicators.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {intentIndicators.map((ind: unknown, i: number) => {
                const indicator = ind as Record<string, unknown>;
                return (
                  <Tag key={i} style={{
                    background: '#EA580C14', color: '#EA580C',
                    border: '1px solid #EA580C28', borderRadius: 4, fontSize: 11, padding: '2px 8px',
                  }}>
                    {String(indicator.label || indicator.pattern || indicator)}
                  </Tag>
                );
              })}
            </div>
          </div>
        )}

        {r.summary ? (
          <div style={{ padding: 16, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, color: '#64748B', fontWeight: 600, marginBottom: 8, letterSpacing: '0.05em' }}>分析摘要</div>
            <div style={{ color: '#334155', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
              {String(r.summary)}
            </div>
          </div>
        ) : null}
      </div>
    );
  };

  const renderBatchResult = () => {
    if (!batchResult) return null;
    const r = batchResult;
    const itemResults = Array.isArray(r.item_results) ? r.item_results : [];

    return (
      <div style={{ marginTop: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
          {[
            { label: '总输入', value: Number(r.total_input ?? 0), color: '#1E40AF' },
            { label: '已处理', value: Number(r.total_processed ?? 0), color: '#16A34A' },
            { label: '去重数', value: Number(r.total_duplicates ?? 0), color: '#0D9488' },
            { label: '高危数', value: Number(r.total_high_risk ?? 0), color: '#DC2626' },
          ].map(item => (
            <div key={item.label} style={{ padding: 14, background: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0', textAlign: 'center' }}>
              <div style={{ fontSize: 11, color: '#94A3B8', fontWeight: 600, marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontSize: 22, fontFamily: 'var(--font-mono)', fontWeight: 700, color: item.color }}>{item.value}</div>
            </div>
          ))}
        </div>

        {itemResults.length > 0 && (
          <div style={{ border: '1px solid #E2E8F0', borderRadius: 10, overflow: 'hidden' }}>
            <Table
              dataSource={itemResults.slice(0, 50)}
              columns={[
                {
                  title: '内容', dataIndex: 'original_content', width: 200,
                  render: (v: unknown, record: Record<string, unknown>) => (
                    <div>
                      <span style={{ color: '#334155', fontSize: 12 }}>
                        {v ? (String(v).length > 50 ? String(v).slice(0, 50) + '...' : String(v)) : '—'}
                      </span>
                      {record.is_duplicate ? (
                        <Tag style={{ marginLeft: 4, background: '#EAB30814', color: '#EAB308', border: '1px solid #EAB30828', borderRadius: 20, padding: '0 4px', fontSize: 10 }}>
                          重复
                        </Tag>
                      ) : null}
                    </div>
                  ),
                },
                {
                  title: '意图', dataIndex: 'intent_level', width: 80,
                  render: (v: string) => {
                    const cfg = INTENT_MAP[v];
                    return cfg ? (
                      <Tag style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}28`, borderRadius: 20, padding: '0 8px', fontSize: 11 }}>
                        {cfg.label}
                      </Tag>
                    ) : <span style={{ color: '#94A3B8' }}>—</span>;
                  },
                },
                {
                  title: '风险', dataIndex: 'risk_score', width: 120,
                  render: (v: number) => renderRiskScore(v ?? 0),
                },
                {
                  title: '实体', dataIndex: 'entities', width: 60, align: 'center' as const,
                  render: (v: unknown[]) => (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#334155' }}>
                      {Array.isArray(v) ? v.length : 0}
                    </span>
                  ),
                },
                {
                  title: '作弊场景', dataIndex: 'cheating_scenarios', width: 160,
                  render: (v: unknown[]) => {
                    if (!Array.isArray(v) || v.length === 0) return <span style={{ color: '#94A3B8' }}>—</span>;
                    return (
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {v.slice(0, 3).map((s: unknown, i: number) => {
                          const sc = s as Record<string, unknown>;
                          return (
                            <Tag key={i} style={{ background: '#DC262614', color: '#DC2626', border: '1px solid #DC262628', borderRadius: 20, padding: '0 6px', fontSize: 10 }}>
                              {String(sc.label || sc.scenario_id || sc)}
                            </Tag>
                          );
                        })}
                        {v.length > 3 && <Tag style={{ fontSize: 10, color: '#94A3B8' }}>+{v.length - 3}</Tag>}
                      </div>
                    );
                  },
                },
              ]}
              rowKey={(record) => `batch_${record.batch_id || Math.random().toString(36).slice(2)}`}
              size="small"
              pagination={false}
            />
          </div>
        )}
      </div>
    );
  };

  const sourceColumns = [
    {
      title: '名称', dataIndex: 'name', width: 160,
      render: (v: string) => <span style={{ fontWeight: 500, color: '#0F172A', fontSize: 13 }}>{v}</span>,
    },
    {
      title: '类型', dataIndex: 'source_type', width: 100,
      render: (v: string) => (
        <Tag style={{ background: '#2563EB14', color: '#2563EB', border: '1px solid #2563EB28', borderRadius: 4, fontSize: 11 }}>
          {SOURCE_TYPE_MAP[v] || v}
        </Tag>
      ),
    },
    {
      title: '优先级', dataIndex: 'priority', width: 80,
      render: (v: string) => {
        const cfg = PRIORITY_MAP[v];
        return cfg ? (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, borderRadius: 20, padding: '0 8px', fontSize: 11 }}>
            {cfg.label}
          </Tag>
        ) : <span style={{ color: '#94A3B8' }}>{v}</span>;
      },
    },
    {
      title: '状态', dataIndex: 'status', width: 90,
      render: (v: string) => {
        const statusCfg: Record<string, { color: string; label: string }> = {
          active: { color: '#16A34A', label: '运行中' },
          paused: { color: '#EAB308', label: '已暂停' },
          disabled: { color: '#DC2626', label: '已禁用' },
          error: { color: '#DC2626', label: '异常' },
        };
        const cfg = statusCfg[v] || { color: '#64748B', label: v };
        return (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, borderRadius: 20, padding: '0 8px', fontSize: 11 }}>
            {cfg.label}
          </Tag>
        );
      },
    },
    {
      title: '间隔', dataIndex: 'interval_minutes', width: 80, align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#334155' }}>
          {v ? `${v}min` : '手动'}
        </span>
      ),
    },
    {
      title: '已采集', dataIndex: 'total_collected', width: 80, align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#334155' }}>{v ?? 0}</span>
      ),
    },
    {
      title: '错误', dataIndex: 'consecutive_errors', width: 70, align: 'center' as const,
      render: (v: number) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: v > 0 ? '#DC2626' : '#94A3B8' }}>
          {v ?? 0}
        </span>
      ),
    },
    {
      title: '操作', width: 140,
      render: (_: unknown, record: Record<string, unknown>) => (
        <Space size={4}>
          <Tooltip title="触发采集">
            <Button type="link" size="small" icon={<PlayCircleOutlined />}
              onClick={() => handleTriggerSource(String(record.source_id))}
              style={{ color: '#16A34A', fontSize: 12, padding: 0 }} />
          </Tooltip>
          <Popconfirm title="确认删除此数据源？" onConfirm={() => handleDeleteSource(String(record.source_id))} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
            <Tooltip title="删除">
              <Button type="link" size="small" icon={<DeleteOutlined />}
                style={{ color: '#DC2626', fontSize: 12, padding: 0 }} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const scenarioColumns = [
    {
      title: '场景', dataIndex: 'label', width: 140,
      render: (v: string) => <span style={{ fontWeight: 500, color: '#0F172A', fontSize: 13 }}>{v}</span>,
    },
    {
      title: 'ID', dataIndex: 'scenario_id', width: 120,
      render: (v: string) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#64748B' }}>{v}</span>,
    },
    {
      title: '严重等级', dataIndex: 'severity', width: 100,
      render: (v: string) => {
        const cfg = THREAT_MAP[v] || { color: '#64748B', label: v };
        return (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, borderRadius: 20, padding: '0 8px', fontSize: 11 }}>
            {cfg.label}
          </Tag>
        );
      },
    },
    {
      title: '关键词数', dataIndex: 'keyword_count', width: 80, align: 'center' as const,
      render: (v: number) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{v}</span>,
    },
    {
      title: '关键词', dataIndex: 'keywords',
      render: (v: string[]) => (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {(v || []).slice(0, 8).map((kw, i) => (
            <Tag key={i} style={{ background: '#F1F5F9', color: '#64748B', borderRadius: 4, fontSize: 11, padding: '0 6px' }}>
              {kw}
            </Tag>
          ))}
          {v && v.length > 8 && <Tag style={{ fontSize: 11, color: '#94A3B8' }}>+{v.length - 8}</Tag>}
        </div>
      ),
    },
  ];

  const slangColumns = [
    {
      title: '黑话', dataIndex: 'slang', width: 140,
      render: (v: string) => (
        <Tag style={{ background: '#EAB30814', color: '#EAB308', border: '1px solid #EAB30828', borderRadius: 4, fontSize: 12, padding: '2px 8px', fontWeight: 600 }}>
          {v}
        </Tag>
      ),
    },
    {
      title: '释义', dataIndex: 'meaning',
      render: (v: string) => <span style={{ color: '#334155', fontSize: 13 }}>{v}</span>,
    },
  ];

  return (
    <div style={{ minHeight: '100%', padding: 0, background: '#F8FAFC', overflowX: 'hidden' }}>
      <div style={{ padding: '32px 32px 8px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 600, fontFamily: 'var(--font-body)', color: '#0F172A', letterSpacing: '-0.025em', marginBottom: 4, lineHeight: 1.2 }}>
            情报流水线
          </h1>
          <p style={{ fontSize: 14, color: '#64748B', margin: 0, fontFamily: 'var(--font-body)' }}>
            自动化情报采集、清洗、去重、分类、实体抽取与风险评分
          </p>
        </div>
        <Space size={8}>
          <Button icon={<ReloadOutlined />} onClick={() => { fetchStats(); fetchSources(); fetchHistory(); }}>
            刷新
          </Button>
        </Space>
      </div>

      <div style={{ padding: '8px 32px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 16 }}>
          {statItems.map((item, idx) => (
            <div key={item.label} style={{
              padding: '20px 24px', background: '#FFFFFF', borderRadius: 12,
              border: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', gap: 14,
              transition: 'all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)', cursor: 'default',
            }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.08)'; }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
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

      {intentDistribution.length > 0 && (
        <div style={{ padding: '0 32px', marginBottom: 16 }}>
          <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16, fontFamily: 'var(--font-body)' }}>
              意图等级分布
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={intentDistribution} layout="vertical" margin={{ top: 4, right: 20, left: 60, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" horizontal={false} vertical={false} />
                <XAxis type="number" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={56} />
                <RTooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                <Bar dataKey="value" barSize={16} radius={[0, 6, 6, 0]} isAnimationActive={false}>
                  {intentDistribution.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div style={{ padding: '0 32px' }}>
        <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
          {
            key: 'analyze',
            label: <span><ThunderboltOutlined style={{ marginRight: 6 }} />情报分析</span>,
            children: (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16 }}>单条分析</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div style={{ display: 'flex', gap: 12 }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>来源</div>
                        <Select value={analyzeSource} onChange={setAnalyzeSource} style={{ width: '100%' }}
                          options={[
                            { label: '手动输入', value: 'manual' },
                            { label: '论坛', value: 'forum' },
                            { label: '微信', value: 'wechat' },
                            { label: 'Telegram', value: 'telegram' },
                            { label: '暗网', value: 'darkweb' },
                            { label: '商业情报', value: 'commercial' },
                          ]}
                        />
                      </div>
                      <div style={{ display: 'flex', alignItems: 'flex-end', paddingBottom: 2 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <Switch size="small" checked={useLlm} onChange={setUseLlm} />
                          <span style={{ fontSize: 12, color: '#64748B' }}>LLM增强</span>
                        </div>
                      </div>
                    </div>
                    <TextArea rows={6} placeholder="输入待分析的情报文本..." value={analyzeText}
                      onChange={e => setAnalyzeText(e.target.value)} />
                    <Button type="primary" block loading={analyzing} onClick={handleAnalyze}
                      icon={<ThunderboltOutlined />}>
                      执行分析
                    </Button>
                  </div>
                </div>

                <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16 }}>批量分析</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div style={{ padding: '8px 12px', background: '#1E40AF10', borderRadius: 8, fontSize: 12, color: '#1E40AF' }}>
                      每行一条情报，系统将自动批量处理
                    </div>
                    <TextArea rows={6} placeholder="每行输入一条情报内容..." value={batchItems}
                      onChange={e => setBatchItems(e.target.value)} />
                    <div style={{ display: 'flex', gap: 8 }}>
                      <Upload beforeUpload={handleFileImport} showUploadList={false} accept=".json,.jsonl,.csv,.txt">
                        <Button icon={<CloudUploadOutlined />}>导入文件</Button>
                      </Upload>
                      <Button type="primary" loading={batchAnalyzing} onClick={handleBatchAnalyze}
                        icon={<ExperimentOutlined />} style={{ flex: 1 }}>
                        批量分析
                      </Button>
                    </div>
                  </div>
                </div>

                {analyzeResult && (
                  <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0', gridColumn: '1 / -1' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>分析结果</div>
                      <Button size="small" type="text" onClick={() => setAnalyzeResult(null)} icon={<DeleteOutlined />} />
                    </div>
                    {renderAnalyzeResult()}
                  </div>
                )}

                {batchResult && (
                  <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0', gridColumn: '1 / -1' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>批量分析结果</div>
                      <Button size="small" type="text" onClick={() => setBatchResult(null)} icon={<DeleteOutlined />} />
                    </div>
                    {renderBatchResult()}
                  </div>
                )}
              </div>
            ),
          },
          {
            key: 'sources',
            label: <span><ScheduleOutlined style={{ marginRight: 6 }} />采集源管理</span>,
            children: (
              <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>采集源列表</div>
                  <Space size={8}>
                    <Button icon={<PlayCircleOutlined />} onClick={handleTriggerAll}>全部触发</Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => { setSourceForm({}); setSourceModalVisible(true); }}>
                      添加采集源
                    </Button>
                  </Space>
                </div>
                <Table
                  dataSource={sources}
                  columns={sourceColumns}
                  rowKey="source_id"
                  loading={sourcesLoading}
                  size="middle"
                  pagination={false}
                />

                {historyData.length > 0 && (
                  <div style={{ marginTop: 24 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 12 }}>采集历史</div>
                    <Table
                      dataSource={historyData}
                      columns={[
                        {
                          title: '周期ID', dataIndex: 'cycle_id', width: 120,
                          render: (v: string) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#64748B' }}>{v || '—'}</span>,
                        },
                        {
                          title: '开始时间', dataIndex: 'started_at', width: 160,
                          render: (v: string) => (
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#64748B' }}>
                              {v ? new Date(v).toLocaleString('zh-CN') : '—'}
                            </span>
                          ),
                        },
                        {
                          title: '状态', dataIndex: 'errors', width: 80,
                          render: (v: number) => {
                            const isError = Number(v ?? 0) > 0;
                            const cfg = isError ? { color: '#EAB308', label: '部分' } : { color: '#16A34A', label: '成功' };
                            return <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, borderRadius: 20, padding: '0 8px', fontSize: 11 }}>{cfg.label}</Tag>;
                          },
                        },
                        {
                          title: '采集源数', dataIndex: 'sources_collected', width: 90, align: 'center' as const,
                          render: (v: number) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{v ?? 0}</span>,
                        },
                        {
                          title: '情报数', dataIndex: 'total_items', width: 80, align: 'center' as const,
                          render: (v: number) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{v ?? 0}</span>,
                        },
                        {
                          title: '错误数', dataIndex: 'errors', width: 80, align: 'center' as const,
                          render: (v: number) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: Number(v ?? 0) > 0 ? '#DC2626' : '#94A3B8' }}>{v ?? 0}</span>,
                        },
                      ]}
                      rowKey="cycle_id"
                      size="small"
                      pagination={{ pageSize: 5 }}
                    />
                  </div>
                )}
              </div>
            ),
          },
          {
            key: 'scenarios',
            label: <span><WarningOutlined style={{ marginRight: 6 }} />作弊场景</span>,
            children: (
              <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16 }}>
                  {scenarios.length}类作弊场景识别规则
                </div>
                <Table
                  dataSource={scenarios}
                  columns={scenarioColumns}
                  rowKey="scenario_id"
                  size="middle"
                  pagination={false}
                />
              </div>
            ),
          },
          {
            key: 'slang',
            label: <span><BookOutlined style={{ marginRight: 6 }} />黑话字典</span>,
            children: (
              <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>
                    黑话术语字典 ({slangData.length})
                  </div>
                  <Input.Search
                    placeholder="搜索黑话..."
                    value={slangKeyword}
                    onChange={e => setSlangKeyword(e.target.value)}
                    style={{ width: 240 }}
                    allowClear
                  />
                </div>
                <Table
                  dataSource={slangData}
                  columns={slangColumns}
                  rowKey={(record) => `slang_${record.id || Math.random().toString(36).slice(2)}`}
                  loading={slangLoading}
                  size="middle"
                  pagination={{ pageSize: 20, showTotal: t => `共 ${t} 条` }}
                />
              </div>
            ),
          },
        ]} />
      </div>

      <Modal
        title="添加采集源"
        open={sourceModalVisible}
        onCancel={() => setSourceModalVisible(false)}
        onOk={handleCreateSource}
        okText="创建"
        width={560}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 8 }}>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>源ID *</div>
            <Input placeholder="如: wechat_monitor" value={String(sourceForm.source_id || '')}
              onChange={e => setSourceForm({ ...sourceForm, source_id: e.target.value })} />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>名称 *</div>
            <Input placeholder="如: 微信公众号监控" value={String(sourceForm.name || '')}
              onChange={e => setSourceForm({ ...sourceForm, name: e.target.value })} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>类型 *</div>
              <Select value={String(sourceForm.source_type || 'forum')} style={{ width: '100%' }}
                onChange={v => setSourceForm({ ...sourceForm, source_type: v })}
                options={[
                  { label: '论坛', value: 'forum' },
                  { label: '微信', value: 'wechat' },
                  { label: 'Telegram', value: 'telegram' },
                  { label: '暗网', value: 'darkweb' },
                  { label: '商业', value: 'commercial' },
                  { label: '手动', value: 'manual' },
                ]}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>优先级</div>
              <Select value={String(sourceForm.priority || 'medium')} style={{ width: '100%' }}
                onChange={v => setSourceForm({ ...sourceForm, priority: v })}
                options={[
                  { label: '紧急', value: 'critical' },
                  { label: '高', value: 'high' },
                  { label: '中', value: 'medium' },
                  { label: '低', value: 'low' },
                ]}
              />
            </div>
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>采集间隔（分钟，0=仅手动）</div>
            <Input type="number" min={0} value={String(sourceForm.interval_minutes ?? 30)}
              onChange={e => setSourceForm({ ...sourceForm, interval_minutes: Number(e.target.value) })} />
          </div>
          <div>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4, fontWeight: 500 }}>关键词（逗号分隔）</div>
            <Input placeholder="如: 跑分,洗钱,四件套" value={String(sourceForm.keywords_text || '')}
              onChange={e => setSourceForm({ ...sourceForm, keywords_text: e.target.value })} />
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default IntelPipeline;
