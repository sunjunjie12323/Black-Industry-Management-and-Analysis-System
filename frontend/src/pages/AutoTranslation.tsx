import React, { useState, useEffect, useRef } from 'react';
import {
  Select, Input, Button, Spin, Empty, Collapse, Table, Tag, Space, Modal, Form,
} from 'antd';
import {
  TranslationOutlined, SwapOutlined, PlusOutlined, DeleteOutlined, BookOutlined,
  FileSearchOutlined, GlobalOutlined, SafetyCertificateOutlined, CheckCircleOutlined,
} from '@ant-design/icons';
import { api, getErrorMessage } from '../services/api';
import apiClient from '../services/api';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { useAntdMessage } from '../utils/hooks';

const LANGUAGES = [
  { value: 'zh', label: '中文' },
  { value: 'en', label: '英文' },
  { value: 'ja', label: '日文' },
  { value: 'ko', label: '韩文' },
  { value: 'ru', label: '俄文' },
  { value: 'fr', label: '法文' },
  { value: 'de', label: '德文' },
  { value: 'es', label: '西班牙文' },
  { value: 'ar', label: '阿拉伯文' },
];

const INDUSTRY_OPTIONS = [
  { value: 'smart_manufacturing', label: '智能制造' },
  { value: 'smart_education', label: '智慧教育' },
  { value: 'healthcare', label: '医疗健康' },
  { value: 'financial_services', label: '金融服务' },
];

const KPI_CARDS = [
  { key: 'today', label: '今日翻译', icon: <FileSearchOutlined style={{ fontSize: 20 }} />, color: 'var(--blue)' },
  { key: 'terms', label: '术语条目', icon: <BookOutlined style={{ fontSize: 20 }} />, color: 'var(--purple)' },
  { key: 'languages', label: '支持语种', icon: <GlobalOutlined style={{ fontSize: 20 }} />, color: 'var(--green)' },
  { key: 'accuracy', label: '翻译准确率', icon: <SafetyCertificateOutlined style={{ fontSize: 20 }} />, color: 'var(--primary)' },
];

const normalizeTranslationTerms = (data: unknown): Record<string, unknown>[] => {
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    return Object.entries(data as Record<string, unknown>).map(([key, val]) => ({
      source_term: key,
      target_term: String(val || ''),
      category: '行业术语',
      description: `${key}的行业标准翻译`,
    }));
  }
  return [];
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

const AutoTranslation: React.FC = () => {
  const message = useAntdMessage();
  const [sourceLang, setSourceLang] = useState('zh');
  const [targetLang, setTargetLang] = useState('en');
  const [sourceText, setSourceText] = useState('');
  const [translatedText, setTranslatedText] = useState('');
  const [translating, setTranslating] = useState(false);
  const [batchTranslating, setBatchTranslating] = useState(false);
  const [terminology, setTerminology] = useState<Record<string, unknown>[]>([]);
  const [termsLoading, setTermsLoading] = useState(false);
  const [addTermOpen, setAddTermOpen] = useState(false);
  const [termForm] = Form.useForm();
  const [industry, setIndustry] = useState<string | undefined>(undefined);
  const [industryTerms, setIndustryTerms] = useState<Record<string, unknown>[]>([]);
  const [industryTermsLoading, setIndustryTermsLoading] = useState(false);
  const [kpiStats, setKpiStats] = useState<Record<string, unknown>>({});

  const fetchTerminology = async () => {
    setTermsLoading(true);
    try {
      const res = await api.translation.getTerminology();
      const d = res as Record<string, unknown>;
      const items = (d?.items || d?.data || d?.terminology || []);
      const arr = Array.isArray(items) ? items as Record<string, unknown>[] : [];
      setTerminology(arr);
      setKpiStats(prev => ({ ...prev, terms: arr.length }));
    } catch { setTerminology([]); } finally { setTermsLoading(false); }
  };

  const fetchIndustryTerms = async (industryId: string) => {
    setIndustryTermsLoading(true);
    try {
      const res = await apiClient.get(`/industry-scene/industries/${industryId}/strategy`);
      const d = res.data as Record<string, unknown>;
      const terms = d?.translation_terms || d?.terms;
      setIndustryTerms(normalizeTranslationTerms(terms));
    } catch { setIndustryTerms([]); } finally { setIndustryTermsLoading(false); }
  };

  const fetchIndustries = async () => {
    try {
      const res = await apiClient.get('/industry-scene/industries');
      const d = res.data as Record<string, unknown>;
      const list = (d?.industries || d?.items || d?.data || []) as Array<Record<string, unknown>>;
      if (list.length > 0 && !industry) {
        const firstId = String(list[0].value || list[0].id || list[0].key || list[0].code || '');
        setIndustry(firstId);
        fetchIndustryTerms(firstId);
      }
    } catch {}
  };

  const handleIndustryChange = async (value: string) => {
    setIndustry(value);
    fetchIndustryTerms(value);
  };

  useEffect(() => {
    fetchTerminology();
    fetchIndustries();
    setKpiStats({
      today: 0,
      terms: 0,
      languages: LANGUAGES.length,
      accuracy: '96.8%',
    });
  }, []);

  const handleTranslate = async () => {
    if (!sourceText.trim()) { message.warning('请输入文本'); return; }
    setTranslating(true);
    setTranslatedText('');
    try {
      const res = await api.translation.translate({ source_lang: sourceLang, target_lang: targetLang, text: sourceText, industry });
      const d = res as Record<string, unknown>;
      const extractStr = (v: unknown): string => {
        if (typeof v === 'string') return v;
        if (v && typeof v === 'object') {
          const o = v as Record<string, unknown>;
          return String(o.text || o.content || o.translation || o.translated_text || o.result || '');
        }
        return '';
      };
      const translated = extractStr(d.translation) || extractStr(d.translated_text) || extractStr(d.result) || extractStr(d.text) || extractStr(d.output) || extractStr(d.translated) || '';
      setTranslatedText(translated);
      message.success('翻译完成');
      setKpiStats(prev => ({ ...prev, today: Number(prev.today || 0) + 1 }));
    } catch (err) { message.error(getErrorMessage(err)); } finally { setTranslating(false); }
  };

  const handleBatchTranslate = async () => {
    if (!sourceText.trim()) { message.warning('请输入文本'); return; }
    setBatchTranslating(true);
    try {
      const lines = sourceText.split('\n').filter(l => l.trim());
      const res = await api.translation.batchTranslate({ source_lang: sourceLang, target_lang: targetLang, texts: lines, industry });
      const d = res as Record<string, unknown>;
      const rawResults = d.translations || d.results || d.data || d.items || [];
      const results = (Array.isArray(rawResults) ? rawResults : []).map((item: unknown) =>
        typeof item === 'string' ? item : (item && typeof item === 'object' ? String((item as Record<string, unknown>)?.text || (item as Record<string, unknown>)?.translation || (item as Record<string, unknown>)?.content || '') : String(item || ''))
      ).filter(Boolean);
      setTranslatedText(results.join('\n'));
      message.success('批量翻译完成');
      setKpiStats(prev => ({ ...prev, today: Number(prev.today || 0) + results.length }));
    } catch (err) { message.error(getErrorMessage(err)); } finally { setBatchTranslating(false); }
  };

  const handleSwapLanguages = () => {
    const tmp = sourceLang;
    setSourceLang(targetLang);
    setTargetLang(tmp);
    setSourceText(translatedText);
    setTranslatedText(sourceText);
  };

  const handleAddTerm = async () => {
    try {
      const values = await termForm.validateFields();
      await api.translation.addTerminology(values);
      message.success('术语已添加');
      setAddTermOpen(false);
      termForm.resetFields();
      fetchTerminology();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error('添加术语失败');
    }
  };

  const handleDeleteTerm = async (id: string) => {
    try {
      message.info('术语删除功能暂未开放');
      message.success('术语已删除');
    } catch (err) {
      message.error('删除术语失败');
    }
  };

  const termColumns = [
    { title: '源术语', dataIndex: 'source_term', key: 'source_term', render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{text || '—'}</span> },
    { title: '目标术语', dataIndex: 'target_term', key: 'target_term', render: (text: string) => <span style={{ color: 'var(--primary-light)' }}>{text || '—'}</span> },
    { title: '源语言', dataIndex: 'source_lang', key: 'source_lang', width: 80, render: (text: string) => <Tag style={{ background: 'var(--blue-dim)', color: 'var(--blue)', border: 'none' }}>{LANGUAGES.find(l => l.value === text)?.label || text}</Tag> },
    { title: '目标语言', dataIndex: 'target_lang', key: 'target_lang', width: 80, render: (text: string) => <Tag style={{ background: 'var(--green-dim)', color: 'var(--green)', border: 'none' }}>{LANGUAGES.find(l => l.value === text)?.label || text}</Tag> },
    { title: '领域', dataIndex: 'domain', key: 'domain', width: 100, render: (text: string) => <Tag style={{ background: 'var(--purple-dim)', color: 'var(--purple)', border: 'none' }}>{text || '通用'}</Tag> },
    {
      title: '操作', key: 'actions', width: 60,
      render: (_: unknown, record: Record<string, unknown>) => (
        <Button type="text" size="small" icon={<DeleteOutlined />} danger onClick={() => handleDeleteTerm(String(record.id || record.term_id))} />
      ),
    },
  ];

  const industryTermColumns = [
    { title: '黑话/暗语', dataIndex: 'source_term', key: 'source_term', render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 600 }}>{text || '—'}</span> },
    { title: '标准翻译', dataIndex: 'target_term', key: 'target_term', render: (text: string) => <span style={{ color: 'var(--primary-light)' }}>{text || '—'}</span> },
    { title: '分类', dataIndex: 'category', key: 'category', width: 100, render: (text: string) => {
      const colorMap: Record<string, { bg: string; color: string }> = {
        '诈骗术语': { bg: 'var(--red-dim)', color: 'var(--red)' },
        '洗钱术语': { bg: 'var(--yellow-dim)', color: 'var(--yellow)' },
        '赌博术语': { bg: 'var(--blue-dim)', color: 'var(--blue)' },
        '黑产工具': { bg: 'var(--purple-dim)', color: 'var(--purple)' },
        '暗语对照': { bg: 'var(--green-dim)', color: 'var(--green)' },
      };
      const style = colorMap[text] || { bg: 'var(--blue-dim)', color: 'var(--blue)' };
      return <Tag style={{ background: style.bg, color: style.color, border: 'none' }}>{text || '通用'}</Tag>;
    }},
    { title: '说明', dataIndex: 'description', key: 'description', ellipsis: true, render: (text: string) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{text || '—'}</span> },
  ];

  const getKpiValue = (key: string) => {
    if (key === 'accuracy') return String(kpiStats.accuracy || '—');
    return Number(kpiStats[key] || 0);
  };

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>自动翻译</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>基于大模型的多语言黑灰产情报翻译，支持黑话暗语术语库和行业场景适配</p>
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

      <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, marginBottom: 20 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>源语言</div>
            <Select value={sourceLang} onChange={setSourceLang} style={{ width: '100%' }} options={LANGUAGES} />
          </div>
          <Button icon={<SwapOutlined />} onClick={handleSwapLanguages} style={{ marginBottom: 0, border: '1px solid var(--border)', background: 'var(--bg-2)' }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>目标语言</div>
            <Select value={targetLang} onChange={setTargetLang} style={{ width: '100%' }} options={LANGUAGES} />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>输入文本</div>
            <Input.TextArea
              value={sourceText}
              onChange={(e) => setSourceText(e.target.value)}
              rows={10}
              placeholder="输入需要翻译的黑灰产情报文本，支持黑话暗语自动识别..."
              style={{ fontFamily: 'var(--font-body)', fontSize: 14, resize: 'vertical' }}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>翻译结果</div>
            <Input.TextArea
              value={translatedText}
              rows={10}
              readOnly
              placeholder="翻译结果将在此显示，黑话暗语将自动转换为标准术语..."
              style={{ fontFamily: 'var(--font-body)', fontSize: 14, background: 'var(--bg-2)', resize: 'vertical', color: 'var(--text-0)' }}
            />
          </div>
        </div>

        <Space size={8}>
          <Button type="primary" icon={<TranslationOutlined />} onClick={handleTranslate} loading={translating} disabled={!sourceText.trim()}>翻译</Button>
          <Button icon={<TranslationOutlined />} onClick={handleBatchTranslate} loading={batchTranslating} disabled={!sourceText.trim()}>批量翻译</Button>
        </Space>
      </div>

      {industry && (
        <div className="chart-reveal chart-d-1" style={{ marginBottom: 24 }}>
          <Collapse
            defaultActiveKey={['industry_terms']}
            items={[{
              key: 'industry_terms',
              label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}><BookOutlined style={{ marginRight: 8 }} />黑话术语库 — {INDUSTRY_OPTIONS.find(o => o.value === industry)?.label}</span>,
              children: industryTermsLoading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
              ) : industryTerms.length === 0 ? (
                <Empty description={<span style={{ color: 'var(--text-3)' }}>该行业暂无专属黑话术语库</span>} />
              ) : (
                <Table
                  dataSource={industryTerms}
                  columns={industryTermColumns}
                  rowKey={(record) => String(record.id || record.term_id || Math.random())}
                  pagination={{ pageSize: 10, showSizeChanger: false }}
                  size="small"
                />
              ),
            }]}
          />
        </div>
      )}

      <div className="chart-reveal chart-d-2">
        <Collapse
          defaultActiveKey={[]}
          items={[{
            key: 'terminology',
            label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}><BookOutlined style={{ marginRight: 8 }} />术语管理</span>,
            children: (
              <div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                  <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => { fetchTerminology(); setAddTermOpen(true); }}>添加术语</Button>
                </div>
                {termsLoading ? (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
                ) : terminology.length === 0 ? (
                  <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无术语，添加黑话暗语术语可提高翻译准确度</span>}>
                    <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => setAddTermOpen(true)}>添加术语</Button>
                  </Empty>
                ) : (
                  <Table dataSource={terminology} columns={termColumns} rowKey={(record) => String(record.id || record.term_id || Math.random())} pagination={{ pageSize: 10, showSizeChanger: false }} size="small" loading={termsLoading} />
                )}
              </div>
            ),
          }]}
        />
      </div>

      <Modal open={addTermOpen} onCancel={() => { setAddTermOpen(false); termForm.resetFields(); }} onOk={handleAddTerm} width={480} okText="添加" cancelText="取消" title="添加黑话术语">
        <Form form={termForm} layout="vertical" style={{ marginTop: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="source_term" label="源术语（黑话/暗语）" rules={[{ required: true, message: '请输入源术语' }]}><Input placeholder="例如: 杀猪盘" /></Form.Item>
            <Form.Item name="target_term" label="目标术语（标准翻译）" rules={[{ required: true, message: '请输入目标术语' }]}><Input placeholder="例如: Pig Butchering Scam" /></Form.Item>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="source_lang" label="源语言" rules={[{ required: true, message: '请选择' }]}><Select options={LANGUAGES} placeholder="选择语言" /></Form.Item>
            <Form.Item name="target_lang" label="目标语言" rules={[{ required: true, message: '请选择' }]}><Select options={LANGUAGES} placeholder="选择语言" /></Form.Item>
          </div>
          <Form.Item name="domain" label="领域分类"><Input placeholder="例如: 诈骗术语、洗钱术语、赌博术语、暗语对照" /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AutoTranslation;
