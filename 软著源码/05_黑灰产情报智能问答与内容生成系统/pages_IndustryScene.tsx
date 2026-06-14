import React, { useState, useEffect } from 'react';
import {
  Card, Tag, Button, Descriptions, Spin, Empty, Space, Slider, Switch, Input, Select, Divider,
} from 'antd';
import {
  ToolOutlined, ReadOutlined, HeartOutlined, DollarOutlined,
  ThunderboltOutlined, TranslationOutlined, FileTextOutlined,
  QuestionCircleOutlined, SettingOutlined, CheckCircleOutlined,
  SafetyCertificateOutlined, BugOutlined, AlertOutlined,
  LockOutlined, BankOutlined, RobotOutlined,
} from '@ant-design/icons';
import apiClient from '../services/api';
import { getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const INDUSTRY_META: Record<string, {
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  label: string;
  description: string;
  defaultFocusAreas: string[];
  defaultTerms: Array<{ term: string; meaning: string; category: string }>;
  defaultConfig: Record<string, unknown>;
}> = {
  smart_manufacturing: {
    icon: <ToolOutlined style={{ fontSize: 28 }} />,
    color: '#2563EB',
    bgColor: '#2563EB15',
    label: '智能制造',
    description: '聚焦工业控制系统安全、供应链攻击、OT/IT融合威胁',
    defaultFocusAreas: ['工控系统漏洞', '供应链攻击', 'OT/IT融合威胁', '勒索软件', '工业间谍', 'PLC攻击'],
    defaultTerms: [
      { term: '肉鸡', meaning: '被控制的工控设备', category: '控制术语' },
      { term: '洗料', meaning: '篡改生产配方数据', category: '生产术语' },
      { term: '挂马', meaning: '在SCADA系统中植入后门', category: '攻击术语' },
      { term: '社工', meaning: '针对运维人员的社会工程', category: '攻击术语' },
      { term: '提权', meaning: '获取PLC控制权限', category: '攻击术语' },
      { term: '脱裤', meaning: '窃取生产数据库', category: '数据术语' },
    ],
    defaultConfig: {
      analysis_depth: 'deep',
      enable_ot_monitoring: true,
      supply_chain_scan_interval: 24,
      threat_score_threshold: 0.7,
      enable_iot_detection: true,
      max_analysis_concurrency: 5,
    },
  },
  smart_education: {
    icon: <ReadOutlined style={{ fontSize: 28 }} />,
    color: '#16A34A',
    bgColor: '#16A34A15',
    label: '智慧教育',
    description: '聚焦学术数据泄露、在线教育平台攻击、学生隐私威胁',
    defaultFocusAreas: ['数据泄露', '在线平台攻击', '学术造假', '隐私窃取', '钓鱼攻击', '考试作弊黑产'],
    defaultTerms: [
      { term: '代写', meaning: '论文/作业代写黑产', category: '学术术语' },
      { term: '代考', meaning: '考试替考黑产', category: '学术术语' },
      { term: '查重', meaning: '论文查重绕过服务', category: '学术术语' },
      { term: '挂科包过', meaning: '课程成绩篡改服务', category: '学术术语' },
      { term: '社工库', meaning: '学生信息泄露数据库', category: '数据术语' },
      { term: '撞库', meaning: '利用泄露凭证批量登录', category: '攻击术语' },
    ],
    defaultConfig: {
      analysis_depth: 'standard',
      enable_platform_monitoring: true,
      data_leak_scan_interval: 12,
      threat_score_threshold: 0.6,
      enable_privacy_detection: true,
      max_analysis_concurrency: 8,
    },
  },
  healthcare: {
    icon: <HeartOutlined style={{ fontSize: 28 }} />,
    color: '#DC2626',
    bgColor: '#DC262615',
    label: '医疗健康',
    description: '聚焦医疗设备安全、患者数据泄露、医药供应链威胁',
    defaultFocusAreas: ['医疗设备漏洞', '患者数据泄露', '医药造假', '远程医疗攻击', '勒索软件', '处方药黑市'],
    defaultTerms: [
      { term: '号贩子', meaning: '倒卖专家号源的黑产', category: '医疗术语' },
      { term: '假药', meaning: '仿冒药品黑产链', category: '医药术语' },
      { term: '医保套现', meaning: '医保卡非法套现', category: '金融术语' },
      { term: '病历倒卖', meaning: '患者病历信息贩卖', category: '数据术语' },
      { term: '处方外流', meaning: '处方药非法流通', category: '医药术语' },
      { term: '医托', meaning: '医疗诈骗引流', category: '诈骗术语' },
    ],
    defaultConfig: {
      analysis_depth: 'deep',
      enable_device_monitoring: true,
      data_leak_scan_interval: 6,
      threat_score_threshold: 0.8,
      enable_hipaa_compliance: true,
      max_analysis_concurrency: 4,
    },
  },
  financial_services: {
    icon: <DollarOutlined style={{ fontSize: 28 }} />,
    color: '#7C3AED',
    bgColor: '#7C3AED15',
    label: '金融服务',
    description: '聚焦金融诈骗、洗钱活动、支付安全、信贷欺诈威胁',
    defaultFocusAreas: ['金融诈骗', '洗钱活动', '支付安全', '信贷欺诈', '内鬼威胁', '加密货币犯罪'],
    defaultTerms: [
      { term: '杀猪盘', meaning: '长期感情投资型诈骗', category: '诈骗术语' },
      { term: '跑分', meaning: '利用第三方支付洗钱', category: '洗钱术语' },
      { term: '四件套', meaning: '银行卡+U盾+身份证+手机卡', category: '工具术语' },
      { term: '料子', meaning: '窃取的银行卡信息', category: '数据术语' },
      { term: '水房', meaning: '洗钱资金转移通道', category: '洗钱术语' },
      { term: '接码', meaning: '验证码接收服务', category: '工具术语' },
    ],
    defaultConfig: {
      analysis_depth: 'comprehensive',
      enable_transaction_monitoring: true,
      fraud_scan_interval: 1,
      threat_score_threshold: 0.9,
      enable_aml_detection: true,
      max_analysis_concurrency: 10,
    },
  },
};

const INDUSTRY_KEYS = ['smart_manufacturing', 'smart_education', 'healthcare', 'financial_services'];

const FOCUS_AREA_COLORS: Record<string, string> = {
  '工控系统漏洞': '#2563EB', '供应链攻击': '#2563EB', 'OT/IT融合威胁': '#2563EB',
  '勒索软件': '#DC2626', '工业间谍': '#EA580C', 'PLC攻击': '#7C3AED',
  '数据泄露': '#DC2626', '在线平台攻击': '#EA580C', '学术造假': '#7C3AED',
  '隐私窃取': '#DC2626', '钓鱼攻击': '#0D9488', '考试作弊黑产': '#7C3AED',
  '医疗设备漏洞': '#DC2626', '患者数据泄露': '#2563EB', '医药造假': '#EA580C',
  '远程医疗攻击': '#0D9488', '处方药黑市': '#7C3AED',
  '金融诈骗': '#DC2626', '洗钱活动': '#EA580C', '支付安全': '#2563EB',
  '信贷欺诈': '#7C3AED', '内鬼威胁': '#0D9488', '加密货币犯罪': '#7C3AED',
};

const TERM_CATEGORY_COLORS: Record<string, { bg: string; color: string }> = {
  '控制术语': { bg: '#2563EB15', color: '#2563EB' },
  '生产术语': { bg: '#16A34A15', color: '#16A34A' },
  '攻击术语': { bg: '#DC262615', color: '#DC2626' },
  '数据术语': { bg: '#7C3AED15', color: '#7C3AED' },
  '学术术语': { bg: '#16A34A15', color: '#16A34A' },
  '医疗术语': { bg: '#DC262615', color: '#DC2626' },
  '医药术语': { bg: '#0D948815', color: '#0D9488' },
  '金融术语': { bg: '#7C3AED15', color: '#7C3AED' },
  '诈骗术语': { bg: '#DC262615', color: '#DC2626' },
  '洗钱术语': { bg: '#EA580C15', color: '#EA580C' },
  '工具术语': { bg: '#2563EB15', color: '#2563EB' },
};

const IndustryScene: React.FC = () => {
  const message = useAntdMessage();
  const [industries, setIndustries] = useState<Array<Record<string, unknown>>>([]);
  const [industriesLoading, setIndustriesLoading] = useState(true);
  const [selectedIndustry, setSelectedIndustry] = useState<string | null>(null);
  const [strategy, setStrategy] = useState<Record<string, unknown> | null>(null);
  const [config, setConfig] = useState<Record<string, unknown> | null>(null);
  const [strategyLoading, setStrategyLoading] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);
  const [editedConfig, setEditedConfig] = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);

  const fetchIndustries = async () => {
    setIndustriesLoading(true);
    try {
      const res = await apiClient.get('/industry-scene/industries');
      const d = res.data as Record<string, unknown>;
      const list = (d?.industries || d?.items || d?.data || []) as Array<Record<string, unknown>>;
      setIndustries(list);
      if (list.length > 0 && !selectedIndustry) {
        const firstId = String(list[0].value || list[0].id || list[0].key || list[0].code || INDUSTRY_KEYS[0]);
        setSelectedIndustry(firstId);
      }
    } catch {
      setIndustries([]);
      if (!selectedIndustry) {
        setSelectedIndustry(INDUSTRY_KEYS[0]);
      }
    } finally {
      setIndustriesLoading(false);
    }
  };

  const fetchStrategy = async (industryId: string) => {
    setStrategyLoading(true);
    try {
      const res = await apiClient.get(`/industry-scene/industries/${industryId}/strategy`);
      const d = res.data as Record<string, unknown>;
      setStrategy(d);
    } catch {
      setStrategy(null);
    } finally {
      setStrategyLoading(false);
    }
  };

  const fetchConfig = async (industryId: string) => {
    setConfigLoading(true);
    try {
      const res = await apiClient.get(`/industry-scene/industries/${industryId}/config`);
      const d = res.data as Record<string, unknown>;
      setConfig(d);
      setEditedConfig((d?.config || d || {}) as Record<string, unknown>);
    } catch {
      setConfig(null);
      const meta = INDUSTRY_META[industryId];
      setEditedConfig(meta?.defaultConfig || {});
    } finally {
      setConfigLoading(false);
    }
  };

  useEffect(() => {
    fetchIndustries();
  }, []);

  useEffect(() => {
    if (selectedIndustry) {
      fetchStrategy(selectedIndustry);
      fetchConfig(selectedIndustry);
    }
  }, [selectedIndustry]);

  const handleSelectIndustry = (key: string) => {
    if (key !== selectedIndustry) {
      setSelectedIndustry(key);
    }
  };

  const handleSaveConfig = async () => {
    if (!selectedIndustry) return;
    setSaving(true);
    try {
      await apiClient.put(`/industry-scene/industries/${selectedIndustry}/config`, editedConfig);
      message.success('配置已保存');
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const handleQuickAction = (action: string) => {
    if (!selectedIndustry) return;
    const meta = INDUSTRY_META[selectedIndustry];
    const label = meta?.label || selectedIndustry;
    switch (action) {
      case 'qa':
        message.info(`已切换智能问答至「${label}」行业上下文`);
        break;
      case 'translation':
        message.info(`已切换自动翻译至「${label}」行业术语库`);
        break;
      case 'content-gen':
        message.info(`已切换内容生成至「${label}」行业模板`);
        break;
    }
  };

  const getFocusAreas = (): string[] => {
    if (strategy?.focus_areas) {
      return (strategy.focus_areas as string[]);
    }
    if (strategy?.threat_categories) {
      return (strategy.threat_categories as string[]);
    }
    return INDUSTRY_META[selectedIndustry || '']?.defaultFocusAreas || [];
  };

  const getTerms = (): Array<{ term: string; meaning: string; category: string }> => {
    if (strategy?.terms) {
      const raw = strategy.terms;
      if (Array.isArray(raw)) {
        return raw.map((t: unknown) => {
          if (typeof t === 'object' && t !== null) {
            const obj = t as Record<string, unknown>;
            return {
              term: String(obj.term || obj.source_term || obj.name || ''),
              meaning: String(obj.meaning || obj.target_term || obj.definition || obj.description || ''),
              category: String(obj.category || obj.type || '行业术语'),
            };
          }
          return { term: String(t), meaning: '', category: '行业术语' };
        });
      }
      if (typeof raw === 'object') {
        return Object.entries(raw as Record<string, unknown>).map(([key, val]) => ({
          term: key,
          meaning: String(val || ''),
          category: '行业术语',
        }));
      }
    }
    if (strategy?.translation_terms) {
      const raw = strategy.translation_terms;
      if (typeof raw === 'object' && !Array.isArray(raw)) {
        return Object.entries(raw as Record<string, unknown>).map(([key, val]) => ({
          term: key,
          meaning: String(val || ''),
          category: '行业术语',
        }));
      }
    }
    return INDUSTRY_META[selectedIndustry || '']?.defaultTerms || [];
  };

  const getActiveConfig = (): Record<string, unknown> => {
    if (Object.keys(editedConfig).length > 0) return editedConfig;
    if (config?.config) return config.config as Record<string, unknown>;
    return INDUSTRY_META[selectedIndustry || '']?.defaultConfig || {};
  };

  const meta = selectedIndustry ? INDUSTRY_META[selectedIndustry] : null;
  const focusAreas = getFocusAreas();
  const terms = getTerms();
  const activeConfig = getActiveConfig();

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>
          行业场景
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>
          针对不同行业场景定制威胁分析策略、行业术语库和分析配置，提升情报分析精准度
        </p>
      </div>

      <Spin spinning={industriesLoading}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
          {INDUSTRY_KEYS.map((key) => {
          const m = INDUSTRY_META[key];
          const isActive = selectedIndustry === key;
          return (
            <Card
              key={key}
              hoverable
              onClick={() => handleSelectIndustry(key)}
              style={{
                background: isActive ? m.bgColor : 'var(--bg-1)',
                border: isActive ? `2px solid ${m.color}` : '1px solid var(--border)',
                borderRadius: 12,
                cursor: 'pointer',
                transition: 'all 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
                transform: isActive ? 'translateY(-2px)' : 'none',
                boxShadow: isActive ? `0 8px 24px ${m.color}20` : 'none',
              }}
              styles={{ body: { padding: 20 } }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                <div
                  style={{
                    width: 48,
                    height: 48,
                    borderRadius: 12,
                    background: isActive ? `${m.color}20` : 'var(--bg-2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: isActive ? m.color : 'var(--text-2)',
                    transition: 'all 0.25s',
                  }}
                >
                  {m.icon}
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 600, color: isActive ? m.color : 'var(--text-0)', fontFamily: 'var(--font-body)' }}>
                    {m.label}
                  </div>
                  {isActive && (
                    <Tag style={{ background: `${m.color}20`, color: m.color, border: 'none', fontSize: 11, marginTop: 2, padding: '0 6px' }}>
                      当前
                    </Tag>
                  )}
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
                {m.description}
              </div>
            </Card>
          );
        })}
      </div>
      </Spin>

      {selectedIndustry && meta && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div
              style={{
                background: 'var(--bg-1)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                padding: 24,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
                <AlertOutlined style={{ fontSize: 16, color: meta.color }} />
                <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>威胁关注领域</span>
                <Tag style={{ background: `${meta.color}15`, color: meta.color, border: 'none', marginLeft: 'auto' }}>
                  {focusAreas.length} 项
                </Tag>
              </div>
              {strategyLoading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div>
              ) : focusAreas.length === 0 ? (
                <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无威胁关注领域</span>} />
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {focusAreas.map((area) => {
                    const c = FOCUS_AREA_COLORS[area] || meta.color;
                    return (
                      <Tag
                        key={area}
                        style={{
                          background: `${c}12`,
                          color: c,
                          border: `1px solid ${c}30`,
                          borderRadius: 6,
                          padding: '4px 12px',
                          fontSize: 13,
                          fontWeight: 500,
                        }}
                      >
                        {area}
                      </Tag>
                    );
                  })}
                </div>
              )}
            </div>

            <div
              style={{
                background: 'var(--bg-1)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                padding: 24,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
                <BugOutlined style={{ fontSize: 16, color: meta.color }} />
                <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>行业术语与黑话</span>
                <Tag style={{ background: `${meta.color}15`, color: meta.color, border: 'none', marginLeft: 'auto' }}>
                  {terms.length} 条
                </Tag>
              </div>
              {strategyLoading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div>
              ) : terms.length === 0 ? (
                <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无行业术语</span>} />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 280, overflowY: 'auto' }}>
                  {terms.map((t, i) => {
                    const catStyle = TERM_CATEGORY_COLORS[t.category] || { bg: `${meta.color}15`, color: meta.color };
                    return (
                      <div
                        key={i}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          padding: '8px 12px',
                          background: 'var(--bg-0)',
                          borderRadius: 8,
                          border: '1px solid var(--border)',
                        }}
                      >
                        <span style={{ fontWeight: 600, color: 'var(--text-0)', fontSize: 13, minWidth: 60 }}>{t.term}</span>
                        <span style={{ color: 'var(--text-2)', fontSize: 12, flex: 1 }}>{t.meaning}</span>
                        <Tag style={{ background: catStyle.bg, color: catStyle.color, border: 'none', fontSize: 11, flexShrink: 0 }}>
                          {t.category}
                        </Tag>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div
            style={{
              background: 'var(--bg-1)',
              border: '1px solid var(--border)',
              borderRadius: 12,
              padding: 24,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
              <SettingOutlined style={{ fontSize: 16, color: meta.color }} />
              <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>行业分析配置</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                <Button
                  size="small"
                  onClick={() => {
                    const defaultCfg = INDUSTRY_META[selectedIndustry]?.defaultConfig || {};
                    setEditedConfig(defaultCfg);
                  }}
                >
                  恢复默认
                </Button>
                <Button
                  type="primary"
                  size="small"
                  icon={<CheckCircleOutlined />}
                  loading={saving}
                  onClick={handleSaveConfig}
                >
                  保存配置
                </Button>
              </div>
            </div>
            {configLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>分析深度</div>
                    <Select
                      value={String(editedConfig.analysis_depth || activeConfig.analysis_depth || 'standard')}
                      onChange={(v) => setEditedConfig((prev) => ({ ...prev, analysis_depth: v }))}
                      style={{ width: '100%' }}
                      options={[
                        { value: 'quick', label: '快速' },
                        { value: 'standard', label: '标准' },
                        { value: 'deep', label: '深度' },
                        { value: 'comprehensive', label: '全面' },
                      ]}
                    />
                  </div>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)' }}>威胁评分阈值</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: meta.color, fontWeight: 600 }}>
                        {Number(editedConfig.threat_score_threshold ?? activeConfig.threat_score_threshold ?? 0.7).toFixed(2)}
                      </span>
                    </div>
                    <Slider
                      min={0}
                      max={100}
                      value={Math.round((Number(editedConfig.threat_score_threshold ?? activeConfig.threat_score_threshold ?? 0.7)) * 100)}
                      onChange={(v) => setEditedConfig((prev) => ({ ...prev, threat_score_threshold: v / 100 }))}
                    />
                  </div>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)' }}>最大分析并发数</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-1)', fontWeight: 600 }}>
                        {String(editedConfig.max_analysis_concurrency ?? activeConfig.max_analysis_concurrency ?? 5)}
                      </span>
                    </div>
                    <Slider
                      min={1}
                      max={20}
                      value={Number(editedConfig.max_analysis_concurrency ?? activeConfig.max_analysis_concurrency ?? 5)}
                      onChange={(v) => setEditedConfig((prev) => ({ ...prev, max_analysis_concurrency: v }))}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>扫描间隔（小时）</div>
                    <Input
                      type="number"
                      value={String(editedConfig.supply_chain_scan_interval ?? editedConfig.data_leak_scan_interval ?? editedConfig.fraud_scan_interval ?? activeConfig.supply_chain_scan_interval ?? activeConfig.data_leak_scan_interval ?? activeConfig.fraud_scan_interval ?? 12)}
                      onChange={(e) => {
                        const val = Number(e.target.value);
                        const key = selectedIndustry === 'smart_manufacturing' ? 'supply_chain_scan_interval'
                          : selectedIndustry === 'financial_services' ? 'fraud_scan_interval'
                          : 'data_leak_scan_interval';
                        setEditedConfig((prev) => ({ ...prev, [key]: val }));
                      }}
                      style={{ width: '100%' }}
                    />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {[
                      { key: 'enable_ot_monitoring', label: 'OT监控', industries: ['smart_manufacturing'] },
                      { key: 'enable_iot_detection', label: 'IoT检测', industries: ['smart_manufacturing'] },
                      { key: 'enable_platform_monitoring', label: '平台监控', industries: ['smart_education'] },
                      { key: 'enable_privacy_detection', label: '隐私检测', industries: ['smart_education'] },
                      { key: 'enable_device_monitoring', label: '设备监控', industries: ['healthcare'] },
                      { key: 'enable_hipaa_compliance', label: 'HIPAA合规', industries: ['healthcare'] },
                      { key: 'enable_transaction_monitoring', label: '交易监控', industries: ['financial_services'] },
                      { key: 'enable_aml_detection', label: '反洗钱检测', industries: ['financial_services'] },
                    ].filter((item) => item.industries.includes(selectedIndustry)).map((item) => (
                      <div
                        key={item.key}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '8px 12px',
                          background: 'var(--bg-0)',
                          borderRadius: 8,
                          border: '1px solid var(--border)',
                        }}
                      >
                        <span style={{ fontSize: 13, color: 'var(--text-1)' }}>{item.label}</span>
                        <Switch
                          size="small"
                          checked={Boolean(editedConfig[item.key] ?? activeConfig[item.key] ?? true)}
                          onChange={(v) => setEditedConfig((prev) => ({ ...prev, [item.key]: v }))}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          <div
            style={{
              background: 'var(--bg-1)',
              border: '1px solid var(--border)',
              borderRadius: 12,
              padding: 24,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
              <ThunderboltOutlined style={{ fontSize: 16, color: meta.color }} />
              <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>快捷操作</span>
              <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 4 }}>
                将「{meta.label}」行业上下文应用到其他功能模块
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              <Button
                size="large"
                icon={<QuestionCircleOutlined />}
                onClick={() => handleQuickAction('qa')}
                style={{
                  height: 56,
                  borderRadius: 10,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  background: 'var(--bg-0)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-0)',
                  fontWeight: 500,
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <RobotOutlined style={{ fontSize: 18, color: meta.color }} />
                  <span style={{ fontSize: 12 }}>切换智能问答</span>
                </div>
              </Button>
              <Button
                size="large"
                icon={<TranslationOutlined />}
                onClick={() => handleQuickAction('translation')}
                style={{
                  height: 56,
                  borderRadius: 10,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  background: 'var(--bg-0)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-0)',
                  fontWeight: 500,
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <TranslationOutlined style={{ fontSize: 18, color: meta.color }} />
                  <span style={{ fontSize: 12 }}>切换自动翻译</span>
                </div>
              </Button>
              <Button
                size="large"
                icon={<FileTextOutlined />}
                onClick={() => handleQuickAction('content-gen')}
                style={{
                  height: 56,
                  borderRadius: 10,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  background: 'var(--bg-0)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-0)',
                  fontWeight: 500,
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <FileTextOutlined style={{ fontSize: 18, color: meta.color }} />
                  <span style={{ fontSize: 12 }}>切换内容生成</span>
                </div>
              </Button>
            </div>
          </div>

          {strategy && Object.keys(strategy).length > 0 && (
            <div
              style={{
                background: 'var(--bg-1)',
                border: '1px solid var(--border)',
                borderRadius: 12,
                padding: 24,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
                <SafetyCertificateOutlined style={{ fontSize: 16, color: meta.color }} />
                <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>策略详情</span>
              </div>
              <Descriptions
                bordered
                size="small"
                column={2}
                styles={{ label: { background: 'var(--bg-2)', color: 'var(--text-2)', fontSize: 12, fontWeight: 500 }, content: { background: 'var(--bg-1)', color: 'var(--text-0)', fontSize: 13 } }}
              >
                {Object.entries(strategy)
                  .filter(([key]) => !['focus_areas', 'terms', 'translation_terms', 'threat_categories'].includes(key))
                  .map(([key, value]) => (
                    <Descriptions.Item key={key} label={key}>
                      {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                    </Descriptions.Item>
                  ))}
              </Descriptions>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default IndustryScene;
