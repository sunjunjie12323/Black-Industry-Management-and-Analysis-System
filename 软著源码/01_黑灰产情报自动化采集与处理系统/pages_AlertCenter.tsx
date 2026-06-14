import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Table, Tag, Button, Space, Select, Switch, Spin, Popconfirm, Collapse, Empty, Tooltip, Pagination,
} from 'antd';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell, Tooltip as RechartsTooltip, ResponsiveContainer,
} from 'recharts';
import {
  BellOutlined, CheckCircleOutlined, ExclamationCircleOutlined,
  WarningOutlined, ThunderboltOutlined, ExperimentOutlined,
  ReloadOutlined, DownloadOutlined,
} from '@ant-design/icons';
import { api } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import StatCard from '../components/StatCard';
import { StaggeredBarShape } from '../components/AnimatedChart';

const SEVERITY_MAP: Record<string, { color: string; label: string }> = {
  critical: { color: '#DC2626', label: '严重' },
  high: { color: '#EA580C', label: '高危' },
  medium: { color: '#EAB308', label: '中危' },
  low: { color: '#16A34A', label: '低危' },
};

const STATUS_MAP: Record<string, { color: string; label: string }> = {
  pending: { color: '#EAB308', label: '待处理' },
  processing: { color: '#2563EB', label: '处理中' },
  acknowledged: { color: '#16A34A', label: '已确认' },
  resolved: { color: '#64748B', label: '已处理' },
  ignored: { color: '#94A3B8', label: '已忽略' },
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

interface AlertItem {
  id: string;
  severity: string;
  message: string;
  status: string;
  created_at: string;
  source?: string;
}

interface RuleItem {
  id: string;
  name: string;
  condition?: string;
  severity?: string;
  enabled: boolean;
}

const AlertCenter: React.FC = () => {
  const message = useAntdMessage();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [stats, setStats] = useState<Record<string, number>>({});
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [alertPage, setAlertPage] = useState(1);
  const ALERT_PAGE_SIZE = 12;
  const heroRef = useRef<HTMLDivElement>(null);
  const cardGridRef = useRef<HTMLDivElement>(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    const [alertRes, statsRes] = await Promise.allSettled([
      api.alerts.getActive(severityFilter),
      api.alerts.getStats(),
    ]);
    if (alertRes.status === 'fulfilled') {
      const res = alertRes.value as Record<string, unknown>;
      const rawAlerts = (Array.isArray(res)
        ? res
        : (Array.isArray(res?.alerts) ? res.alerts : Array.isArray(res?.items) ? res.items : [])) as Record<string, unknown>[];
      setAlerts(
        rawAlerts.map(a => ({
          id: (a.id || a.alert_id || '') as string,
          severity: (a.severity || a.level || 'medium') as string,
          message: (a.message || a.title || a.description || '') as string,
          status: (a.status || 'pending') as string,
          created_at: (a.created_at || a.triggered_at || '') as string,
          source: (a.source || a.source_type || '') as string,
        })),
      );
    }
    if (statsRes.status === 'fulfilled') {
      const s = statsRes.value as Record<string, unknown>;
      const bySeverity = (s?.by_severity || {}) as Record<string, number>;
      setStats(typeof bySeverity === 'object' && bySeverity !== null ? bySeverity : {});
    }
    setLoading(false);
  }, [severityFilter]);

  const fetchRules = useCallback(async () => {
    setRulesLoading(true);
    try {
      const res = await api.alerts.getRules();
      const raw = (Array.isArray(res)
        ? res
        : (Array.isArray(res?.items) ? res.items : Array.isArray(res?.rules) ? res.rules : [])) as Record<string, unknown>[];
      setRules(
        raw.map(r => ({
          id: (r.id || r.rule_id || '') as string,
          name: (r.name || r.rule_name || '') as string,
          condition: (r.condition || r.description || '') as string,
          severity: (r.severity || r.level || '') as string,
          enabled: (r.enabled !== false) as boolean,
        })),
      );
    } catch {
      message.error('获取规则失败');
    } finally {
      setRulesLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    if (heroRef.current) {
      gsap.fromTo(heroRef.current, { y: 16, opacity: 0 }, { y: 0, opacity: 1, duration: 0.5, ease: 'power2.out' });
    }
  }, []);

  useEffect(() => {
    if (cardGridRef.current) {
      const cards = cardGridRef.current.querySelectorAll('.alert-card-item');
      gsap.fromTo(cards, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.04, ease: 'power2.out' });
    }
  }, [alerts]);

  const handleAcknowledge = async (id: string) => {
    try {
      await api.alerts.acknowledge(id);
      message.success('已确认');
      fetchAlerts();
    } catch {
      message.error('确认失败');
    }
  };

  const handleExportAlerts = () => {
    if (alerts.length === 0) {
      message.warning('没有可导出的告警数据');
      return;
    }
    const headers = ['ID', '严重程度', '告警信息', '状态', '来源', '触发时间'];
    const rows = alerts.map(a => [
      a.id,
      SEVERITY_MAP[a.severity]?.label || a.severity,
      `"${a.message.replace(/"/g, '""')}"`,
      STATUS_MAP[a.status]?.label || a.status,
      a.source || '',
      a.created_at || '',
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alerts_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    message.success(`已导出 ${alerts.length} 条告警`);
  };

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await api.alerts.toggleRule(ruleId, enabled);
      message.success(enabled ? '已启用' : '已禁用');
      fetchRules();
    } catch {
      message.error('操作失败');
    }
  };

  const handleTestTrigger = async () => {
    try {
      await api.alerts.testTrigger();
      message.success('测试告警已触发');
      fetchAlerts();
    } catch {
      message.error('触发失败');
    }
  };

  const criticalCount = stats.critical ?? alerts.filter(a => a.severity === 'critical').length;
  const highCount = stats.high ?? alerts.filter(a => a.severity === 'high').length;
  const mediumCount = stats.medium ?? alerts.filter(a => a.severity === 'medium').length;
  const activeTotal = alerts.length;

  const statItems = [
    { label: '活跃告警', value: activeTotal, icon: <BellOutlined />, color: '#1E40AF' },
    { label: '严重', value: criticalCount, icon: <ExclamationCircleOutlined />, color: '#DC2626' },
    { label: '高危', value: highCount, icon: <WarningOutlined />, color: '#EA580C' },
    { label: '中危', value: mediumCount, icon: <ThunderboltOutlined />, color: '#EAB308' },
  ];

  const severityPieData = Object.entries(stats).length > 0
    ? Object.entries(stats).map(([name, value]) => ({
        name: SEVERITY_MAP[name]?.label || name,
        value,
        color: SEVERITY_MAP[name]?.color || '#64748B',
      }))
    : alerts.length > 0
      ? Object.entries(
          alerts.reduce<Record<string, number>>((acc, a) => {
            acc[a.severity] = (acc[a.severity] || 0) + 1;
            return acc;
          }, {})
        ).map(([name, value]) => ({
          name: SEVERITY_MAP[name]?.label || name,
          value,
          color: SEVERITY_MAP[name]?.color || '#64748B',
        }))
      : [];

  const ruleColumns = [
    {
      title: '规则名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string) => (
        <span style={{ color: '#334155', fontSize: 13 }}>{v || '—'}</span>
      ),
    },
    {
      title: '触发条件',
      dataIndex: 'condition',
      ellipsis: true,
      render: (v: string) => (
        <span style={{
          color: '#64748B',
          fontSize: 12,
          fontFamily: 'var(--font-mono)',
        }}>
          {v || '—'}
        </span>
      ),
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      width: 90,
      render: (v: string) => {
        const cfg = SEVERITY_MAP[v];
        return cfg ? (
          <Tag style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28`, fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>
            {cfg.label}
          </Tag>
        ) : (
          <Tag style={{ background: '#E2E8F0', border: '1px solid #E2E8F0', color: '#64748B', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>{v || '—'}</Tag>
        );
      },
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, r: RuleItem) => (
        <Tooltip title={v ? '点击禁用此规则' : '点击启用此规则'}>
          <Switch
            size="small"
            checked={v}
            onChange={checked => handleToggleRule(r.id, checked)}
          />
        </Tooltip>
      ),
    },
  ];

  return (
    <div style={{ minHeight: '100%', padding: 0, background: '#F8FAFC', overflowX: 'hidden' }}>
      <style>{`
        .alert-card-item {
          transition: all 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }
        .alert-card-item:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 24px rgba(0,0,0,0.08);
        }
      `}</style>

      <div ref={heroRef} style={{ margin: '24px 32px 0', borderRadius: 16, padding: '28px 32px', background: 'linear-gradient(135deg, #EFF6FF 0%, #DBEAFE 50%, #E0F2FE 100%)', position: 'relative', overflow: 'hidden', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ position: 'absolute', top: -40, right: -30, width: 180, height: 180, borderRadius: '50%', background: 'rgba(255,255,255,0.08)' }} />
        <div style={{ position: 'absolute', bottom: -60, right: 120, width: 140, height: 140, borderRadius: '50%', background: 'rgba(255,255,255,0.05)' }} />
        <div style={{ position: 'absolute', top: 20, left: '45%', width: 100, height: 100, borderRadius: '50%', background: 'rgba(255,255,255,0.04)' }} />
        <div style={{ position: 'relative', zIndex: 1 }}>
          <h1 style={{ fontSize: 26, fontWeight: 700, fontFamily: 'var(--font-body)', color: '#1E3A5F', margin: 0, letterSpacing: '-0.02em', lineHeight: 1.3 }}>
            告警中心
          </h1>
          <p style={{ fontSize: 14, color: '#6B7280', margin: '6px 0 0', fontFamily: 'var(--font-body)' }}>
            实时威胁告警监控 · 智能规则引擎 · DeepSeek驱动
          </p>
        </div>
        <Space size={8} style={{ position: 'relative', zIndex: 1 }}>
          <Select
            placeholder="全部等级"
            value={severityFilter}
            onChange={setSeverityFilter}
            allowClear
            style={{ width: 140 }}
            options={Object.entries(SEVERITY_MAP).map(([k, v]) => ({
              label: v.label,
              value: k,
            }))}
          />
          <Tooltip title="发送一条测试告警以验证告警系统是否正常工作">
            <Button
              icon={<ExperimentOutlined />}
              onClick={handleTestTrigger}
              style={{ background: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.25)', color: '#1E3A5F', backdropFilter: 'blur(8px)', borderRadius: 8 }}
            >
              测试触发
            </Button>
          </Tooltip>
          <Tooltip title="刷新数据">
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchAlerts}
              style={{ background: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.25)', color: '#1E3A5F', backdropFilter: 'blur(8px)', borderRadius: 8 }}
            >
              刷新
            </Button>
          </Tooltip>
          <Tooltip title="导出告警数据">
            <Button
              icon={<DownloadOutlined />}
              onClick={handleExportAlerts}
              style={{ background: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.25)', color: '#1E3A5F', backdropFilter: 'blur(8px)', borderRadius: 8 }}
            >
              导出
            </Button>
          </Tooltip>
        </Space>
      </div>

      <div style={{ padding: '16px 32px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 16 }}>
          {statItems.map((item) => (
            <StatCard
              key={item.label}
              icon={item.icon}
              label={item.label}
              value={item.value}
              color={item.color}
            />
          ))}
        </div>
      </div>

      <div style={{ padding: '0 32px', marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16 }}>
          <div className="chart-reveal chart-d-1" style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16, fontFamily: 'var(--font-body)' }}>
              告警严重度分布
            </div>
            {severityPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={severityPieData} margin={{ top: 8, right: 16, left: 0, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                  <RechartsTooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                  <Bar dataKey="value" barSize={16} radius={[6, 6, 0, 0]} isAnimationActive={false} shape={<StaggeredBarShape radius={[6, 6, 0, 0]} />}>
                    {severityPieData.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty description="暂无告警数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              </div>
            )}
          </div>

          <div style={{ padding: 24, background: '#FFFFFF', borderRadius: 12, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 16, fontFamily: 'var(--font-body)' }}>
              告警处理概览
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
              {[
                { label: '待处理', value: alerts.filter(a => a.status === 'pending').length, color: '#EAB308', icon: <ExclamationCircleOutlined /> },
                { label: '已确认', value: alerts.filter(a => a.status === 'acknowledged').length, color: '#16A34A', icon: <CheckCircleOutlined /> },
                { label: '已处理', value: alerts.filter(a => a.status === 'resolved').length, color: '#64748B', icon: <CheckCircleOutlined /> },
              ].map((item) => (
                <div key={item.label} style={{ padding: 16, background: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', textAlign: 'center' }}>
                  <div style={{ fontSize: 12, color: '#94A3B8', fontWeight: 500, marginBottom: 8 }}>{item.label}</div>
                  <div style={{ fontSize: 28, fontFamily: 'var(--font-mono)', fontWeight: 700, color: item.color, lineHeight: 1 }}>{item.value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div style={{ padding: '0 32px' }}>
        <div className="page-collapse fade-in-up stagger-4">
          <Collapse
            defaultActiveKey={['alerts']}
            items={[
              {
                key: 'alerts',
                label: <span style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>告警列表</span>,
                children: (
                  <div style={{ padding: '12px 0' }}>
                    {loading ? (
                      <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
                    ) : alerts.length === 0 ? (
                      <div style={{ padding: '40px 0', textAlign: 'center' }}>
                        <Empty
                          description="暂无活跃告警，系统运行正常"
                          image={Empty.PRESENTED_IMAGE_SIMPLE}
                        >
                          <Tooltip title="发送一条测试告警以验证告警系统是否正常工作">
                            <Button type="primary" onClick={handleTestTrigger} icon={<ExperimentOutlined />}>测试触发</Button>
                          </Tooltip>
                        </Empty>
                      </div>
                    ) : (
                      <>
                      <div ref={cardGridRef} style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
                        {alerts.slice((alertPage - 1) * ALERT_PAGE_SIZE, alertPage * ALERT_PAGE_SIZE).map((alert) => {
                          const sevCfg = SEVERITY_MAP[alert.severity] || SEVERITY_MAP.medium;
                          const statusCfg = STATUS_MAP[alert.status];
                          return (
                            <div key={alert.id} className="alert-card-item" style={{ background: '#FFFFFF', borderRadius: 10, border: '1px solid #E2E8F0', display: 'flex', overflow: 'hidden' }}>
                              <div style={{ width: 4, background: sevCfg.color, flexShrink: 0 }} />
                              <div style={{ flex: 1, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                                    <Tag style={{ background: `${sevCfg.color}14`, color: sevCfg.color, border: `1px solid ${sevCfg.color}28`, fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px', flexShrink: 0 }}>
                                      {sevCfg.label}
                                    </Tag>
                                    {statusCfg && (
                                      <Tag style={{ background: `${statusCfg.color}14`, color: statusCfg.color, border: `1px solid ${statusCfg.color}28`, fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px', flexShrink: 0 }}>
                                        {statusCfg.label}
                                      </Tag>
                                    )}
                                  </div>
                                  {alert.status === 'pending' || alert.status === 'processing' ? (
                                    <Popconfirm
                                      title="确认此告警？"
                                      onConfirm={() => handleAcknowledge(alert.id)}
                                      okText="确认"
                                      cancelText="取消"
                                    >
                                      <Tooltip title="确认此告警">
                                      <Button type="link" size="small" style={{ color: '#1E40AF', fontSize: 12, padding: 0, flexShrink: 0 }}>
                                        确认
                                      </Button>
                                    </Tooltip>
                                    </Popconfirm>
                                  ) : (
                                    <span style={{ fontSize: 12, color: '#94A3B8', flexShrink: 0 }}>—</span>
                                  )}
                                </div>
                                <div style={{ fontSize: 13, color: '#334155', lineHeight: 1.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {alert.message || '—'}
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                  <span style={{ fontFamily: 'var(--font-mono)', color: '#64748B', fontSize: 11 }}>
                                    {alert.id ? alert.id.slice(0, 12) : '—'}
                                  </span>
                                  <span style={{ fontFamily: 'var(--font-mono)', color: '#94A3B8', fontSize: 11 }}>
                                    {alert.created_at
                                      ? new Date(alert.created_at).toLocaleString('zh-CN', {
                                          month: '2-digit',
                                          day: '2-digit',
                                          hour: '2-digit',
                                          minute: '2-digit',
                                        })
                                      : '—'}
                                  </span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                      {alerts.length > ALERT_PAGE_SIZE && (
                        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
                          <Pagination current={alertPage} pageSize={ALERT_PAGE_SIZE} total={alerts.length} onChange={setAlertPage} size="small" showTotal={t => `共 ${t} 条`} />
                        </div>
                      )}
                      </>
                    )}
                  </div>
                ),
              },
              {
                key: 'rules',
                label: <span style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>告警规则</span>,
                children: (
                  <div className="page-table fade-in-up stagger-5">
                    <Table
                      dataSource={rules}
                      columns={ruleColumns}
                      rowKey="id"
                      loading={rulesLoading}
                      size="middle"
                      pagination={{ pageSize: 12 }}
                      onHeaderRow={() => ({
                        onClick: () => fetchRules(),
                      })}
                    />
                  </div>
                ),
              },
            ]}
          />
        </div>
      </div>
    </div>
  );
};

export default AlertCenter;
