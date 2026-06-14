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
  critical: { color: '#EF4444', label: '严重' },
  high: { color: '#F97316', label: '高危' },
  medium: { color: '#F97316', label: '中危' },
  low: { color: '#22C55E', label: '低危' },
};

const STATUS_MAP: Record<string, { color: string; label: string }> = {
  pending: { color: '#F97316', label: '待处理' },
  processing: { color: '#6C5CE7', label: '处理中' },
  acknowledged: { color: '#22C55E', label: '已确认' },
  resolved: { color: '#7C7F9A', label: '已处理' },
  ignored: { color: '#7C7F9A', label: '已忽略' },
};

const TOOLTIP_STYLE: React.CSSProperties = {
  background: '#1C1F35',
  border: '1px solid rgba(255,255,255,0.06)',
  borderRadius: 8,
  fontSize: 12,
  color: '#E8E9ED',
  fontFamily: 'var(--font-body)',
  padding: '10px 14px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
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
  const mountedRef = useRef(true);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [stats, setStats] = useState<Record<string, number>>({});
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [alertPage, setAlertPage] = useState(1);
  const ALERT_PAGE_SIZE = 12;
  const bannerRef = useRef<HTMLDivElement>(null);
  const timelineRef = useRef<HTMLDivElement>(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    const [alertRes, statsRes] = await Promise.allSettled([
      api.alerts.getActive(severityFilter),
      api.alerts.getStats(),
    ]);
    if (!mountedRef.current) { setLoading(false); return; }
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
    return () => { mountedRef.current = false; };
  }, [fetchAlerts]);

  useEffect(() => {
    if (bannerRef.current) {
      const tween = gsap.fromTo(bannerRef.current, { y: -8, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, ease: 'power2.out' });
      return () => { tween.kill(); };
    }
  }, []);

  useEffect(() => {
    if (timelineRef.current) {
      const items = timelineRef.current.querySelectorAll('.timeline-alert-item');
      const tween = gsap.fromTo(items, { x: -12, opacity: 0 }, { x: 0, opacity: 1, duration: 0.3, stagger: 0.03, ease: 'power2.out' });
      return () => { tween.kill(); };
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
  const lowCount = stats.low ?? alerts.filter(a => a.severity === 'low').length;
  const activeTotal = alerts.length;

  const statItems = [
    { label: '活跃告警', value: activeTotal, icon: <BellOutlined />, color: '#6C5CE7' },
    { label: '严重', value: criticalCount, icon: <ExclamationCircleOutlined />, color: '#EF4444' },
    { label: '高危', value: highCount, icon: <WarningOutlined />, color: '#F97316' },
    { label: '中危', value: mediumCount, icon: <ThunderboltOutlined />, color: '#F97316' },
  ];

  const severityPieData = Object.entries(stats).length > 0
    ? Object.entries(stats).map(([name, value]) => ({
        name: SEVERITY_MAP[name]?.label || name,
        value,
        color: SEVERITY_MAP[name]?.color || '#7C7F9A',
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
          color: SEVERITY_MAP[name]?.color || '#7C7F9A',
        }))
      : [];

  const severityTabs = [
    { key: undefined, label: '全部', count: activeTotal, color: '#E8E9ED' },
    { key: 'critical', label: '严重', count: criticalCount, color: '#EF4444' },
    { key: 'high', label: '高危', count: highCount, color: '#F97316' },
    { key: 'medium', label: '中危', count: mediumCount, color: '#F97316' },
    { key: 'low', label: '低危', count: lowCount, color: '#22C55E' },
  ];

  const ruleColumns = [
    {
      title: '规则名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string) => (
        <span style={{ color: '#E8E9ED', fontSize: 13 }}>{v || '—'}</span>
      ),
    },
    {
      title: '触发条件',
      dataIndex: 'condition',
      ellipsis: true,
      render: (v: string) => (
        <span style={{
          color: '#7C7F9A',
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
          <Tag style={{ background: 'rgba(28,31,53,0.5)', border: '1px solid rgba(255,255,255,0.06)', color: '#7C7F9A', borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>{v || '—'}</Tag>
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

  const pagedAlerts = alerts.slice((alertPage - 1) * ALERT_PAGE_SIZE, alertPage * ALERT_PAGE_SIZE);

  return (
    <div style={{ minHeight: '100%', padding: 0, background: '#0B0D17', overflowX: 'hidden' }}>
      <style>{`
        .timeline-alert-item {
          transition: all 0.2s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }
        .timeline-alert-item:hover {
          transform: translateX(4px);
          box-shadow: 0 4px 16px rgba(0,0,0,0.25);
        }
        .severity-pill {
          transition: all 0.2s ease;
          cursor: pointer;
          user-select: none;
        }
        .severity-pill:hover {
          transform: translateY(-1px);
          box-shadow: 0 2px 8px rgba(0,0,0,0.25);
        }
        .severity-pill.active {
          box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .mini-stat-block {
          transition: all 0.2s ease;
        }
        .mini-stat-block:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.25);
        }
      `}</style>

      <div ref={bannerRef} style={{
        height: 60,
        background: 'rgba(20,22,37,0.80)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '0 32px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'sticky',
        top: 0,
        zIndex: 10,
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h1 style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-body)', color: '#E8E9ED', margin: 0, lineHeight: 1 }}>
            告警中心
          </h1>
          {activeTotal > 0 && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              minWidth: 20,
              height: 20,
              padding: '0 6px',
              borderRadius: 10,
              background: '#EF4444',
              color: '#FFFFFF',
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'var(--font-mono)',
              lineHeight: '20px',
            }}>
              {activeTotal > 99 ? '99+' : activeTotal}
            </span>
          )}
          <span style={{ fontSize: 13, color: '#7C7F9A', marginLeft: 4 }}>
            实时威胁告警监控
          </span>
        </div>
        <Space size={6}>
          <Tooltip title="筛选严重等级">
            <Select
              placeholder="全部等级"
              value={severityFilter}
              onChange={setSeverityFilter}
              allowClear
              style={{ width: 120 }}
              size="small"
              options={Object.entries(SEVERITY_MAP).map(([k, v]) => ({
                label: v.label,
                value: k,
              }))}
            />
          </Tooltip>
          <Tooltip title="发送一条测试告警以验证告警系统是否正常工作">
            <Button
              size="small"
              icon={<ExperimentOutlined />}
              onClick={handleTestTrigger}
              style={{ borderRadius: 6 }}
              aria-label="测试触发"
            >
              测试触发
            </Button>
          </Tooltip>
          <Tooltip title="刷新数据">
            <Button
              size="small"
              icon={<ReloadOutlined />}
              onClick={fetchAlerts}
              style={{ borderRadius: 6 }}
              aria-label="刷新数据"
            >
              刷新
            </Button>
          </Tooltip>
          <Tooltip title="导出告警数据">
            <Button
              size="small"
              icon={<DownloadOutlined />}
              onClick={handleExportAlerts}
              style={{ borderRadius: 6 }}
              aria-label="导出告警"
            >
              导出
            </Button>
          </Tooltip>
        </Space>
      </div>

      <div style={{
        padding: '12px 32px',
        background: 'rgba(20,22,37,0.80)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        gap: 8,
        alignItems: 'center',
      }}>
        {severityTabs.map(tab => {
          const isActive = severityFilter === tab.key;
          return (
            <div
              key={tab.key ?? 'all'}
              className={`severity-pill ${isActive ? 'active' : ''}`}
              onClick={() => {
                setSeverityFilter(tab.key);
                setAlertPage(1);
              }}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 20,
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                fontFamily: 'var(--font-body)',
                background: isActive ? `${tab.color}14` : 'rgba(28,31,53,0.5)',
                color: isActive ? tab.color : '#7C7F9A',
                border: `1px solid ${isActive ? `${tab.color}40` : 'rgba(255,255,255,0.06)'}`,
                cursor: 'pointer',
              }}
            >
              {isActive && (
                <span style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: tab.color,
                  flexShrink: 0,
                }} />
              )}
              {tab.label}
              <span style={{
                fontSize: 11,
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
                color: isActive ? tab.color : '#7C7F9A',
                background: isActive ? `${tab.color}20` : 'rgba(255,255,255,0.06)',
                padding: '1px 6px',
                borderRadius: 10,
                lineHeight: '16px',
              }}>
                {tab.count}
              </span>
            </div>
          );
        })}
      </div>

      <div style={{ padding: '20px 32px 32px', display: 'flex', gap: 20, alignItems: 'flex-start' }}>

        <div style={{ flex: '0 0 65%', maxWidth: '65%', minWidth: 0 }}>
          <div style={{
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '14px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <BellOutlined style={{ color: '#7C7F9A', fontSize: 14 }} />
                <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: 'var(--font-body)' }}>
                  告警时间线
                </span>
                <span style={{ fontSize: 12, color: '#7C7F9A', fontFamily: 'var(--font-mono)' }}>
                  {alerts.length} 条记录
                </span>
              </div>
              {severityFilter && (
                <Tag
                  closable
                  onClose={() => setSeverityFilter(undefined)}
                  style={{
                    background: `${SEVERITY_MAP[severityFilter]?.color || '#7C7F9A'}14`,
                    color: SEVERITY_MAP[severityFilter]?.color || '#7C7F9A',
                    border: `1px solid ${SEVERITY_MAP[severityFilter]?.color || '#7C7F9A'}28`,
                    borderRadius: 20,
                    fontSize: 12,
                  }}
                >
                  {SEVERITY_MAP[severityFilter]?.label || severityFilter}
                </Tag>
              )}
            </div>

            <div style={{ padding: '8px 0' }}>
              {loading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
              ) : alerts.length === 0 ? (
                <div style={{ padding: '48px 0', textAlign: 'center' }}>
                  <Empty
                    description="暂无活跃告警，系统运行正常"
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                  >
                    <Tooltip title="发送一条测试告警以验证告警系统是否正常工作">
                      <Button type="primary" size="small" onClick={handleTestTrigger} icon={<ExperimentOutlined />}>测试触发</Button>
                    </Tooltip>
                  </Empty>
                </div>
              ) : (
                <>
                  <div ref={timelineRef}>
                    {pagedAlerts.map((alert, idx) => {
                      const sevCfg = SEVERITY_MAP[alert.severity] || SEVERITY_MAP.medium;
                      const statusCfg = STATUS_MAP[alert.status];
                      const isLast = idx === pagedAlerts.length - 1;
                      return (
                        <div
                          key={alert.id}
                          className="timeline-alert-item"
                          style={{
                            display: 'flex',
                            alignItems: 'stretch',
                            minHeight: 72,
                          }}
                        >
                          <div style={{
                            width: 48,
                            flexShrink: 0,
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            position: 'relative',
                          }}>
                            <div style={{
                              width: 10,
                              height: 10,
                              borderRadius: '50%',
                              background: sevCfg.color,
                              border: `2px solid ${sevCfg.color}30`,
                              marginTop: 20,
                              flexShrink: 0,
                              zIndex: 1,
                              boxShadow: `0 0 0 3px ${sevCfg.color}18`,
                            }} />
                            {!isLast && (
                              <div style={{
                                width: 2,
                                flex: 1,
                                background: 'linear-gradient(to bottom, rgba(255,255,255,0.06), rgba(255,255,255,0.02))',
                                marginTop: 4,
                              }} />
                            )}
                          </div>

                          <div style={{
                            flex: 1,
                            margin: '8px 16px 8px 0',
                            padding: '12px 16px',
                            background: 'rgba(28,31,53,0.5)',
                            borderRadius: 8,
                            border: '1px solid rgba(255,255,255,0.06)',
                            borderLeft: `3px solid ${sevCfg.color}`,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 6,
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                                <Tag style={{
                                  background: `${sevCfg.color}14`,
                                  color: sevCfg.color,
                                  border: `1px solid ${sevCfg.color}28`,
                                  fontSize: 11,
                                  borderRadius: 20,
                                  padding: '0 8px',
                                  lineHeight: '20px',
                                  flexShrink: 0,
                                  margin: 0,
                                }}>
                                  {sevCfg.label}
                                </Tag>
                                {statusCfg && (
                                  <Tag style={{
                                    background: `${statusCfg.color}14`,
                                    color: statusCfg.color,
                                    border: `1px solid ${statusCfg.color}28`,
                                    fontSize: 11,
                                    borderRadius: 20,
                                    padding: '0 8px',
                                    lineHeight: '20px',
                                    flexShrink: 0,
                                    margin: 0,
                                  }}>
                                    {statusCfg.label}
                                  </Tag>
                                )}
                              </div>
                              {(alert.status === 'pending' || alert.status === 'processing') ? (
                                <Popconfirm
                                  title="确认此告警？"
                                  onConfirm={() => handleAcknowledge(alert.id)}
                                  okText="确认"
                                  cancelText="取消"
                                >
                                  <Button type="link" size="small" style={{ color: '#6C5CE7', fontSize: 12, padding: 0, flexShrink: 0 }}>
                                    确认
                                  </Button>
                                </Popconfirm>
                              ) : (
                                <CheckCircleOutlined style={{ color: '#7C7F9A', fontSize: 14, flexShrink: 0 }} />
                              )}
                            </div>
                            <div style={{
                              fontSize: 13,
                              color: '#E8E9ED',
                              lineHeight: 1.5,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}>
                              {alert.message || '—'}
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontFamily: 'var(--font-mono)', color: '#7C7F9A', fontSize: 11 }}>
                                {alert.id ? alert.id.slice(0, 12) : '—'}
                              </span>
                              <span style={{ fontFamily: 'var(--font-mono)', color: '#7C7F9A', fontSize: 11 }}>
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
                    <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '8px 16px 12px' }}>
                      <Pagination
                        current={alertPage}
                        pageSize={ALERT_PAGE_SIZE}
                        total={alerts.length}
                        onChange={setAlertPage}
                        size="small"
                        showTotal={t => `共 ${t} 条`}
                      />
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        <div style={{ flex: '0 0 calc(35% - 20px)', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>

          <div style={{
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '14px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}>
              <ExclamationCircleOutlined style={{ color: '#7C7F9A', fontSize: 14 }} />
              <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: 'var(--font-body)' }}>
                严重度分布
              </span>
            </div>
            <div style={{ padding: '12px 16px 8px' }}>
              {severityPieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={severityPieData} margin={{ top: 4, right: 8, left: -8, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                    <XAxis dataKey="name" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                    <RechartsTooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                    <Bar dataKey="value" barSize={20} radius={[6, 6, 0, 0]} isAnimationActive={false} shape={<StaggeredBarShape radius={[6, 6, 0, 0]} />}>
                      {severityPieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
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
              padding: '14px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}>
              <CheckCircleOutlined style={{ color: '#7C7F9A', fontSize: 14 }} />
              <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: 'var(--font-body)' }}>
                处理概览
              </span>
            </div>
            <div style={{ padding: 16, display: 'flex', gap: 10 }}>
              {[
                { label: '待处理', value: alerts.filter(a => a.status === 'pending').length, color: '#F97316', bg: 'rgba(249,115,22,0.12)' },
                { label: '已确认', value: alerts.filter(a => a.status === 'acknowledged').length, color: '#22C55E', bg: 'rgba(34,197,94,0.12)' },
                { label: '已处理', value: alerts.filter(a => a.status === 'resolved').length, color: '#7C7F9A', bg: 'rgba(28,31,53,0.5)' },
              ].map(item => (
                <div
                  key={item.label}
                  className="mini-stat-block"
                  style={{
                    flex: 1,
                    padding: '14px 8px',
                    background: item.bg,
                    borderRadius: 8,
                    textAlign: 'center',
                    border: `1px solid ${item.color}20`,
                  }}
                >
                  <div style={{ fontSize: 11, color: item.color, fontWeight: 500, marginBottom: 6, fontFamily: 'var(--font-body)' }}>
                    {item.label}
                  </div>
                  <div style={{ fontSize: 24, fontFamily: 'var(--font-mono)', fontWeight: 700, color: item.color, lineHeight: 1 }}>
                    {item.value}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
            overflow: 'hidden',
          }}>
            <Collapse
              defaultActiveKey={[]}
              ghost
              items={[
                {
                  key: 'rules',
                  label: (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0' }}>
                      <ThunderboltOutlined style={{ color: '#7C7F9A', fontSize: 14 }} />
                      <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: 'var(--font-body)' }}>
                        告警规则
                      </span>
                      <span style={{ fontSize: 12, color: '#7C7F9A', fontFamily: 'var(--font-mono)' }}>
                        {rules.length} 条
                      </span>
                    </div>
                  ),
                  children: (
                    <Table
                      dataSource={rules}
                      columns={ruleColumns}
                      rowKey="id"
                      loading={rulesLoading}
                      size="small"
                      pagination={{ pageSize: 5 }}
                      onHeaderRow={() => ({
                        onClick: () => fetchRules(),
                      })}
                      style={{ fontSize: 12 }}
                    />
                  ),
                },
              ]}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertCenter;
