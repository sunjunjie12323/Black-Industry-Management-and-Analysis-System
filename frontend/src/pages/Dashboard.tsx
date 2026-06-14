import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { Table, Empty, Button, Skeleton, message } from 'antd';
import {
  PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  DatabaseOutlined, AlertOutlined, ApartmentOutlined, ShareAltOutlined,
  ReloadOutlined, SafetyCertificateOutlined, ArrowUpOutlined,
  ClockCircleOutlined, PieChartOutlined, LineChartOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { dashboardApi } from '../services/api';
import type { DashboardStats, IntelligenceItem } from '../types';

const THREAT_COLORS: Record<string, string> = {
  critical: '#E5484D',
  high: '#F76B15',
  medium: '#E5A000',
  low: '#34D399',
  info: '#3B82F6',
};

const THREAT_LABELS: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const TOOLTIP_STYLE: React.CSSProperties = {
  background: 'var(--bg-1, #141625)',
  border: '1px solid var(--glass-border, rgba(108,92,231,0.10))',
  borderRadius: 12,
  fontSize: 12,
  color: 'var(--text-0, #E8E9ED)',
  fontFamily: 'var(--font-body, "Inter", sans-serif)',
  padding: '10px 14px',
  boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
  backdropFilter: 'blur(12px)',
};

const NUM: React.CSSProperties = {
  fontFamily: 'var(--font-number, "Space Grotesk", monospace)',
  fontVariantNumeric: 'tabular-nums',
};

const CARD_BASE: React.CSSProperties = {
  background: 'var(--glass-bg, rgba(20,22,37,0.80))',
  borderRadius: 'var(--radius, 12px)',
  border: '1px solid var(--glass-border, rgba(108,92,231,0.10))',
  boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
  backdropFilter: 'blur(12px)',
  overflow: 'hidden',
};

const SparklineDecoration: React.FC<{ color: string }> = ({ color }) => (
  <svg width="120" height="40" viewBox="0 0 120 40" style={{ opacity: 0.35, flexShrink: 0 }}>
    <defs>
      <linearGradient id={`spark-grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stopColor={color} stopOpacity={0.4} />
        <stop offset="100%" stopColor={color} stopOpacity={0} />
      </linearGradient>
    </defs>
    <path
      d="M0 35 Q15 30 25 25 T50 18 T75 22 T100 10 T120 5"
      fill="none"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
    />
    <path
      d="M0 35 Q15 30 25 25 T50 18 T75 22 T100 10 T120 5 L120 40 L0 40Z"
      fill={`url(#spark-grad-${color.replace('#', '')})`}
    />
  </svg>
);

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [threatDist, setThreatDist] = useState<Record<string, number>>({});
  const [trendData, setTrendData] = useState<Array<{ date: string; critical: number; high: number; medium: number; total: number }>>([]);
  const [recentItems, setRecentItems] = useState<IntelligenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const isMountedRef = useRef(true);

  const fetchData = useCallback(async () => {
    const results = await Promise.allSettled([
      dashboardApi.getStats(),
      dashboardApi.getThreatDistribution(),
      dashboardApi.getTrend(7),
      dashboardApi.getRecentIntelligence(10),
    ]);

    if (!isMountedRef.current) return;

    const [statsRes, distRes, trendRes, recentRes] = results;

    if (statsRes.status === 'fulfilled') setStats(statsRes.value);
    if (distRes.status === 'fulfilled') setThreatDist(distRes.value?.threat_levels || {});
    if (trendRes.status === 'fulfilled') setTrendData(Array.isArray(trendRes.value?.trend) ? trendRes.value.trend : []);
    if (recentRes.status === 'fulfilled') setRecentItems(Array.isArray(recentRes.value?.items) ? recentRes.value.items : []);

    const rejected = results.filter(r => r.status === 'rejected');
    if (rejected.length > 0) {
      message.error(`${rejected.length}项数据加载失败，请稍后刷新`);
    }

    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => {
      isMountedRef.current = false;
      clearInterval(iv);
    };
  }, [fetchData]);

  const pieData = useMemo(() => Object.entries(threatDist).map(([name, value]) => ({
    name: THREAT_LABELS[name] || name,
    value,
    color: THREAT_COLORS[name] || '#64748B',
  })), [threatDist]);

  const formatTrendDate = useCallback((dateStr: string) => {
    try {
      const d = new Date(dateStr);
      return `${d.getMonth() + 1}/${d.getDate()}`;
    } catch {
      return dateStr;
    }
  }, []);

  const threatLevelTag = useCallback((level: string | null | undefined) => {
    if (!level) return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 10px',
        borderRadius: 20,
        background: 'var(--bg-3, rgba(255,255,255,0.06))',
        color: 'var(--text-2, #7C7F9A)',
        fontSize: 12,
        fontWeight: 500,
        ...NUM,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--text-3, #7C7F9A)', flexShrink: 0 }} />
        未分级
      </span>
    );
    const color = THREAT_COLORS[level] || '#64748B';
    return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '3px 12px',
        borderRadius: 20,
        background: `${color}1A`,
        color,
        fontSize: 12,
        fontWeight: 600,
        ...NUM,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
        {THREAT_LABELS[level] || level}
      </span>
    );
  }, []);

  const columns = useMemo(() => [
    {
      title: '等级',
      dataIndex: 'threat_level',
      key: 'threat_level',
      width: 100,
      render: (v: string | null | undefined) => threatLevelTag(v),
    },
    {
      title: '内容',
      dataIndex: 'content',
      key: 'content',
      ellipsis: true,
      render: (v: string) => (
        <span style={{ color: 'var(--text-1, #C8C9D0)', fontSize: 13, ...NUM }} title={v}>
          {v && v.length > 80 ? v.slice(0, 80) + '…' : v || '—'}
        </span>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120,
      render: (v: string | null | undefined) => (
        <span style={{ color: 'var(--text-2, #7C7F9A)', ...NUM, fontSize: 12 }}>
          {v || '—'}
        </span>
      ),
    },
    {
      title: '时间',
      dataIndex: 'collected_at',
      key: 'collected_at',
      width: 130,
      render: (v: string | null | undefined) => (
        <span style={{ color: 'var(--text-3, #7C7F9A)', ...NUM, fontSize: 12 }}>
          {v ? new Date(v).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—'}
        </span>
      ),
    },
  ], [threatLevelTag]);

  const smallStats = useMemo(() => [
    {
      label: '高危告警',
      value: stats?.threat_alerts ?? 0,
      icon: <AlertOutlined />,
      color: '#E5484D',
      suffix: undefined,
    },
    {
      label: '实体数量',
      value: stats?.knowledge_graph?.node_count ?? 0,
      icon: <ApartmentOutlined />,
      color: '#3B82F6',
      suffix: `${stats?.knowledge_graph?.edge_count ?? 0} 边`,
    },
    {
      label: '知识图谱',
      value: stats?.knowledge_graph?.edge_count ?? 0,
      icon: <ShareAltOutlined />,
      color: '#34D399',
      suffix: undefined,
    },
  ], [stats]);

  if (loading) {
    return (
      <div style={{ padding: '32px 40px', background: 'var(--bg-0, #0B0D17)', minHeight: '100vh' }}>
        <Skeleton.Input active style={{ width: 160, height: 28 }} />
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 16, marginTop: 24 }}>
          <div style={{
            padding: 28,
            background: 'var(--glass-bg, rgba(20,22,37,0.80))',
            borderRadius: 'var(--radius, 12px)',
            border: '1px solid var(--glass-border, rgba(108,92,231,0.10))',
            backdropFilter: 'blur(12px)',
          }}>
            <Skeleton.Input active size="small" style={{ width: 80, height: 12 }} />
            <Skeleton.Input active size="small" style={{ width: 120, height: 44, marginTop: 16 }} />
          </div>
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} style={{
              padding: 24,
              background: 'var(--glass-bg, rgba(20,22,37,0.80))',
              borderRadius: 'var(--radius, 12px)',
              border: '1px solid var(--glass-border, rgba(108,92,231,0.10))',
              backdropFilter: 'blur(12px)',
            }}>
              <Skeleton.Input active size="small" style={{ width: 60, height: 10 }} />
              <Skeleton.Input active size="small" style={{ width: 80, height: 32, marginTop: 12 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div style={{ background: 'var(--bg-0, #0B0D17)', minHeight: '100vh' }}>
      <style>{`
        @keyframes dashFadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes dashNumReveal {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes dashPulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
        .dash-table .ant-table-thead > tr > th {
          background: var(--bg-2, #1C1F35) !important;
          border-bottom: 1px solid var(--border, rgba(255,255,255,0.06)) !important;
          font-family: var(--font-mono, "JetBrains Mono", monospace) !important;
          font-size: 11px !important;
          font-weight: 600 !important;
          color: var(--text-3, #7C7F9A) !important;
          text-transform: uppercase !important;
          letter-spacing: 0.08em !important;
          padding: 12px 20px !important;
        }
        .dash-table .ant-table-tbody > tr > td {
          border-bottom: 1px solid var(--border, rgba(255,255,255,0.06)) !important;
          padding: 14px 20px !important;
          background: transparent !important;
          transition: all 0.15s ease !important;
        }
        .dash-table .ant-table-tbody > tr > td:first-child {
          border-left: 3px solid transparent !important;
          transition: border-color 0.15s ease, background 0.15s ease !important;
        }
        .dash-table .ant-table-tbody > tr:hover > td {
          background: var(--bg-2, #1C1F35) !important;
        }
        .dash-table .ant-table-tbody > tr:hover > td:first-child {
          border-left-color: var(--accent, #6C5CE7) !important;
        }
        .dash-table .ant-table {
          background: transparent !important;
        }
        .dash-table .ant-table-container {
          border: none !important;
        }
        .dash-table .ant-table-content {
          border: none !important;
          border-radius: 0 !important;
        }
        .dash-table .recharts-legend-item-text {
          color: var(--text-2, #7C7F9A) !important;
          font-family: var(--font-number, "Space Grotesk", monospace) !important;
          font-size: 12px !important;
        }
      `}</style>

      {/* Header */}
      <div style={{
        padding: '28px 40px 0',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 42,
            height: 42,
            borderRadius: 12,
            background: 'linear-gradient(135deg, #6C5CE7, #5A4BD6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#FFFFFF',
            fontSize: 18,
            boxShadow: '0 4px 12px rgba(108,92,231,0.35)',
          }}>
            <SafetyCertificateOutlined />
          </div>
          <div>
            <h1 style={{
              fontSize: 24,
              fontWeight: 700,
              fontFamily: 'var(--font-display, "Space Grotesk", sans-serif)',
              color: 'var(--text-0, #E8E9ED)',
              margin: 0,
              lineHeight: 1.2,
              letterSpacing: '-0.03em',
            }}>
              态势总览
            </h1>
            <p style={{
              fontSize: 13,
              color: 'var(--text-2, #7C7F9A)',
              margin: 0,
              lineHeight: 1.4,
              ...NUM,
            }}>
              威胁情报实时监控面板
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {lastRefresh && (
            <span style={{
              fontSize: 12,
              color: 'var(--text-3, #7C7F9A)',
              ...NUM,
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}>
              <span style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#34D399',
                animation: 'dashPulse 2s ease infinite',
              }} />
              <ClockCircleOutlined style={{ fontSize: 11 }} />
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={fetchData}
            aria-label="刷新数据"
            style={{
              background: 'var(--bg-2, #1C1F35)',
              border: '1px solid var(--border-hover, rgba(108,92,231,0.35))',
              cursor: 'pointer',
              ...NUM,
              fontSize: 13,
              fontWeight: 500,
              color: 'var(--text-1, #C8C9D0)',
              padding: '8px 18px',
              borderRadius: 10,
              lineHeight: 1,
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              transition: 'all var(--transition-spring, 0.35s cubic-bezier(0.22, 1, 0.36, 1))',
              boxShadow: '0 1px 3px rgba(0,0,0,0.15)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'var(--accent, #6C5CE7)';
              e.currentTarget.style.color = 'var(--accent, #6C5CE7)';
              e.currentTarget.style.background = 'var(--accent-dim, rgba(108,92,231,0.12))';
              e.currentTarget.style.boxShadow = '0 2px 12px rgba(108,92,231,0.25)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-hover, rgba(108,92,231,0.35))';
              e.currentTarget.style.color = 'var(--text-1, #C8C9D0)';
              e.currentTarget.style.background = 'var(--bg-2, #1C1F35)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.15)';
            }}
          >
            <ReloadOutlined style={{ fontSize: 12 }} />
            刷新
          </button>
        </div>
      </div>

      {/* Hero Stats - Bento Grid */}
      <div style={{ padding: '24px 40px 0' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr 1fr',
          gridTemplateRows: 'auto',
          gap: 16,
        }}>
          {/* LARGE card - 情报总量 */}
          <div
            style={{
              ...CARD_BASE,
              position: 'relative',
              padding: '28px 32px',
              background: 'linear-gradient(135deg, rgba(108,92,231,0.12) 0%, rgba(108,92,231,0.03) 50%, var(--glass-bg, rgba(20,22,37,0.80)) 100%)',
              animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
              transition: 'all var(--transition-spring, 0.35s cubic-bezier(0.22, 1, 0.36, 1))',
              cursor: 'default',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 8px 24px rgba(108,92,231,0.2)';
              e.currentTarget.style.borderColor = 'rgba(108,92,231,0.35)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 4px 16px rgba(0,0,0,0.2)';
              e.currentTarget.style.borderColor = 'rgba(108,92,231,0.10)';
            }}
          >
            <div style={{
              position: 'absolute',
              top: -30,
              right: -20,
              width: 140,
              height: 140,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(108,92,231,0.12) 0%, transparent 70%)',
              pointerEvents: 'none',
            }} />
            <div style={{
              position: 'absolute',
              bottom: -40,
              right: 60,
              width: 120,
              height: 120,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(108,92,231,0.08) 0%, transparent 70%)',
              pointerEvents: 'none',
            }} />

            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
                  <span style={{
                    width: 38,
                    height: 38,
                    borderRadius: 10,
                    background: 'rgba(108,92,231,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent, #6C5CE7)',
                    fontSize: 17,
                    flexShrink: 0,
                  }}>
                    <DatabaseOutlined />
                  </span>
                  <span style={{
                    ...NUM,
                    fontSize: 13,
                    fontWeight: 500,
                    color: 'var(--text-2, #7C7F9A)',
                  }}>
                    情报总量
                  </span>
                </div>

                <div style={{
                  display: 'flex',
                  alignItems: 'baseline',
                  gap: 10,
                  animation: 'dashNumReveal 0.4s cubic-bezier(0.22, 1, 0.36, 1) both',
                  animationDelay: '100ms',
                }}>
                  <span style={{
                    ...NUM,
                    fontSize: 48,
                    fontWeight: 700,
                    color: 'var(--text-0, #E8E9ED)',
                    lineHeight: 1,
                    letterSpacing: '-0.03em',
                  }}>
                    {(stats?.total_intelligence ?? 0).toLocaleString()}
                  </span>
                  {stats?.total_intelligence ? (
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '4px 10px',
                      borderRadius: 20,
                      background: 'rgba(48,164,108,0.12)',
                    }}>
                      <ArrowUpOutlined style={{ fontSize: 10, color: '#34D399' }} />
                      <span style={{
                        ...NUM,
                        fontSize: 12,
                        color: '#34D399',
                        fontWeight: 600,
                      }}>
                        12.5%
                      </span>
                    </span>
                  ) : null}
                </div>

                <p style={{
                  ...NUM,
                  fontSize: 12,
                  color: 'var(--text-3, #7C7F9A)',
                  margin: '10px 0 0',
                  lineHeight: 1,
                }}>
                  较上周增长
                </p>
              </div>

              <div style={{ marginTop: 8 }}>
                <SparklineDecoration color="#6C5CE7" />
              </div>
            </div>
          </div>

          {/* Three smaller cards */}
          {smallStats.map((card, idx) => (
            <div
              key={card.label}
              style={{
                ...CARD_BASE,
                position: 'relative',
                padding: '24px 24px',
                background: 'var(--glass-bg, rgba(20,22,37,0.80))',
                animation: `dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both`,
                animationDelay: `${(idx + 1) * 80}ms`,
                transition: 'all var(--transition-spring, 0.35s cubic-bezier(0.22, 1, 0.36, 1))',
                cursor: 'default',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = `0 8px 24px ${card.color}20`;
                e.currentTarget.style.borderColor = `${card.color}40`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 4px 16px rgba(0,0,0,0.2)';
                e.currentTarget.style.borderColor = 'rgba(108,92,231,0.10)';
              }}
            >
              <div style={{
                position: 'absolute',
                top: -15,
                right: -15,
                width: 60,
                height: 60,
                borderRadius: '50%',
                background: `${card.color}10`,
                pointerEvents: 'none',
              }} />

              <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 16 }}>
                <span style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: `${card.color}18`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: card.color,
                  fontSize: 14,
                  flexShrink: 0,
                }}>
                  {card.icon}
                </span>
                <span style={{
                  ...NUM,
                  fontSize: 12,
                  fontWeight: 500,
                  color: 'var(--text-2, #7C7F9A)',
                }}>
                  {card.label}
                </span>
              </div>

              <div style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 6,
                animation: `dashNumReveal 0.4s cubic-bezier(0.22, 1, 0.36, 1) both`,
                animationDelay: `${(idx + 1) * 80 + 150}ms`,
              }}>
                <span style={{
                  ...NUM,
                  fontSize: 32,
                  fontWeight: 700,
                  color: 'var(--text-0, #E8E9ED)',
                  lineHeight: 1.1,
                  letterSpacing: '-0.02em',
                }}>
                  {card.value.toLocaleString()}
                </span>
                {card.suffix && (
                  <span style={{
                    ...NUM,
                    fontSize: 12,
                    fontWeight: 500,
                    color: 'var(--text-3, #7C7F9A)',
                  }}>
                    {card.suffix}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Charts Section */}
      <div style={{ padding: '20px 40px 0' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 3fr',
          gap: 16,
        }}>
          {/* Pie Chart Card */}
          <div style={{
            ...CARD_BASE,
            animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
            animationDelay: '0.2s',
          }}>
            <div style={{
              height: 3,
              background: 'linear-gradient(90deg, #E5484D, #F76B15, #E5A000, #34D399, #3B82F6)',
            }} />
            <div style={{
              padding: '18px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <PieChartOutlined style={{ fontSize: 14, color: '#E5484D' }} />
                <h2 style={{
                  fontSize: 15,
                  fontWeight: 600,
                  fontFamily: 'var(--font-display, "Space Grotesk", sans-serif)',
                  color: 'var(--text-0, #E8E9ED)',
                  margin: 0,
                  lineHeight: 1,
                }}>
                  威胁等级分布
                </h2>
              </div>
              {pieData.length > 0 && (
                <span style={{
                  ...NUM,
                  fontSize: 12,
                  color: 'var(--text-3, #7C7F9A)',
                }}>
                  {pieData.reduce((s, d) => s + d.value, 0)} 条
                </span>
              )}
            </div>
            <div style={{ padding: '8px 24px 20px', position: 'relative' }}>
              {pieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={240}>
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={82}
                        paddingAngle={3}
                        dataKey="value"
                        stroke="none"
                        isAnimationActive={true}
                        animationBegin={400}
                        animationDuration={1000}
                        animationEasing="ease-out"
                      >
                        {pieData.map((d, i) => (
                          <Cell key={i} fill={d.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Legend
                        iconType="circle"
                        iconSize={6}
                        wrapperStyle={{
                          fontSize: 12,
                          ...NUM,
                          color: 'var(--text-2, #7C7F9A)',
                          paddingTop: 8,
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{
                    position: 'absolute',
                    bottom: 0,
                    left: 0,
                    right: 0,
                    height: 40,
                    background: 'linear-gradient(to top, var(--glass-bg, rgba(20,22,37,0.80)), transparent)',
                    pointerEvents: 'none',
                    borderRadius: '0 0 12px 12px',
                  }} />
                </>
              ) : (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: 240,
                  gap: 12,
                }}>
                  <PieChartOutlined style={{ fontSize: 40, color: 'var(--text-3, #7C7F9A)' }} />
                  <span style={{
                    color: 'var(--text-3, #7C7F9A)',
                    fontSize: 13,
                    ...NUM,
                  }}>
                    暂无威胁分布数据
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Trend Chart Card */}
          <div style={{
            ...CARD_BASE,
            animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
            animationDelay: '0.28s',
          }}>
            <div style={{
              height: 3,
              background: 'linear-gradient(90deg, #6C5CE7, #3B82F6)',
            }} />
            <div style={{
              padding: '18px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <LineChartOutlined style={{ fontSize: 14, color: 'var(--accent, #6C5CE7)' }} />
                <h2 style={{
                  fontSize: 15,
                  fontWeight: 600,
                  fontFamily: 'var(--font-display, "Space Grotesk", sans-serif)',
                  color: 'var(--text-0, #E8E9ED)',
                  margin: 0,
                  lineHeight: 1,
                }}>
                  七日趋势
                </h2>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: '#34D399',
                  animation: 'dashPulse 2s ease infinite',
                }} />
                <span style={{
                  ...NUM,
                  fontSize: 12,
                  color: 'var(--text-3, #7C7F9A)',
                }}>
                  实时更新
                </span>
              </div>
            </div>
            <div style={{ padding: '8px 24px 12px', position: 'relative' }}>
              {trendData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={260}>
                    <AreaChart data={trendData}>
                      <defs>
                        <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent, #6C5CE7)" stopOpacity={0.25} />
                          <stop offset="100%" stopColor="var(--accent, #6C5CE7)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                      <XAxis
                        dataKey="date"
                        tickFormatter={formatTrendDate}
                        tick={{ fill: 'var(--text-3, #7C7F9A)', fontSize: 11, fontFamily: 'var(--font-number, "Space Grotesk", monospace)' }}
                        axisLine={{ stroke: 'rgba(255,255,255,0.06)' }}
                        tickLine={false}
                      />
                      <YAxis
                        tick={{ fill: 'var(--text-3, #7C7F9A)', fontSize: 11, fontFamily: 'var(--font-number, "Space Grotesk", monospace)' }}
                        axisLine={false}
                        tickLine={false}
                        width={36}
                      />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Area
                        type="monotone"
                        dataKey="total"
                        stroke="var(--accent, #6C5CE7)"
                        strokeWidth={2.5}
                        fill="url(#trendGrad)"
                        name="总量"
                        dot={false}
                        activeDot={{ r: 5, fill: 'var(--accent, #6C5CE7)', stroke: 'var(--bg-1, #141625)', strokeWidth: 2 }}
                        isAnimationActive={true}
                        animationBegin={400}
                        animationDuration={1000}
                        animationEasing="ease-out"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                  <div style={{
                    position: 'absolute',
                    bottom: 0,
                    left: 0,
                    right: 0,
                    height: 40,
                    background: 'linear-gradient(to top, var(--glass-bg, rgba(20,22,37,0.80)), transparent)',
                    pointerEvents: 'none',
                    borderRadius: '0 0 12px 12px',
                  }} />
                </>
              ) : (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: 260,
                  gap: 12,
                }}>
                  <LineChartOutlined style={{ fontSize: 40, color: 'var(--text-3, #7C7F9A)' }} />
                  <span style={{
                    color: 'var(--text-3, #7C7F9A)',
                    fontSize: 13,
                    ...NUM,
                  }}>
                    暂无趋势数据
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div style={{ padding: '20px 40px 32px' }}>
        <div style={{
          ...CARD_BASE,
          animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
          animationDelay: '0.36s',
        }}>
          <div style={{
            height: 3,
            background: 'linear-gradient(90deg, #3B82F6, #6C5CE7)',
          }} />
          <div style={{
            padding: '18px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <UnorderedListOutlined style={{ fontSize: 14, color: 'var(--accent-blue, #3B82F6)' }} />
              <h2 style={{
                fontSize: 15,
                fontWeight: 600,
                fontFamily: 'var(--font-display, "Space Grotesk", sans-serif)',
                color: 'var(--text-0, #E8E9ED)',
                margin: 0,
                lineHeight: 1,
              }}>
                最近情报
              </h2>
            </div>
            <span
              role="button"
              tabIndex={0}
              aria-label="查看全部情报"
              style={{
                ...NUM,
                fontSize: 13,
                color: 'var(--accent, #6C5CE7)',
                cursor: 'pointer',
                padding: '6px 16px',
                borderRadius: 20,
                background: 'var(--accent-dim, rgba(108,92,231,0.12))',
                transition: 'all var(--transition-spring, 0.35s cubic-bezier(0.22, 1, 0.36, 1))',
                lineHeight: 1,
                fontWeight: 500,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'var(--accent, #6C5CE7)';
                e.currentTarget.style.color = '#FFFFFF';
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(108,92,231,0.35)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'var(--accent-dim, rgba(108,92,231,0.12))';
                e.currentTarget.style.color = 'var(--accent, #6C5CE7)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              查看全部 →
            </span>
          </div>

          <div>
            {recentItems.length > 0 ? (
              <Table
                dataSource={recentItems}
                columns={columns}
                rowKey="id"
                pagination={false}
                size="middle"
                className="dash-table"
                style={{
                  fontSize: 13,
                  ...NUM,
                  background: 'transparent',
                }}
              />
            ) : (
              <div style={{ padding: '64px 0', textAlign: 'center' }}>
                <Empty
                  description={
                    <span style={{ color: 'var(--text-3, #7C7F9A)', ...NUM, fontSize: 13 }}>
                      暂无情报数据，请先采集情报
                    </span>
                  }
                  image={<UnorderedListOutlined style={{ fontSize: 48, color: 'var(--text-3, #7C7F9A)' }} />}
                >
                  <Button
                    onClick={fetchData}
                    style={{
                      ...NUM,
                      fontSize: 13,
                      border: '1px solid var(--border-hover, rgba(108,92,231,0.35))',
                      borderRadius: 10,
                      background: 'var(--bg-2, #1C1F35)',
                      color: 'var(--text-1, #C8C9D0)',
                      boxShadow: '0 1px 3px rgba(0,0,0,0.15)',
                      height: 38,
                      padding: '0 22px',
                      fontWeight: 500,
                    }}
                  >
                    刷新数据
                  </Button>
                </Empty>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
