import React, { useEffect, useState } from 'react';
import { Table, Empty, Button, Skeleton, message } from 'antd';
import {
  PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  DatabaseOutlined, AlertOutlined, ApartmentOutlined, ShareAltOutlined,
  ReloadOutlined, SafetyCertificateOutlined, ArrowUpOutlined, ArrowDownOutlined,
  ThunderboltOutlined, ClockCircleOutlined, PieChartOutlined, LineChartOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { dashboardApi } from '../services/api';
import type { DashboardStats, IntelligenceItem } from '../types';

const THREAT_COLORS: Record<string, string> = {
  critical: '#E5484D',
  high: '#F76B15',
  medium: '#E5A000',
  low: '#30A46C',
  info: '#0090FF',
};

const THREAT_LABELS: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const TOOLTIP_STYLE: React.CSSProperties = {
  background: '#FFFFFF',
  border: '1px solid rgba(0,0,0,0.06)',
  borderRadius: 12,
  fontSize: 12,
  color: '#374151',
  fontFamily: '"DM Sans", sans-serif',
  padding: '10px 14px',
  boxShadow: '0 8px 32px rgba(0,0,0,0.08)',
};

const NUM: React.CSSProperties = {
  fontFamily: '"DM Sans", sans-serif',
  fontVariantNumeric: 'tabular-nums',
};

const CARD_BASE: React.CSSProperties = {
  background: '#FFFFFF',
  borderRadius: 16,
  border: '1px solid rgba(0,0,0,0.06)',
  boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
  overflow: 'hidden',
};

const SparklineDecoration: React.FC<{ color: string }> = ({ color }) => (
  <svg width="120" height="40" viewBox="0 0 120 40" style={{ opacity: 0.2, flexShrink: 0 }}>
    <defs>
      <linearGradient id={`spark-grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stopColor={color} stopOpacity={0.3} />
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

  const fetchData = async () => {
    const results = await Promise.allSettled([
      dashboardApi.getStats(),
      dashboardApi.getThreatDistribution(),
      dashboardApi.getTrend(7),
      dashboardApi.getRecentIntelligence(10),
    ]);

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
  };

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, []);

  const pieData = Object.entries(threatDist).map(([name, value]) => ({
    name: THREAT_LABELS[name] || name,
    value,
    color: THREAT_COLORS[name] || '#64748B',
  }));

  const formatTrendDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      return `${d.getMonth() + 1}/${d.getDate()}`;
    } catch {
      return dateStr;
    }
  };

  const threatLevelTag = (level: string | null | undefined) => {
    if (!level) return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 10px',
        borderRadius: 20,
        background: '#F3F4F6',
        color: '#6B7280',
        fontSize: 12,
        fontWeight: 500,
        ...NUM,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#9CA3AF', flexShrink: 0 }} />
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
        background: `${color}0D`,
        color,
        fontSize: 12,
        fontWeight: 600,
        ...NUM,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
        {THREAT_LABELS[level] || level}
      </span>
    );
  };

  const columns = [
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
        <span style={{ color: '#374151', fontSize: 13, ...NUM }} title={v}>
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
        <span style={{ color: '#6B7280', ...NUM, fontSize: 12 }}>
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
        <span style={{ color: '#9CA3AF', ...NUM, fontSize: 12 }}>
          {v ? new Date(v).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—'}
        </span>
      ),
    },
  ];

  const smallStats = [
    {
      label: '高危告警',
      value: stats?.threat_alerts ?? 0,
      icon: <AlertOutlined />,
      color: '#E5484D',
      bg: 'linear-gradient(135deg, rgba(229,72,77,0.06) 0%, rgba(229,72,77,0.01) 100%)',
    },
    {
      label: '实体数量',
      value: stats?.knowledge_graph?.node_count ?? 0,
      icon: <ApartmentOutlined />,
      color: '#0090FF',
      suffix: `${stats?.knowledge_graph?.edge_count ?? 0} 边`,
      bg: 'linear-gradient(135deg, rgba(0,144,255,0.06) 0%, rgba(0,144,255,0.01) 100%)',
    },
    {
      label: '知识图谱',
      value: stats?.knowledge_graph?.edge_count ?? 0,
      icon: <ShareAltOutlined />,
      color: '#30A46C',
      bg: 'linear-gradient(135deg, rgba(48,164,108,0.06) 0%, rgba(48,164,108,0.01) 100%)',
    },
  ];

  if (loading) {
    return (
      <div style={{ padding: '32px 40px', background: '#F8F9FA', minHeight: '100vh' }}>
        <Skeleton.Input active style={{ width: 160, height: 28 }} />
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 16, marginTop: 24 }}>
          <div style={{ padding: 28, background: '#FFF', borderRadius: 16, border: '1px solid rgba(0,0,0,0.06)' }}>
            <Skeleton.Input active size="small" style={{ width: 80, height: 12 }} />
            <Skeleton.Input active size="small" style={{ width: 120, height: 44, marginTop: 16 }} />
          </div>
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} style={{ padding: 24, background: '#FFF', borderRadius: 16, border: '1px solid rgba(0,0,0,0.06)' }}>
              <Skeleton.Input active size="small" style={{ width: 60, height: 10 }} />
              <Skeleton.Input active size="small" style={{ width: 80, height: 32, marginTop: 12 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div style={{ background: '#F8F9FA', minHeight: '100vh' }}>
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
          background: #FAFAFA !important;
          border-bottom: 1px solid rgba(0,0,0,0.06) !important;
          font-family: "DM Sans", sans-serif !important;
          font-size: 11px !important;
          font-weight: 600 !important;
          color: #9CA3AF !important;
          text-transform: uppercase !important;
          letter-spacing: 0.06em !important;
          padding: 12px 20px !important;
        }
        .dash-table .ant-table-tbody > tr > td {
          border-bottom: 1px solid rgba(0,0,0,0.04) !important;
          padding: 14px 20px !important;
          transition: all 0.15s ease !important;
        }
        .dash-table .ant-table-tbody > tr:nth-child(even) > td {
          background: #FAFAFA !important;
        }
        .dash-table .ant-table-tbody > tr:nth-child(odd) > td {
          background: #FFFFFF !important;
        }
        .dash-table .ant-table-tbody > tr > td:first-child {
          border-left: 3px solid transparent !important;
          transition: border-color 0.15s ease, background 0.15s ease !important;
        }
        .dash-table .ant-table-tbody > tr:hover > td {
          background: rgba(108,92,231,0.03) !important;
        }
        .dash-table .ant-table-tbody > tr:hover > td:first-child {
          border-left-color: #6C5CE7 !important;
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
            boxShadow: '0 4px 12px rgba(108,92,231,0.25)',
          }}>
            <SafetyCertificateOutlined />
          </div>
          <div>
            <h1 style={{
              fontSize: 24,
              fontWeight: 700,
              fontFamily: '"Clash Display", "DM Sans", sans-serif',
              color: '#1E293B',
              margin: 0,
              lineHeight: 1.2,
              letterSpacing: '-0.03em',
            }}>
              态势总览
            </h1>
            <p style={{
              fontSize: 13,
              color: '#9CA3AF',
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
              color: '#9CA3AF',
              ...NUM,
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}>
              <span style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#30A46C',
                animation: 'dashPulse 2s ease infinite',
              }} />
              <ClockCircleOutlined style={{ fontSize: 11 }} />
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={fetchData}
            style={{
              background: '#FFFFFF',
              border: '1px solid rgba(0,0,0,0.06)',
              cursor: 'pointer',
              ...NUM,
              fontSize: 13,
              fontWeight: 500,
              color: '#6B7280',
              padding: '8px 18px',
              borderRadius: 10,
              lineHeight: 1,
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              transition: 'all 0.2s cubic-bezier(0.22, 1, 0.36, 1)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = '#6C5CE7';
              e.currentTarget.style.color = '#6C5CE7';
              e.currentTarget.style.background = 'rgba(108,92,231,0.04)';
              e.currentTarget.style.boxShadow = '0 2px 8px rgba(108,92,231,0.12)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'rgba(0,0,0,0.06)';
              e.currentTarget.style.color = '#6B7280';
              e.currentTarget.style.background = '#FFFFFF';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)';
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
              background: 'linear-gradient(135deg, rgba(108,92,231,0.06) 0%, rgba(108,92,231,0.01) 50%, #FFFFFF 100%)',
              animation: 'dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both',
              transition: 'all 0.3s cubic-bezier(0.22, 1, 0.36, 1)',
              cursor: 'default',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 8px 24px rgba(108,92,231,0.1)';
              e.currentTarget.style.borderColor = 'rgba(108,92,231,0.15)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)';
              e.currentTarget.style.borderColor = 'rgba(0,0,0,0.06)';
            }}
          >
            <div style={{
              position: 'absolute',
              top: -30,
              right: -20,
              width: 140,
              height: 140,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(108,92,231,0.08) 0%, transparent 70%)',
              pointerEvents: 'none',
            }} />
            <div style={{
              position: 'absolute',
              bottom: -40,
              right: 60,
              width: 120,
              height: 120,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(108,92,231,0.05) 0%, transparent 70%)',
              pointerEvents: 'none',
            }} />

            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
                  <span style={{
                    width: 38,
                    height: 38,
                    borderRadius: 10,
                    background: 'rgba(108,92,231,0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#6C5CE7',
                    fontSize: 17,
                    flexShrink: 0,
                  }}>
                    <DatabaseOutlined />
                  </span>
                  <span style={{
                    ...NUM,
                    fontSize: 13,
                    fontWeight: 500,
                    color: '#6B7280',
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
                    color: '#1E293B',
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
                      background: 'rgba(48,164,108,0.08)',
                    }}>
                      <ArrowUpOutlined style={{ fontSize: 10, color: '#30A46C' }} />
                      <span style={{
                        ...NUM,
                        fontSize: 12,
                        color: '#30A46C',
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
                  color: '#9CA3AF',
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
                background: card.bg,
                borderLeft: `4px solid ${card.color}`,
                animation: `dashFadeIn 0.5s cubic-bezier(0.22, 1, 0.36, 1) both`,
                animationDelay: `${(idx + 1) * 80}ms`,
                transition: 'all 0.3s cubic-bezier(0.22, 1, 0.36, 1)',
                cursor: 'default',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = `0 8px 24px ${card.color}12`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)';
              }}
            >
              <div style={{
                position: 'absolute',
                top: -15,
                right: -15,
                width: 60,
                height: 60,
                borderRadius: '50%',
                background: `${card.color}08`,
                pointerEvents: 'none',
              }} />

              <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 16 }}>
                <span style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: `${card.color}12`,
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
                  color: '#6B7280',
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
                  color: '#1E293B',
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
                    color: '#9CA3AF',
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
              background: 'linear-gradient(90deg, #E5484D, #F76B15, #E5A000, #30A46C, #0090FF)',
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
                  fontFamily: '"Clash Display", "DM Sans", sans-serif',
                  color: '#374151',
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
                  color: '#9CA3AF',
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
                          color: '#6B7280',
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
                    background: 'linear-gradient(to top, #FFFFFF, transparent)',
                    pointerEvents: 'none',
                    borderRadius: '0 0 16px 16px',
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
                  <PieChartOutlined style={{ fontSize: 40, color: '#E5E7EB' }} />
                  <span style={{
                    color: '#9CA3AF',
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
              background: 'linear-gradient(90deg, #6C5CE7, #0090FF)',
            }} />
            <div style={{
              padding: '18px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <LineChartOutlined style={{ fontSize: 14, color: '#6C5CE7' }} />
                <h2 style={{
                  fontSize: 15,
                  fontWeight: 600,
                  fontFamily: '"Clash Display", "DM Sans", sans-serif',
                  color: '#374151',
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
                  background: '#30A46C',
                  animation: 'dashPulse 2s ease infinite',
                }} />
                <span style={{
                  ...NUM,
                  fontSize: 12,
                  color: '#9CA3AF',
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
                          <stop offset="0%" stopColor="#6C5CE7" stopOpacity={0.15} />
                          <stop offset="100%" stopColor="#6C5CE7" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#F0F0F0" vertical={false} />
                      <XAxis
                        dataKey="date"
                        tickFormatter={formatTrendDate}
                        tick={{ fill: '#9CA3AF', fontSize: 11, fontFamily: '"DM Sans", sans-serif' }}
                        axisLine={{ stroke: '#F0F0F0' }}
                        tickLine={false}
                      />
                      <YAxis
                        tick={{ fill: '#9CA3AF', fontSize: 11, fontFamily: '"DM Sans", sans-serif' }}
                        axisLine={false}
                        tickLine={false}
                        width={36}
                      />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Area
                        type="monotone"
                        dataKey="total"
                        stroke="#6C5CE7"
                        strokeWidth={2.5}
                        fill="url(#trendGrad)"
                        name="总量"
                        dot={false}
                        activeDot={{ r: 5, fill: '#6C5CE7', stroke: '#FFFFFF', strokeWidth: 2 }}
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
                    background: 'linear-gradient(to top, #FFFFFF, transparent)',
                    pointerEvents: 'none',
                    borderRadius: '0 0 16px 16px',
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
                  <LineChartOutlined style={{ fontSize: 40, color: '#E5E7EB' }} />
                  <span style={{
                    color: '#9CA3AF',
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
            background: 'linear-gradient(90deg, #0090FF, #6C5CE7)',
          }} />
          <div style={{
            padding: '18px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <UnorderedListOutlined style={{ fontSize: 14, color: '#0090FF' }} />
              <h2 style={{
                fontSize: 15,
                fontWeight: 600,
                fontFamily: '"Clash Display", "DM Sans", sans-serif',
                color: '#374151',
                margin: 0,
                lineHeight: 1,
              }}>
                最近情报
              </h2>
            </div>
            <span
              style={{
                ...NUM,
                fontSize: 13,
                color: '#6C5CE7',
                cursor: 'pointer',
                padding: '6px 16px',
                borderRadius: 20,
                background: 'rgba(108,92,231,0.06)',
                transition: 'all 0.2s cubic-bezier(0.22, 1, 0.36, 1)',
                lineHeight: 1,
                fontWeight: 500,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#6C5CE7';
                e.currentTarget.style.color = '#FFFFFF';
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(108,92,231,0.25)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(108,92,231,0.06)';
                e.currentTarget.style.color = '#6C5CE7';
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
                    <span style={{ color: '#9CA3AF', ...NUM, fontSize: 13 }}>
                      暂无情报数据，请先采集情报
                    </span>
                  }
                  image={<UnorderedListOutlined style={{ fontSize: 48, color: '#E5E7EB' }} />}
                >
                  <Button
                    onClick={fetchData}
                    style={{
                      ...NUM,
                      fontSize: 13,
                      border: '1px solid rgba(0,0,0,0.06)',
                      borderRadius: 10,
                      background: '#FFFFFF',
                      color: '#6B7280',
                      boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
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
