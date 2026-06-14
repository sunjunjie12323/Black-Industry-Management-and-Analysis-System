import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Select, Input, Tag, Modal, Slider, Spin, Progress } from 'antd';
import { SearchOutlined, ZoomInOutlined, ZoomOutOutlined, CompressOutlined, NodeIndexOutlined, TeamOutlined, ExperimentOutlined, CloseCircleOutlined, ApartmentOutlined, DatabaseOutlined, ShareAltOutlined } from '@ant-design/icons';
import { graphApi, getErrorMessage } from '../services/api';
import type { GraphData, GraphStats, CommunityResult, PathResult } from '../types';
import { useAntdMessage } from '../utils/hooks';

const NODE_COLORS: Record<string, string> = {
  ip: '#818CF8',
  account: '#6C5CE7',
  blacktalk: '#EF4444',
  service: '#14B8A6',
  tool: '#F97316',
  person: '#22C55E',
  domain: '#818CF8',
  malware: '#EF4444',
  organization: '#14B8A6',
  email: '#6C5CE7',
  crypto_wallet: '#EAB308',
  url: '#818CF8',
  phone: '#22C55E',
  keyword: '#EF4444',
  website: '#14B8A6',
  location: '#22C55E',
  hash: '#7C7F9A',
  payment_method: '#F97316',
};

const NODE_LABELS: Record<string, string> = {
  account: '账号', url: 'URL', phone: '手机', email: '邮箱', tool: '工具',
  keyword: '关键词', person: '人物', organization: '组织', website: '网站',
  ip: 'IP', domain: '域名', malware: '恶意软件', crypto_wallet: '加密钱包',
  service: '服务', blacktalk: '暗语', location: '地点', hash: '哈希', payment_method: '支付方式',
};

const ENTITY_TYPE_OPTIONS = Object.entries(NODE_LABELS).map(([key, label]) => ({
  label: `${label} (${key})`,
  value: key,
}));

const NUM: React.CSSProperties = {
  fontFamily: 'var(--font-number)',
  fontVariantNumeric: 'tabular-nums',
};

const FB: React.CSSProperties = {
  fontFamily: 'var(--font-body)',
};

const Graph: React.FC = () => {
  const message = useAntdMessage();
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const mountedRef = useRef(true);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [entityTypeFilter, setEntityTypeFilter] = useState<string | undefined>();
  const [searchValue, setSearchValue] = useState('');
  const [depth, setDepth] = useState(2);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [pathVisible, setPathVisible] = useState(false);
  const [pathForm, setPathForm] = useState({ sourceId: '', targetId: '' });
  const [pathResult, setPathResult] = useState<PathResult | null>(null);
  const [pathLoading, setPathLoading] = useState(false);
  const [commResult, setCommResult] = useState<CommunityResult | null>(null);
  const [commLoading, setCommLoading] = useState(false);

  const fetchGraph = useCallback(async () => {
    setLoading(true);
    try {
      const [d, s] = await Promise.all([
        graphApi.getData({
          entity_type: entityTypeFilter || undefined,
          search: searchValue.trim() || undefined,
          depth,
          limit: 50,
        }),
        graphApi.getStats(),
      ]);
      if (mountedRef.current) {
        setGraphData(d);
        setStats(s);
      }
    } catch (err) {
      if (mountedRef.current) message.error(getErrorMessage(err));
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [entityTypeFilter, searchValue, depth, message]);

  useEffect(() => {
    fetchGraph();
    return () => { mountedRef.current = false; };
  }, []);

  const handleZoom = useCallback((factor: number) => {
    const g = graphRef.current;
    if (!g || !graphContainerRef.current) return;
    g.zoomTo(g.getZoom() * factor, {
      x: graphContainerRef.current.clientWidth / 2,
      y: graphContainerRef.current.clientHeight / 2,
    });
  }, []);

  const handleFit = useCallback(() => {
    graphRef.current?.fitView(40, { animate: true, duration: 500 });
  }, []);

  useEffect(() => {
    if (!graphData || !graphContainerRef.current || loading) return;

    const renderG = async () => {
      const G6 = (await import('@antv/g6')).default;
      if (graphRef.current) {
        graphRef.current.destroy();
        graphRef.current = null;
      }
      if (graphContainerRef.current) graphContainerRef.current.innerHTML = '';
      const w = graphContainerRef.current?.clientWidth || 800;
      const h = graphContainerRef.current?.clientHeight || 500;

      const nodes = (graphData.nodes || []).map(n => {
        const color = NODE_COLORS[n.entity_type] || '#7C7F9A';
        const edgeCount = (graphData.edges || []).filter(e => e.source === n.id || e.target === n.id).length;
        const size = Math.max(8, Math.min(20, 8 + edgeCount * 2));
        return {
          id: n.id,
          label: n.label || n.id,
          type: 'circle',
          size,
          style: {
            fill: `${color}20`,
            stroke: color,
            lineWidth: 2,
            cursor: 'pointer',
          },
          labelCfg: {
            position: 'bottom' as const,
            offset: 6,
            style: {
              fill: '#C8C9D0',
              fontSize: 10,
              fontWeight: 400,
              fontFamily: 'var(--font-body)',
              background: {
                fill: '#0B0D17',
                padding: [2, 4, 2, 4],
                radius: 4,
                stroke: 'rgba(255,255,255,0.08)',
                lineWidth: 0.5,
              },
            },
          },
          _entityType: n.entity_type,
          _degree: edgeCount,
          _properties: n.properties,
          _confidence: n.confidence,
        };
      });

      const edges = (graphData.edges || []).map(e => ({
        source: e.source,
        target: e.target,
        label: e.relation_type,
        type: 'quadratic',
        style: {
          stroke: '#6B6F8A',
          lineWidth: 1,
          endArrow: G6.Arrow?.triangle ? {
            path: G6.Arrow.triangle(4, 6, 0),
            fill: '#6B6F8A',
            d: 0,
          } : true,
          cursor: 'pointer',
        },
        labelCfg: {
          style: {
            fill: '#7C7F9A',
            fontSize: 9,
            fontWeight: 400,
            fontFamily: 'var(--font-body)',
            background: {
              fill: '#0B0D17',
              padding: [2, 4, 2, 4],
              radius: 4,
              stroke: 'rgba(255,255,255,0.08)',
              lineWidth: 0.5,
            },
          },
          autoRotate: true,
        },
      }));

      const graph = new G6.Graph({
        container: graphContainerRef.current!,
        width: w,
        height: h,
        pixelRatio: 1,
        modes: {
          default: ['drag-canvas', 'zoom-canvas', 'drag-node'],
        },
        layout: {
          type: 'force',
          linkDistance: 300,
          nodeStrength: -500,
          collideStrength: 0.8,
          alphaDecay: 0.028,
          alphaMin: 0.01,
          preventOverlap: true,
          nodeSize: 30,
          nodeSpacing: 60,
          workerEnabled: false,
        },
        defaultNode: {
          type: 'circle',
          size: 8,
          style: {
            fill: '#7C7F9A20',
            stroke: '#7C7F9A',
            lineWidth: 2,
          },
          labelCfg: {
            position: 'bottom',
            offset: 6,
            style: {
              fill: '#C8C9D0',
              fontSize: 10,
              fontWeight: 400,
              fontFamily: 'var(--font-body)',
              background: {
                fill: '#0B0D17',
                padding: [2, 4, 2, 4],
                radius: 4,
                stroke: 'rgba(255,255,255,0.08)',
                lineWidth: 0.5,
              },
            },
          },
        },
        defaultEdge: {
          type: 'quadratic',
          style: {
            stroke: '#6B6F8A',
            lineWidth: 1,
            endArrow: G6.Arrow?.triangle ? { path: G6.Arrow.triangle(4, 6, 0), fill: '#6B6F8A' } : true,
          },
          labelCfg: {
            style: {
              fill: '#7C7F9A',
              fontSize: 9,
              fontFamily: 'var(--font-body)',
              background: { fill: '#0B0D17', padding: [2, 4, 2, 4], radius: 4, stroke: 'rgba(255,255,255,0.08)', lineWidth: 0.5 },
            },
            autoRotate: true,
          },
        },
        nodeStateStyles: {
          hover: {
            lineWidth: 3,
            stroke: '#6C5CE7',
          },
          selected: {
            stroke: '#6C5CE7',
            lineWidth: 3,
          },
          active: { opacity: 1 },
          inactive: { opacity: 0.15 },
        },
        edgeStateStyles: {
          hover: {
            lineWidth: 2,
            stroke: '#6C5CE7',
          },
          selected: {
            stroke: '#6C5CE7',
            lineWidth: 2,
          },
          active: { opacity: 1, stroke: '#6C5CE7' },
          inactive: { opacity: 0.08, stroke: '#6B6F8A' },
        },
        animate: true,
        animateCfg: { duration: 200, easing: 'easeCubicInOut' },
      });

      graph.data({ nodes, edges });

      if (graphContainerRef.current) {
        graphContainerRef.current.style.opacity = '0';
      }

      graph.render();

      let layoutCompleted = false;
      const showGraph = () => {
        if (layoutCompleted || !graphContainerRef.current) return;
        layoutCompleted = true;
        setTimeout(() => {
          try { graph.fitView(40); } catch {}
          if (graphContainerRef.current) {
            graphContainerRef.current.style.transition = 'opacity 0.4s ease-out';
            graphContainerRef.current.style.opacity = '1';
          }
        }, 50);
      };

      const layoutTimeout = setTimeout(showGraph, 800);
      graph.on('afterlayout', () => { clearTimeout(layoutTimeout); showGraph(); });

      graph.on('node:click', (evt: any) => {
        const item = evt.item;
        const model = item?.getModel?.() ?? null;
        if (!model) return;
        setSelectedNode(model);
        try {
          const neighbors = item.getNeighbors();
          const neighborIds = new Set(neighbors.map((n: any) => n.getModel()?.id));
          graph.getNodes().forEach((node: any) => {
            const nodeId = node.getModel()?.id;
            if (node === item) {
              graph.setItemState(node, 'selected', true);
              graph.setItemState(node, 'active', true);
              graph.setItemState(node, 'inactive', false);
            } else if (neighborIds.has(nodeId)) {
              graph.setItemState(node, 'active', true);
              graph.setItemState(node, 'inactive', false);
              graph.setItemState(node, 'selected', false);
            } else {
              graph.setItemState(node, 'inactive', true);
              graph.setItemState(node, 'active', false);
              graph.setItemState(node, 'selected', false);
            }
          });
          graph.getEdges().forEach((edge: any) => {
            const edgeModel = edge.getModel();
            if (edgeModel.source === model.id || edgeModel.target === model.id) {
              graph.setItemState(edge, 'active', true);
              graph.setItemState(edge, 'inactive', false);
            } else {
              graph.setItemState(edge, 'inactive', true);
              graph.setItemState(edge, 'active', false);
            }
          });
        } catch {
          graph.setItemState(item, 'selected', true);
        }
      });

      graph.on('canvas:click', () => {
        setSelectedNode(null);
        graph.getNodes().forEach((node: any) => {
          graph.setItemState(node, 'selected', false);
          graph.setItemState(node, 'active', false);
          graph.setItemState(node, 'inactive', false);
        });
        graph.getEdges().forEach((edge: any) => {
          graph.setItemState(edge, 'selected', false);
          graph.setItemState(edge, 'active', false);
          graph.setItemState(edge, 'inactive', false);
        });
      });

      graph.on('node:mouseenter', (evt: any) => {
        try {
          graph.setItemState(evt.item, 'hover', true);
          evt.item.getEdges().forEach((e: any) => graph.setItemState(e, 'hover', true));
          evt.item.getNeighbors().forEach((nb: any) => graph.setItemState(nb, 'hover', true));
        } catch {
          graph.setItemState(evt.item, 'hover', true);
        }
      });

      graph.on('node:mouseleave', (evt: any) => {
        try {
          graph.setItemState(evt.item, 'hover', false);
          evt.item.getEdges().forEach((e: any) => graph.setItemState(e, 'hover', false));
          evt.item.getNeighbors().forEach((nb: any) => graph.setItemState(nb, 'hover', false));
        } catch {
          graph.setItemState(evt.item, 'hover', false);
        }
      });

      graphRef.current = graph;
    };

    renderG();
    return () => {
      try {
        if (graphRef.current) { graphRef.current.destroy(); graphRef.current = null; }
      } catch { graphRef.current = null; }
    };
  }, [graphData, loading]);

  const handleFindPath = async () => {
    if (!pathForm.sourceId.trim() || !pathForm.targetId.trim()) {
      message.warning('请输入起止实体ID');
      return;
    }
    setPathLoading(true);
    setPathResult(null);
    try {
      const res = await graphApi.findPath(pathForm.sourceId, pathForm.targetId);
      setPathResult(res);
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setPathLoading(false);
    }
  };

  const handleFindCommunities = async () => {
    setCommLoading(true);
    setCommResult(null);
    try {
      const res = await graphApi.findCommunities();
      setCommResult(res);
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setCommLoading(false);
    }
  };

  const hasData = graphData && (graphData.nodes?.length > 0 || graphData.edges?.length > 0);

  const STAT_ITEMS = [
    { label: '节点数', value: stats?.node_count ?? 0, color: '#6C5CE7' },
    { label: '边数', value: stats?.edge_count ?? 0, color: '#818CF8' },
    { label: '实体类型', value: stats?.entity_types ? Object.keys(stats.entity_types).length : 0, color: '#14B8A6' },
    { label: '平均度', value: stats && stats.node_count > 0 ? (stats.edge_count * 2 / stats.node_count).toFixed(1) : '0', color: '#F97316' },
  ];

  const glassPanel: React.CSSProperties = {
    background: 'var(--glass-bg)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-lg)',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
  };

  return (
    <div style={{ padding: '28px 32px 48px', background: '#0B0D17', minHeight: '100vh' }}>
      <div style={{ display: 'flex', alignItems: 'stretch', gap: 14, marginBottom: 24 }}>
        <div style={{
          width: 4,
          borderRadius: 2,
          background: 'linear-gradient(180deg, #6C5CE7 0%, #818CF8 100%)',
          flexShrink: 0,
        }} />
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 24,
            fontWeight: 700,
            color: 'var(--text-0)',
            margin: 0,
            lineHeight: 1.2,
            letterSpacing: '-0.02em',
          }}>
            关联图谱
          </h1>
          <span style={{
            ...FB,
            fontSize: 13,
            color: 'var(--text-2)',
            marginTop: 3,
            lineHeight: 1.4,
          }}>
            实体关系可视化与知识图谱探索
          </span>
        </div>
      </div>

      <div style={{
        ...glassPanel,
        display: 'flex',
        alignItems: 'center',
        gap: 0,
        marginBottom: 20,
        padding: '10px 8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 14px' }}>
          <span style={{ ...FB, fontSize: 12, color: 'var(--text-2)', whiteSpace: 'nowrap', fontWeight: 600, letterSpacing: '0.02em' }}>类型</span>
          <Select
            placeholder="全部"
            value={entityTypeFilter}
            onChange={v => setEntityTypeFilter(v)}
            allowClear
            style={{ width: 130 }}
            options={ENTITY_TYPE_OPTIONS}
            size="small"
          />
        </div>
        <div style={{ width: 1, height: 24, background: 'var(--border)', flexShrink: 0 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 14px' }}>
          <Input
            placeholder="搜索实体..."
            prefix={<SearchOutlined style={{ color: 'var(--text-2)', fontSize: 12 }} />}
            value={searchValue}
            onChange={e => setSearchValue(e.target.value)}
            onPressEnter={fetchGraph}
            allowClear
            style={{ width: 180 }}
            size="small"
          />
        </div>
        <div style={{ width: 1, height: 24, background: 'var(--border)', flexShrink: 0 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 14px' }}>
          <span style={{ ...FB, fontSize: 12, color: 'var(--text-2)', whiteSpace: 'nowrap', fontWeight: 600, letterSpacing: '0.02em' }}>深度</span>
          <Slider min={1} max={5} value={depth} onChange={v => setDepth(v)} style={{ width: 72, margin: 0 }} />
          <span style={{
            ...NUM,
            fontSize: 12,
            color: '#6C5CE7',
            fontWeight: 700,
            minWidth: 22,
            textAlign: 'center',
            background: 'rgba(108, 92, 231, 0.12)',
            borderRadius: 6,
            padding: '2px 8px',
            border: '1px solid rgba(108, 92, 231, 0.18)',
          }}>{depth}</span>
        </div>
        <div style={{ width: 1, height: 24, background: 'var(--border)', flexShrink: 0 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 14px' }}>
          <button
            onClick={fetchGraph}
            disabled={loading}
            aria-label="加载图谱"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 16px',
              borderRadius: 9,
              border: 'none',
              background: 'linear-gradient(135deg, #6C5CE7 0%, #818CF8 100%)',
              color: '#FFFFFF',
              fontSize: 13,
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.65 : 1,
              transition: 'all 0.2s ease',
              ...FB,
              whiteSpace: 'nowrap',
              boxShadow: '0 1px 3px rgba(108, 92, 231, 0.25)',
            }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 3px 8px rgba(108, 92, 231, 0.3)'; } }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 1px 3px rgba(108, 92, 231, 0.25)'; }}
          >
            <DatabaseOutlined style={{ fontSize: 12 }} />
            {loading ? '加载中' : '加载图谱'}
          </button>
          <button
            onClick={() => setPathVisible(true)}
            aria-label="查找路径"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 16px',
              borderRadius: 9,
              border: '1px solid var(--border)',
              background: 'var(--bg-2)',
              color: 'var(--text-0)',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              ...FB,
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-hover)'; e.currentTarget.style.color = '#818CF8'; e.currentTarget.style.background = 'rgba(108, 92, 231, 0.08)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-0)'; e.currentTarget.style.background = 'var(--bg-2)'; }}
          >
            <NodeIndexOutlined style={{ fontSize: 12 }} />
            查找路径
          </button>
          <button
            onClick={handleFindCommunities}
            disabled={commLoading}
            aria-label="社区发现"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 16px',
              borderRadius: 9,
              border: '1px solid var(--border)',
              background: 'var(--bg-2)',
              color: 'var(--text-0)',
              fontSize: 13,
              fontWeight: 600,
              cursor: commLoading ? 'not-allowed' : 'pointer',
              opacity: commLoading ? 0.65 : 1,
              transition: 'all 0.2s ease',
              ...FB,
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => { if (!commLoading) { e.currentTarget.style.borderColor = 'rgba(20, 184, 166, 0.35)'; e.currentTarget.style.color = '#14B8A6'; e.currentTarget.style.background = 'rgba(20, 184, 166, 0.08)'; } }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-0)'; e.currentTarget.style.background = 'var(--bg-2)'; }}
          >
            <TeamOutlined style={{ fontSize: 12 }} />
            {commLoading ? '分析中' : '社区发现'}
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 20 }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <div style={{
            position: 'relative',
            width: '100%',
            height: 'calc(100vh - 230px)',
            minHeight: 480,
            overflow: 'hidden',
            ...glassPanel,
          }}>
            <div ref={graphContainerRef} style={{
              width: '100%',
              height: '100%',
              background: '#0B0D17',
              borderRadius: 'var(--radius-lg)',
            }}>
              {loading && (
                <div style={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'var(--glass-bg)',
                  zIndex: 10,
                  borderRadius: 'var(--radius-lg)',
                }}>
                  <div style={{
                    width: 56,
                    height: 56,
                    borderRadius: 14,
                    background: 'rgba(108, 92, 231, 0.12)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: 18,
                  }}>
                    <Spin size="large" />
                  </div>
                  <span style={{ ...FB, color: 'var(--text-2)', fontSize: 13, fontWeight: 500 }}>正在加载图谱数据...</span>
                </div>
              )}
              {!loading && !hasData && (
                <div style={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 10,
                }}>
                  <div style={{
                    width: 100,
                    height: 100,
                    borderRadius: 24,
                    background: 'rgba(108, 92, 231, 0.10)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: 24,
                    border: '1px solid rgba(108, 92, 231, 0.12)',
                  }}>
                    <ApartmentOutlined style={{ fontSize: 44, color: '#6C5CE7' }} />
                  </div>
                  <h3 style={{
                    ...FB,
                    color: 'var(--text-0)',
                    fontSize: 17,
                    fontWeight: 700,
                    marginBottom: 8,
                    letterSpacing: '-0.01em',
                  }}>尚未加载图谱</h3>
                  <p style={{
                    ...FB,
                    color: 'var(--text-2)',
                    fontSize: 13,
                    marginBottom: 24,
                    maxWidth: 280,
                    textAlign: 'center',
                    lineHeight: 1.6,
                  }}>点击「加载图谱」开始探索实体关系网络</p>
                  <button
                    onClick={fetchGraph}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 7,
                      padding: '9px 22px',
                      borderRadius: 10,
                      border: 'none',
                      background: 'linear-gradient(135deg, #6C5CE7 0%, #818CF8 100%)',
                      color: '#FFFFFF',
                      fontSize: 14,
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      ...FB,
                      boxShadow: '0 2px 8px rgba(108, 92, 231, 0.25)',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 4px 14px rgba(108, 92, 231, 0.35)'; }}
                    onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(108, 92, 231, 0.25)'; }}
                  >
                    <DatabaseOutlined style={{ fontSize: 14 }} />
                    加载图谱
                  </button>
                </div>
              )}
            </div>

            {hasData && (
              <>
                <div style={{
                  position: 'absolute',
                  left: 14,
                  top: 14,
                  display: 'flex',
                  flexDirection: 'column',
                  zIndex: 5,
                  ...glassPanel,
                  overflow: 'hidden',
                }}>
                  {[
                    { icon: <ZoomInOutlined />, action: () => handleZoom(1.3) },
                    { icon: <ZoomOutOutlined />, action: () => handleZoom(0.7) },
                    { icon: <CompressOutlined />, action: handleFit },
                  ].map((item, i) => (
                    <button
                      key={i}
                      onClick={item.action}
                      style={{
                        width: 36,
                        height: 36,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: 'none',
                        background: 'transparent',
                        color: 'var(--text-2)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                        fontSize: 14,
                        borderBottom: i < 2 ? '1px solid var(--border)' : 'none',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-2)'; e.currentTarget.style.color = '#6C5CE7'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-2)'; }}
                    >
                      {item.icon}
                    </button>
                  ))}
                </div>

                <div style={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 18px',
                  background: 'rgba(20,22,37,0.94)',
                  backdropFilter: 'blur(8px)',
                  borderTop: '1px solid var(--border)',
                  borderRadius: '0 0 var(--radius-lg) var(--radius-lg)',
                  zIndex: 4,
                }}>
                  <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                    <span style={{ ...NUM, fontSize: 12, color: 'var(--text-2)' }}>
                      节点 <span style={{ fontWeight: 700, color: 'var(--text-0)' }}>{stats?.node_count ?? graphData?.nodes?.length ?? 0}</span>
                    </span>
                    <span style={{ ...NUM, fontSize: 12, color: 'var(--text-2)' }}>
                      边 <span style={{ fontWeight: 700, color: 'var(--text-0)' }}>{stats?.edge_count ?? graphData?.edges?.length ?? 0}</span>
                    </span>
                    {stats?.entity_types && (
                      <span style={{ ...NUM, fontSize: 12, color: 'var(--text-2)' }}>
                        类型 <span style={{ fontWeight: 700, color: 'var(--text-0)' }}>{Object.keys(stats.entity_types).length}</span>
                      </span>
                    )}
                  </div>
                  <span style={{ ...FB, fontSize: 11, color: 'var(--text-3)' }}>拖拽画布 · 滚轮缩放 · 点击节点</span>
                </div>
              </>
            )}
          </div>
        </div>

        <div style={{ width: 272, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{
            ...glassPanel,
            overflow: 'hidden',
          }}>
            <div style={{ padding: '16px 18px 0' }}>
              <div style={{
                ...FB,
                fontSize: 13,
                fontWeight: 700,
                color: 'var(--text-0)',
                marginBottom: 16,
                letterSpacing: '-0.01em',
              }}>图谱统计</div>
            </div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 0,
            }}>
              {STAT_ITEMS.map((item) => (
                <div key={item.label} style={{
                  padding: '0 14px 18px',
                  position: 'relative',
                  borderTop: `3px solid ${item.color}`,
                  paddingTop: 14,
                  margin: '0 8px 4px',
                  borderRadius: '8px 8px 0 0',
                }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    marginBottom: 8,
                  }}>
                    <div style={{
                      width: 7,
                      height: 7,
                      borderRadius: 4,
                      background: item.color,
                      flexShrink: 0,
                      boxShadow: `0 0 0 2px ${item.color}20`,
                    }} />
                    <span style={{
                      ...FB,
                      fontSize: 11,
                      color: 'var(--text-2)',
                      fontWeight: 500,
                    }}>{item.label}</span>
                  </div>
                  <div style={{
                    ...NUM,
                    fontSize: 28,
                    fontWeight: 700,
                    color: item.color,
                    lineHeight: 1,
                    letterSpacing: '-0.03em',
                  }}>{item.value}</div>
                </div>
              ))}
            </div>
            {stats?.entity_types && Object.keys(stats.entity_types).length > 0 && (
              <div style={{
                padding: '0 18px 16px',
                display: 'flex',
                flexWrap: 'wrap',
                gap: 5,
              }}>
                {Object.entries(stats.entity_types).map(([type, count]) => {
                  const color = NODE_COLORS[type] || '#7C7F9A';
                  return (
                    <Tag key={type} style={{
                      color,
                      border: `1px solid ${color}25`,
                      fontSize: 11,
                      fontWeight: 500,
                      padding: '2px 9px',
                      borderRadius: 6,
                      ...FB,
                      background: `${color}08`,
                    }}>
                      {NODE_LABELS[type] || type} <span style={{ ...NUM, fontWeight: 700 }}>{count}</span>
                    </Tag>
                  );
                })}
              </div>
            )}
          </div>

          {selectedNode && (
            <div style={{
              ...glassPanel,
              overflow: 'hidden',
            }}>
              <div style={{
                height: 3,
                background: `linear-gradient(90deg, ${NODE_COLORS[selectedNode._entityType] || '#6C5CE7'}, ${NODE_COLORS[selectedNode._entityType] || '#6C5CE7'}88)`,
              }} />
              <div style={{ padding: 18 }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 16,
                }}>
                  <div style={{
                    ...FB,
                    fontSize: 13,
                    fontWeight: 700,
                    color: 'var(--text-0)',
                    letterSpacing: '-0.01em',
                  }}>选中节点</div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: 8,
                      border: 'none',
                      background: 'var(--bg-2)',
                      color: 'var(--text-2)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: 12,
                      transition: 'all 0.15s ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-3)'; e.currentTarget.style.color = 'var(--text-0)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-2)'; e.currentTarget.style.color = 'var(--text-2)'; }}
                  >
                    <CloseCircleOutlined />
                  </button>
                </div>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  marginBottom: 16,
                }}>
                  <div style={{
                    width: 11,
                    height: 11,
                    background: NODE_COLORS[selectedNode._entityType] || '#7C7F9A',
                    borderRadius: 6,
                    flexShrink: 0,
                    boxShadow: `0 0 0 3px ${NODE_COLORS[selectedNode._entityType] || '#7C7F9A'}20`,
                  }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      ...FB,
                      fontWeight: 700,
                      fontSize: 14,
                      color: 'var(--text-0)',
                      lineHeight: 1.3,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>{selectedNode.label}</div>
                    <div style={{
                      ...FB,
                      fontSize: 11,
                      color: 'var(--text-2)',
                      marginTop: 3,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>{selectedNode.id}</div>
                  </div>
                </div>
                <Tag style={{
                  color: NODE_COLORS[selectedNode._entityType] || '#7C7F9A',
                  border: `1px solid ${NODE_COLORS[selectedNode._entityType] || '#7C7F9A'}25`,
                  fontSize: 11,
                  fontWeight: 600,
                  borderRadius: 6,
                  padding: '3px 10px',
                  ...FB,
                  background: `${NODE_COLORS[selectedNode._entityType] || '#7C7F9A'}08`,
                }}>
                  {NODE_LABELS[selectedNode._entityType] || selectedNode._entityType || '未知'}
                </Tag>
                <div style={{
                  marginTop: 16,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '10px 14px',
                    background: 'var(--bg-2)',
                    borderRadius: 10,
                  }}>
                    <span style={{ ...FB, fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>连接度</span>
                    <span style={{
                      ...NUM,
                      fontSize: 14,
                      color: 'var(--text-0)',
                      fontWeight: 700,
                    }}>{selectedNode._degree || 0} <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-2)' }}>条边</span></span>
                  </div>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '10px 14px',
                    background: 'var(--bg-2)',
                    borderRadius: 10,
                  }}>
                    <span style={{ ...FB, fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>置信度</span>
                    <span style={{
                      ...NUM,
                      fontSize: 14,
                      color: 'var(--text-0)',
                      fontWeight: 700,
                    }}>{selectedNode._confidence != null ? `${Math.round(selectedNode._confidence * 100)}%` : '—'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {pathResult && (
            <div style={{
              ...glassPanel,
              overflow: 'hidden',
            }}>
              <div style={{ height: 3, background: 'linear-gradient(90deg, #818CF8, #818CF888)' }} />
              <div style={{ padding: 18 }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  marginBottom: 14,
                }}>
                  <div style={{
                    width: 24,
                    height: 24,
                    borderRadius: 7,
                    background: 'rgba(129, 140, 248, 0.12)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}>
                    <ShareAltOutlined style={{ color: '#818CF8', fontSize: 11 }} />
                  </div>
                  <span style={{
                    ...FB,
                    fontSize: 13,
                    fontWeight: 700,
                    color: 'var(--text-0)',
                    letterSpacing: '-0.01em',
                  }}>路径结果</span>
                </div>
                <div style={{
                  ...FB,
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--text-0)',
                  marginBottom: 8,
                }}>发现 <span style={{ ...NUM, color: '#818CF8', fontWeight: 700 }}>{pathResult.path_count}</span> 条路径</div>
                {pathResult.message && (
                  <div style={{
                    ...FB,
                    fontSize: 12,
                    color: 'var(--text-2)',
                    marginBottom: 8,
                  }}>{pathResult.message}</div>
                )}
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                  maxHeight: 200,
                  overflow: 'auto',
                }}>
                  {pathResult.paths?.map((path, i) => (
                    <div key={i} style={{
                      padding: '10px 12px',
                      background: 'var(--bg-2)',
                      borderRadius: 10,
                    }}>
                      <div style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 4,
                        alignItems: 'center',
                      }}>
                        {path.map((node, j) => (
                          <React.Fragment key={j}>
                            <Tag style={{
                              color: NODE_COLORS[node.type || ''] || '#7C7F9A',
                              border: `1px solid ${NODE_COLORS[node.type || ''] || '#7C7F9A'}25`,
                              fontSize: 11,
                              fontWeight: 500,
                              margin: 0,
                              borderRadius: 5,
                              ...FB,
                              background: `${NODE_COLORS[node.type || ''] || '#7C7F9A'}08`,
                              padding: '1px 7px',
                            }}>
                              {node.value || node.id}
                            </Tag>
                            {j < path.length - 1 && (
                              <span style={{ color: 'var(--text-2)', fontSize: 11, ...FB }}>→</span>
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {commResult && (
            <div style={{
              ...glassPanel,
              overflow: 'hidden',
            }}>
              <div style={{ height: 3, background: 'linear-gradient(90deg, #14B8A6, #14B8A688)' }} />
              <div style={{ padding: 18 }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  marginBottom: 14,
                }}>
                  <div style={{
                    width: 24,
                    height: 24,
                    borderRadius: 7,
                    background: 'rgba(20, 184, 166, 0.12)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}>
                    <ExperimentOutlined style={{ color: '#14B8A6', fontSize: 11 }} />
                  </div>
                  <span style={{
                    ...FB,
                    fontSize: 13,
                    fontWeight: 700,
                    color: 'var(--text-0)',
                    letterSpacing: '-0.01em',
                  }}>社区发现</span>
                </div>
                <div style={{
                  ...FB,
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--text-0)',
                  marginBottom: 6,
                }}>发现 <span style={{ ...NUM, color: '#14B8A6', fontWeight: 700 }}>{commResult.community_count}</span> 个社区</div>
                <div style={{
                  ...FB,
                  fontSize: 11,
                  color: 'var(--text-2)',
                  marginBottom: 12,
                }}>算法: {commResult.algorithm}</div>
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  maxHeight: 300,
                  overflow: 'auto',
                }}>
                  {commResult.communities?.map((c, i) => (
                    <div key={i} style={{
                      padding: '12px 14px',
                      background: 'var(--bg-2)',
                      borderRadius: 10,
                    }}>
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: 8,
                      }}>
                        <span style={{
                          ...FB,
                          fontSize: 12,
                          fontWeight: 700,
                          color: 'var(--text-0)',
                        }}>社区 4{i + 1}</span>
                        <span style={{
                          ...NUM,
                          fontSize: 11,
                          color: 'var(--text-2)',
                          fontWeight: 600,
                        }}>{c.member_count} 成员</span>
                      </div>
                      <Progress
                        percent={Math.min(100, Math.round(c.member_count / ((commResult.communities?.sort((a, b) => b.member_count - a.member_count)[0]?.member_count || 1)) * 100))}
                        showInfo={false}
                        strokeColor="#14B8A6"
                        trailColor="var(--bg-3)"
                        size="small"
                      />
                      <div style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 4,
                        marginTop: 8,
                      }}>
                        {c.members?.slice(0, 6).map((m, j) => (
                          <Tag key={j} style={{
                            color: 'var(--text-0)',
                            border: '1px solid var(--border)',
                            fontSize: 11,
                            margin: 0,
                            borderRadius: 5,
                            ...FB,
                            background: 'var(--bg-1)',
                            padding: '1px 7px',
                          }}>{m.value}</Tag>
                        ))}
                        {c.member_count > 6 && (
                          <span style={{
                            ...NUM,
                            fontSize: 11,
                            color: 'var(--text-2)',
                            fontWeight: 600,
                          }}>+{c.member_count - 6}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 4,
              height: 22,
              borderRadius: 2,
              background: 'linear-gradient(180deg, #818CF8, #818CF888)',
            }} />
            <span style={{
              ...FB,
              fontWeight: 700,
              fontSize: 16,
              color: 'var(--text-0)',
              letterSpacing: '-0.01em',
            }}>查找路径</span>
          </div>
        }
        open={pathVisible}
        onCancel={() => { setPathVisible(false); setPathResult(null); }}
        footer={
          <button
            onClick={() => { setPathVisible(false); setPathResult(null); }}
            style={{
              padding: '7px 22px',
              borderRadius: 9,
              border: '1px solid var(--border)',
              background: 'var(--bg-2)',
              color: 'var(--text-0)',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              ...FB,
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-3)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-2)'; }}
          >关闭</button>
        }
        width={520}
        styles={{
          content: {
            borderRadius: 'var(--radius-lg)',
            background: 'var(--glass-bg)',
            border: '1px solid var(--glass-border)',
          },
          header: {
            background: 'var(--glass-bg)',
            borderBottom: '1px solid var(--border)',
          },
          body: {
            background: 'var(--glass-bg)',
          },
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 18 }}>
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{
                ...FB,
                fontSize: 12,
                color: 'var(--text-2)',
                marginBottom: 6,
                fontWeight: 500,
              }}>源实体ID</div>
              <Input
                placeholder="输入源实体ID"
                value={pathForm.sourceId}
                onChange={e => setPathForm(p => ({ ...p, sourceId: e.target.value }))}
                style={{ borderRadius: 9, background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-0)' }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{
                ...FB,
                fontSize: 12,
                color: 'var(--text-2)',
                marginBottom: 6,
                fontWeight: 500,
              }}>目标实体ID</div>
              <Input
                placeholder="输入目标实体ID"
                value={pathForm.targetId}
                onChange={e => setPathForm(p => ({ ...p, targetId: e.target.value }))}
                style={{ borderRadius: 9, background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-0)' }}
              />
            </div>
          </div>
          <button
            onClick={handleFindPath}
            disabled={pathLoading}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 7,
              padding: '9px 22px',
              borderRadius: 9,
              border: 'none',
              background: 'linear-gradient(135deg, #6C5CE7 0%, #818CF8 100%)',
              color: '#FFFFFF',
              fontSize: 14,
              fontWeight: 600,
              cursor: pathLoading ? 'not-allowed' : 'pointer',
              opacity: pathLoading ? 0.65 : 1,
              transition: 'all 0.2s ease',
              ...FB,
              boxShadow: '0 1px 3px rgba(108, 92, 231, 0.25)',
            }}
            onMouseEnter={e => { if (!pathLoading) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 3px 8px rgba(108, 92, 231, 0.3)'; } }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 1px 3px rgba(108, 92, 231, 0.25)'; }}
          >
            <NodeIndexOutlined style={{ fontSize: 13 }} />
            {pathLoading ? '查找中...' : '查找路径'}
          </button>
          {pathResult && (
            <div style={{
              padding: 16,
              background: 'var(--bg-2)',
              borderRadius: 12,
              border: '1px solid var(--border)',
              maxHeight: 300,
              overflow: 'auto',
            }}>
              <div style={{
                ...FB,
                fontSize: 12,
                fontWeight: 700,
                color: 'var(--text-0)',
                marginBottom: 12,
              }}>发现 <span style={{ ...NUM, color: '#818CF8' }}>{pathResult.path_count}</span> 条路径</div>
              {pathResult.paths?.map((path, i) => (
                <div key={i} style={{
                  padding: '10px 12px',
                  background: 'var(--bg-1)',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                  marginBottom: 6,
                }}>
                  <div style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 4,
                    alignItems: 'center',
                  }}>
                    {path.map((node, j) => (
                      <React.Fragment key={j}>
                        <Tag style={{
                          color: NODE_COLORS[node.type || ''] || '#7C7F9A',
                          border: `1px solid ${NODE_COLORS[node.type || ''] || '#7C7F9A'}25`,
                          fontSize: 11,
                          fontWeight: 500,
                          margin: 0,
                          borderRadius: 5,
                          ...FB,
                          background: `${NODE_COLORS[node.type || ''] || '#7C7F9A'}08`,
                          padding: '1px 7px',
                        }}>
                          {node.value || node.id}
                        </Tag>
                        {j < path.length - 1 && (
                          <span style={{ color: 'var(--text-2)', fontSize: 11, ...FB }}>→</span>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default Graph;
