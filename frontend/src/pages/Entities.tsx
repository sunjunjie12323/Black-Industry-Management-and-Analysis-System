import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Button, Modal, Form, Input, Select, Space, Spin, Empty,
  Popconfirm, Tooltip, Pagination,
} from 'antd';
import {
  DeleteOutlined, LinkOutlined, SearchOutlined,
  UserOutlined, GlobalOutlined, ToolOutlined, MessageOutlined,
  AppstoreOutlined, PlusOutlined, ReloadOutlined,
} from '@ant-design/icons';
import { Treemap, ResponsiveContainer, Tooltip as RTooltip } from 'recharts';
import { graphApi, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

const ACCENT_BLUE = '#6C5CE7';
const ACCENT_PINK = '#EC4899';
const ACCENT_AMBER = '#F97316';
const ACCENT_GREEN = '#22C55E';
const ACCENT_CYAN = '#06B6D4';

const TEXT_PRIMARY = '#E8E9ED';
const TEXT_SECONDARY = '#E8E9ED';
const TEXT_MUTED = '#7C7F9A';
const TEXT_LIGHT = '#7C7F9A';
const BORDER_COLOR = 'rgba(255,255,255,0.06)';
const BORDER_LIGHT = 'rgba(255,255,255,0.06)';
const SURFACE_BG = '#0B0D17';
const WHITE = '#141625';

const DISPLAY_FONT = 'var(--font-display)';
const BODY_FONT = 'var(--font-body)';
const NUM_STYLE: React.CSSProperties = {
  fontFamily: 'var(--font-number)',
  fontVariantNumeric: 'tabular-nums',
};

const TREEMAP_COLORS = [
  '#818CF8', '#F472B6', '#FBBF24', '#34D399', '#22D3EE',
  '#A78BFA', '#FB923C', '#F87171', '#2DD4BF', '#60A5FA',
  '#C084FC', '#FCA5A5', '#7C7F9A', '#6EE7B7', '#FDA4AF', '#7C7F9A',
];

const TreemapContent = (props: Record<string, unknown>) => {
  const { x, y, width, height, name, value, index } = props as {
    x: number; y: number; width: number; height: number;
    name: string; value: number; index: number;
  };
  if (!width || !height || width < 20 || height < 16) return null;
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} fill={TREEMAP_COLORS[index % TREEMAP_COLORS.length]} fillOpacity={0.75} stroke={WHITE} strokeWidth={2} rx={4} />
      {width > 45 && height > 32 && (
        <>
          <text x={x + 6} y={y + 16} fill={WHITE} fontSize={11} fontWeight="600" fontFamily={BODY_FONT}>{name}</text>
          <text x={x + 6} y={y + 28} fill="rgba(255,255,255,0.8)" fontSize={10} style={NUM_STYLE}>{value}</text>
        </>
      )}
    </g>
  );
};

const ENTITY_TYPES = [
  { value: 'ip', label: 'IP地址', icon: <GlobalOutlined />, color: '#6C5CE7' },
  { value: 'account', label: '账号', icon: <UserOutlined />, color: '#EC4899' },
  { value: 'blacktalk', label: '黑话', icon: <MessageOutlined />, color: '#F97316' },
  { value: 'service', label: '服务', color: '#22C55E' },
  { value: 'crypto_wallet', label: '钱包', color: '#06B6D4' },
  { value: 'tool', label: '工具', icon: <ToolOutlined />, color: '#8B5CF6' },
  { value: 'person', label: '人员', color: '#14B8A6' },
  { value: 'domain', label: '域名', icon: <GlobalOutlined />, color: '#3B82F6' },
  { value: 'malware', label: '恶意软件', color: '#EF4444' },
  { value: 'organization', label: '组织', color: '#8B5CF6' },
  { value: 'email', label: '邮箱', color: '#F97316' },
  { value: 'url', label: '链接', icon: <GlobalOutlined />, color: '#0EA5E9' },
  { value: 'hash', label: '哈希', color: '#7C7F9A' },
  { value: 'phone', label: '电话', color: '#22C55E' },
  { value: 'payment_method', label: '支付', color: '#E11D48' },
  { value: 'other', label: '其他', color: '#7C7F9A' },
];

const Entities: React.FC = () => {
  const message = useAntdMessage();
  const mountedRef = useRef(true);
  const [entities, setEntities] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | undefined>(undefined);
  const [stats, setStats] = useState<Record<string, unknown>>({});
  const [addOpen, setAddOpen] = useState(false);
  const [entityPage, setEntityPage] = useState(1);
  const ENTITY_PAGE_SIZE = 12;
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [relateOpen, setRelateOpen] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState<Record<string, unknown> | null>(null);
  const [addForm] = Form.useForm();
  const [relateForm] = Form.useForm();
  const headerRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [entRes, statsRes] = await Promise.allSettled([
        graphApi.listEntities({ entity_type: typeFilter, search: search || undefined }),
        graphApi.getStats(),
      ]);
      if (!mountedRef.current) { setLoading(false); return; }
      if (entRes.status === 'fulfilled') {
        const d = entRes.value as unknown as Record<string, unknown>;
        setEntities((d?.items || []) as Record<string, unknown>[]);
      } else { setEntities([]); }
      if (statsRes.status === 'fulfilled') setStats(statsRes.value as unknown as Record<string, unknown>);
    } catch { if (mountedRef.current) setEntities([]); } finally { if (mountedRef.current) setLoading(false); }
  };

  useEffect(() => { fetchData(); return () => { mountedRef.current = false; }; }, [search, typeFilter]);

  useEffect(() => {
    if (headerRef.current) {
      const tween = gsap.fromTo(headerRef.current, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, ease: 'power2.out' });
      return () => { tween.kill(); };
    }
  }, []);

  useEffect(() => {
    if (listRef.current) {
      const rows = listRef.current.querySelectorAll('.entity-card');
      const tween = gsap.fromTo(rows, { y: 6, opacity: 0 }, { y: 0, opacity: 1, duration: 0.25, stagger: 0.02, ease: 'power2.out' });
      return () => { tween.kill(); };
    }
  }, [entities]);

  const getEntityId = (e: Record<string, unknown>) => String(e.id || e.entity_id);

  const entityTypes = (stats.entity_types || {}) as Record<string, number>;

  const kpiStats = useMemo(() => [
    { label: '实体总数', value: Number(stats.node_count || stats.total_entities || entities.length), color: ACCENT_BLUE },
    { label: 'IP', value: Number(entityTypes.ip || entities.filter(e => String(e.type) === 'ip').length), color: ACCENT_PINK },
    { label: '账号', value: Number(entityTypes.account || entities.filter(e => String(e.type) === 'account').length), color: ACCENT_AMBER },
    { label: '黑话', value: Number(entityTypes.blacktalk || entities.filter(e => String(e.type) === 'blacktalk').length), color: ACCENT_GREEN },
  ], [stats, entities]);

  const typeCounts = useMemo(() => {
    const map: Record<string, number> = {};
    entities.forEach(e => { const t = String(e.type || 'other'); map[t] = (map[t] || 0) + 1; });
    return map;
  }, [entities]);

  const typeDist = useMemo(() => {
    const map: Record<string, number> = {};
    entities.forEach(e => { const t = String(e.type || 'other'); map[t] = (map[t] || 0) + 1; });
    return Object.entries(map).map(([name, value]) => ({
      name: ENTITY_TYPES.find(t => t.value === name)?.label || name,
      value,
    }));
  }, [entities]);

  const maxMentionCount = useMemo(() => {
    const counts = entities.map(e => {
      const mc = Number(e.mention_count || 0);
      if (mc > 0) return mc;
      const srcIds = e.source_ids as unknown[];
      return srcIds ? srcIds.length : 0;
    });
    return Math.max(...counts, 1);
  }, [entities]);

  const handleAdd = async () => {
    try {
      const values = await addForm.validateFields();
      await graphApi.addEntity(String(values.type), String(values.name || values.value), String(values.description || ''), 0.8);
      message.success('实体已添加');
      setAddOpen(false);
      addForm.resetFields();
      fetchData();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleRelate = async () => {
    if (!selectedEntity) return;
    try {
      const values = await relateForm.validateFields();
      const id = getEntityId(selectedEntity);
      await graphApi.addRelation(id, String(values.target_id), String(values.relationship_type), 0.8, String(values.description || ''));
      message.success('关联已创建');
      setRelateOpen(false);
      relateForm.resetFields();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try { await graphApi.deleteEntity(id); message.success('实体已删除'); fetchData(); } catch (err) { message.error(getErrorMessage(err)); }
    finally { setDeletingId(null); }
  };

  const tooltipStyle: React.CSSProperties = { background: '#1C1F35', border: `1px solid ${BORDER_COLOR}`, borderRadius: 8, fontSize: 12, color: TEXT_PRIMARY, padding: '8px 12px', ...NUM_STYLE, boxShadow: '0 2px 8px rgba(0,0,0,0.3)' };

  const filterPillTypes = ENTITY_TYPES.filter(t => typeCounts[t.value]);

  return (
    <div style={{ padding: 0, background: SURFACE_BG, minHeight: '100vh', overflowX: 'hidden' }}>
      <style>{`
        .entity-card {
          transition: transform 0.2s cubic-bezier(0.4,0,0.2,1), box-shadow 0.2s cubic-bezier(0.4,0,0.2,1);
        }
        .entity-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 12px 32px rgba(0,0,0,0.3), 0 2px 8px rgba(0,0,0,0.2);
        }
        .entity-card .card-actions {
          opacity: 0;
          transition: opacity 0.15s ease;
        }
        .entity-card:hover .card-actions {
          opacity: 1;
        }
        .entity-filter-pill {
          transition: all 0.18s cubic-bezier(0.4,0,0.2,1);
          cursor: pointer;
          user-select: none;
        }
        .entity-filter-pill:hover {
          transform: translateY(-1px);
          box-shadow: 0 2px 8px rgba(0,0,0,0.25);
        }
        .entity-filter-pill:active {
          transform: translateY(0);
        }
        .entity-search-input .ant-input {
          border-radius: 20px !important;
          background: ${WHITE} !important;
          font-family: ${BODY_FONT} !important;
          font-size: 13px !important;
          color: ${TEXT_PRIMARY} !important;
          height: 36px !important;
        }
        .entity-search-input .ant-input::placeholder {
          color: ${TEXT_LIGHT} !important;
        }
        .entity-search-input .ant-input-affix-wrapper {
          border-radius: 20px !important;
          background: ${WHITE} !important;
          border: 1.5px solid ${BORDER_COLOR} !important;
          height: 40px !important;
          padding: 0 16px !important;
        }
        .entity-search-input .ant-input-affix-wrapper:hover {
          border-color: ${ACCENT_BLUE} !important;
        }
        .entity-search-input .ant-input-affix-wrapper:focus-within {
          border-color: ${ACCENT_BLUE} !important;
          box-shadow: 0 0 0 3px rgba(108,92,231,0.1) !important;
        }
        .entity-search-input .ant-input-affix-wrapper .ant-input {
          background: transparent !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-search-input .ant-input-prefix {
          margin-right: 8px !important;
          color: ${TEXT_LIGHT} !important;
        }
        .entity-modal .ant-modal-content {
          border-radius: 16px !important;
          padding: 0 !important;
          overflow: hidden;
          background: ${WHITE} !important;
          border: 1px solid ${BORDER_COLOR} !important;
          box-shadow: 0 20px 60px rgba(0,0,0,0.4) !important;
        }
        .entity-modal .ant-modal-header {
          border-radius: 16px 16px 0 0 !important;
          border-bottom: 1px solid ${BORDER_LIGHT} !important;
          padding: 20px 24px !important;
          margin: 0 !important;
          background: #1C1F35 !important;
        }
        .entity-modal .ant-modal-title {
          font-family: ${DISPLAY_FONT} !important;
          font-size: 18px !important;
          font-weight: 700 !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-modal .ant-modal-body {
          padding: 24px !important;
          background: ${WHITE} !important;
        }
        .entity-modal .ant-modal-footer {
          border-top: 1px solid ${BORDER_LIGHT} !important;
          padding: 16px 24px !important;
          margin: 0 !important;
          background: #1C1F35 !important;
        }
        .entity-modal .ant-btn {
          border-radius: 10px !important;
          font-family: ${BODY_FONT} !important;
          font-size: 13px !important;
          font-weight: 600 !important;
          height: 38px !important;
          padding: 0 22px !important;
          background: ${WHITE} !important;
          border-color: ${BORDER_COLOR} !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-modal .ant-btn:hover {
          border-color: ${ACCENT_BLUE} !important;
          color: ${ACCENT_BLUE} !important;
        }
        .entity-modal .ant-btn-primary {
          background: ${ACCENT_BLUE} !important;
          border-color: ${ACCENT_BLUE} !important;
          color: #E8E9ED !important;
          font-weight: 700 !important;
        }
        .entity-modal .ant-btn-primary:hover {
          background: #5B4BD5 !important;
          border-color: #5B4BD5 !important;
        }
        .entity-modal .ant-form-item-label > label {
          font-family: ${BODY_FONT} !important;
          font-size: 13px !important;
          color: ${TEXT_MUTED} !important;
          font-weight: 500 !important;
        }
        .entity-modal .ant-input,
        .entity-modal .ant-select-selector,
        .entity-modal .ant-input-affix-wrapper {
          border-radius: 10px !important;
          background: ${WHITE} !important;
          border-color: ${BORDER_COLOR} !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-modal .ant-input::placeholder {
          color: ${TEXT_LIGHT} !important;
        }
        .entity-modal .ant-input:hover,
        .entity-modal .ant-select-selector:hover,
        .entity-modal .ant-input-affix-wrapper:hover {
          border-color: ${ACCENT_BLUE} !important;
        }
        .entity-modal .ant-input:focus,
        .entity-modal .ant-input-focused,
        .entity-modal .ant-select-selector:focus,
        .entity-modal .ant-input-affix-wrapper:focus {
          border-color: ${ACCENT_BLUE} !important;
          box-shadow: 0 0 0 2px rgba(108,92,231,0.1) !important;
        }
        .entity-modal .ant-select-selection-item {
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-modal .ant-select-arrow {
          color: ${TEXT_MUTED} !important;
        }
        .entity-modal .ant-input-textarea textarea {
          background: ${WHITE} !important;
          color: ${TEXT_PRIMARY} !important;
          border-color: ${BORDER_COLOR} !important;
          border-radius: 10px !important;
        }
        .entity-modal .ant-input-textarea textarea::placeholder {
          color: ${TEXT_LIGHT} !important;
        }
        .entity-modal .ant-input-textarea textarea:hover {
          border-color: ${ACCENT_BLUE} !important;
        }
        .entity-modal .ant-input-textarea textarea:focus {
          border-color: ${ACCENT_BLUE} !important;
          box-shadow: 0 0 0 2px rgba(108,92,231,0.1) !important;
        }
        .entity-pagination .ant-pagination-item {
          border-radius: 8px !important;
          font-family: ${BODY_FONT} !important;
          font-size: 13px !important;
          background: ${WHITE} !important;
          border-color: ${BORDER_COLOR} !important;
        }
        .entity-pagination .ant-pagination-item a {
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-pagination .ant-pagination-item:hover {
          border-color: ${ACCENT_BLUE} !important;
        }
        .entity-pagination .ant-pagination-item:hover a {
          color: ${ACCENT_BLUE} !important;
        }
        .entity-pagination .ant-pagination-item-active {
          background: ${ACCENT_BLUE} !important;
          border-color: ${ACCENT_BLUE} !important;
        }
        .entity-pagination .ant-pagination-item-active a {
          color: #E8E9ED !important;
          font-weight: 700 !important;
        }
        .entity-pagination .ant-pagination-prev .ant-pagination-item-link,
        .entity-pagination .ant-pagination-next .ant-pagination-item-link {
          border-radius: 8px !important;
          background: ${WHITE} !important;
          border-color: ${BORDER_COLOR} !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .entity-pagination .ant-pagination-prev .ant-pagination-item-link:hover,
        .entity-pagination .ant-pagination-next .ant-pagination-item-link:hover {
          border-color: ${ACCENT_BLUE} !important;
          color: ${ACCENT_BLUE} !important;
        }
        .entity-pagination .ant-pagination-disabled .ant-pagination-item-link {
          opacity: 0.4 !important;
        }
        .ant-select-dropdown {
          background: ${WHITE} !important;
          border: 1px solid ${BORDER_COLOR} !important;
        }
        .ant-select-dropdown .ant-select-item {
          color: ${TEXT_PRIMARY} !important;
        }
        .ant-select-dropdown .ant-select-item-option-active {
          background: rgba(255,255,255,0.06) !important;
        }
        .ant-select-dropdown .ant-select-item-option-selected {
          background: rgba(108,92,231,0.08) !important;
          color: ${ACCENT_BLUE} !important;
        }
        .ant-popover-inner {
          background: ${WHITE} !important;
          border: 1px solid ${BORDER_COLOR} !important;
        }
        .ant-popconfirm-description {
          color: ${TEXT_PRIMARY} !important;
        }
        .ant-popconfirm-buttons .ant-btn {
          background: ${WHITE} !important;
          border-color: ${BORDER_COLOR} !important;
          color: ${TEXT_PRIMARY} !important;
        }
        .ant-popconfirm-buttons .ant-btn-primary {
          background: #EF4444 !important;
          border-color: #EF4444 !important;
          color: #fff !important;
        }
      `}</style>

      <div ref={headerRef} style={{
        padding: '32px 40px 28px',
        background: WHITE,
        borderBottom: `1px solid ${BORDER_LIGHT}`,
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 4,
              height: 52,
              borderRadius: 2,
              background: `linear-gradient(180deg, ${ACCENT_BLUE}, ${ACCENT_PINK})`,
              flexShrink: 0,
            }} />
            <div>
              <h1 style={{
                fontFamily: DISPLAY_FONT,
                fontSize: 26,
                fontWeight: 800,
                color: TEXT_PRIMARY,
                margin: 0,
                lineHeight: 1.2,
                letterSpacing: -0.5,
              }}>
                实体档案
              </h1>
              <p style={{
                fontFamily: BODY_FONT,
                fontSize: 13,
                color: TEXT_MUTED,
                margin: '4px 0 0',
                lineHeight: 1.4,
              }}>
                黑产实体提取与管理
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {kpiStats.map((s) => (
              <div
                key={s.label}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '8px 16px',
                  borderRadius: 12,
                  background: `${s.color}08`,
                  border: `1px solid ${s.color}15`,
                }}
              >
                <div style={{
                  width: 8,
                  height: 8,
                  borderRadius: 3,
                  background: s.color,
                  flexShrink: 0,
                }} />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <span style={{
                    fontFamily: BODY_FONT,
                    fontSize: 10,
                    color: TEXT_LIGHT,
                    fontWeight: 500,
                    lineHeight: 1,
                    textTransform: 'uppercase',
                    letterSpacing: 0.5,
                  }}>
                    {s.label}
                  </span>
                  <span style={{
                    fontFamily: BODY_FONT,
                    fontSize: 18,
                    fontWeight: 700,
                    color: s.color,
                    lineHeight: 1.2,
                    ...NUM_STYLE,
                  }}>
                    {s.value}
                  </span>
                </div>
              </div>
            ))}
            <div style={{ width: 1, height: 36, background: BORDER_COLOR, margin: '0 4px' }} />
            <Button
              onClick={fetchData}
              icon={<ReloadOutlined />}
              aria-label="刷新数据"
              style={{
                borderRadius: 10,
                fontFamily: BODY_FONT,
                fontWeight: 600,
                height: 38,
                fontSize: 13,
                color: TEXT_MUTED,
                border: `1px solid ${BORDER_COLOR}`,
              }}
            >
              刷新
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setAddOpen(true)}
              aria-label="添加实体"
              style={{
                borderRadius: 10,
                fontFamily: BODY_FONT,
                fontWeight: 700,
                height: 38,
                fontSize: 13,
                background: `linear-gradient(135deg, ${ACCENT_BLUE}, #5B4BD5)`,
                borderColor: ACCENT_BLUE,
                boxShadow: `0 2px 8px ${ACCENT_BLUE}30`,
              }}
            >
              添加实体
            </Button>
          </div>
        </div>
      </div>

      <div style={{ padding: '20px 40px' }}>
        <div style={{
          background: WHITE,
          borderRadius: 12,
          border: `1px solid ${BORDER_COLOR}`,
          boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 16,
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexWrap: 'wrap',
            flex: 1,
          }}>
            <div
              className="entity-filter-pill"
              onClick={() => setTypeFilter(undefined)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '7px 16px',
                borderRadius: 20,
                background: !typeFilter ? ACCENT_BLUE : 'rgba(255,255,255,0.06)',
                color: !typeFilter ? '#E8E9ED' : TEXT_SECONDARY,
                border: `1.5px solid ${!typeFilter ? ACCENT_BLUE : 'transparent'}`,
                fontFamily: BODY_FONT,
                fontSize: 13,
                fontWeight: !typeFilter ? 700 : 500,
                whiteSpace: 'nowrap',
              }}
            >
              <AppstoreOutlined style={{ fontSize: 12 }} />
              全部
              <span style={{
                ...NUM_STYLE,
                fontSize: 11,
                fontWeight: 700,
                background: !typeFilter ? 'rgba(255,255,255,0.25)' : `${TEXT_MUTED}20`,
                color: !typeFilter ? 'rgba(255,255,255,0.9)' : TEXT_MUTED,
                padding: '1px 8px',
                borderRadius: 10,
                marginLeft: 2,
              }}>
                {entities.length}
              </span>
            </div>
            {filterPillTypes.map((t) => {
              const isActive = typeFilter === t.value;
              const count = typeCounts[t.value] || 0;
              return (
                <div
                  key={t.value}
                  className="entity-filter-pill"
                  onClick={() => setTypeFilter(isActive ? undefined : t.value)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '7px 16px',
                    borderRadius: 20,
                    background: isActive ? t.color : 'rgba(255,255,255,0.06)',
                    color: isActive ? '#E8E9ED' : TEXT_SECONDARY,
                    border: `1.5px solid ${isActive ? t.color : 'transparent'}`,
                    fontFamily: BODY_FONT,
                    fontSize: 13,
                    fontWeight: isActive ? 700 : 500,
                    whiteSpace: 'nowrap',
                  }}
                >
                  {t.icon && <span style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center' }}>{t.icon}</span>}
                  {t.label}
                  <span style={{
                    ...NUM_STYLE,
                    fontSize: 11,
                    fontWeight: 700,
                    background: isActive ? 'rgba(255,255,255,0.25)' : `${t.color}15`,
                    color: isActive ? 'rgba(255,255,255,0.9)' : t.color,
                    padding: '1px 8px',
                    borderRadius: 10,
                    marginLeft: 2,
                  }}>
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
          <Input
            className="entity-search-input"
            placeholder="搜索实体..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            allowClear
            style={{ width: 240, flexShrink: 0 }}
            prefix={<SearchOutlined style={{ fontSize: 14 }} />}
          />
        </div>
      </div>

      {typeDist.length > 0 && (
        <div style={{ padding: '0 40px 20px' }}>
          <div style={{
            background: WHITE,
            borderRadius: 12,
            border: `1px solid ${BORDER_COLOR}`,
            overflow: 'hidden',
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          }}>
            <div style={{
              height: 3,
              background: `linear-gradient(90deg, ${ACCENT_BLUE}, ${ACCENT_PINK}, ${ACCENT_AMBER}, ${ACCENT_GREEN}, ${ACCENT_CYAN})`,
            }} />
            <div style={{
              padding: '16px 20px',
              borderBottom: `1px solid ${BORDER_LIGHT}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 28,
                  height: 28,
                  borderRadius: 8,
                  background: `${ACCENT_BLUE}10`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <AppstoreOutlined style={{ fontSize: 14, color: ACCENT_BLUE }} />
                </div>
                <span style={{
                  fontFamily: DISPLAY_FONT,
                  fontSize: 16,
                  fontWeight: 700,
                  color: TEXT_PRIMARY,
                }}>
                  实体类型分布
                </span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14 }}>
                {typeDist.map((d, i) => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 3, background: TREEMAP_COLORS[i % TREEMAP_COLORS.length] }} />
                    <span style={{ color: TEXT_MUTED, fontSize: 12, fontFamily: BODY_FONT, fontWeight: 500 }}>{d.name}</span>
                    <span style={{ color: TEXT_PRIMARY, fontSize: 12, ...NUM_STYLE, fontWeight: 600 }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ padding: '8px 0 0' }}>
              <ResponsiveContainer width="100%" height={200}>
                <Treemap
                  data={typeDist}
                  dataKey="value"
                  nameKey="name"
                  stroke="#141625"
                  fill={ACCENT_BLUE}
                  aspectRatio={4 / 3}
                  content={<TreemapContent />}
                >
                  <RTooltip contentStyle={tooltipStyle} formatter={(val: number, name: string) => [val, name]} />
                </Treemap>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      <div style={{ padding: '0 40px 32px' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}><Spin /></div>
        ) : entities.length === 0 ? (
          <div style={{
            padding: '80px 0',
            textAlign: 'center',
            background: WHITE,
            borderRadius: 12,
            border: `1px solid ${BORDER_COLOR}`,
            boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          }}>
            <Empty description={<span style={{ color: TEXT_MUTED, fontFamily: BODY_FONT, fontSize: 13 }}>暂无实体，点击「添加实体」开始管理</span>}>
              <Button
                type="primary"
                icon={<PlusOutlined />}
                onClick={() => setAddOpen(true)}
                style={{
                  borderRadius: 10,
                  fontFamily: BODY_FONT,
                  fontWeight: 700,
                  height: 38,
                  background: ACCENT_BLUE,
                  borderColor: ACCENT_BLUE,
                }}
              >
                添加实体
              </Button>
            </Empty>
          </div>
        ) : (
          <>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 18,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 28,
                  height: 28,
                  borderRadius: 8,
                  background: `${ACCENT_BLUE}10`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <AppstoreOutlined style={{ fontSize: 14, color: ACCENT_BLUE }} />
                </div>
                <span style={{
                  fontFamily: DISPLAY_FONT,
                  fontSize: 16,
                  fontWeight: 700,
                  color: TEXT_PRIMARY,
                }}>
                  实体列表
                </span>
              </div>
              <span style={{
                ...NUM_STYLE,
                fontSize: 13,
                color: TEXT_LIGHT,
                fontFamily: BODY_FONT,
              }}>
                {entities.length} 条记录
              </span>
            </div>
            <div ref={listRef} style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
              gap: 16,
            }}>
              {entities.slice((entityPage - 1) * ENTITY_PAGE_SIZE, entityPage * ENTITY_PAGE_SIZE).map((entity) => {
                const type = String(entity.type || 'other');
                const typeCfg = ENTITY_TYPES.find(t => t.value === type);
                const color = typeCfg?.color || '#7C7F9A';
                const label = typeCfg?.label || type;
                const id = getEntityId(entity);
                const rawMention = Number(entity.mention_count || 0);
                const mentionCount = rawMention > 0 ? rawMention : ((entity.source_ids as unknown[])?.length || 0);
                const mentionPct = Math.min((mentionCount / maxMentionCount) * 100, 100);
                const desc = String(entity.context || entity.description || '');
                return (
                  <div
                    key={id}
                    className="entity-card"
                    style={{
                      background: WHITE,
                      borderRadius: 12,
                      border: `1px solid ${BORDER_COLOR}`,
                      borderTop: `3px solid ${color}`,
                      overflow: 'hidden',
                      cursor: 'default',
                      position: 'relative',
                      display: 'flex',
                      flexDirection: 'column',
                      boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
                    }}
                  >
                    <div style={{ padding: '16px 18px 0' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{
                            fontFamily: BODY_FONT,
                            fontSize: 16,
                            fontWeight: 700,
                            color: TEXT_PRIMARY,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            lineHeight: 1.4,
                          }}>
                            {String(entity.name || entity.value || '—')}
                          </div>
                        </div>
                        <Space size={2} className="card-actions" style={{ flexShrink: 0, marginLeft: 8 }}>
                          <Tooltip title="关联">
                            <Button
                              type="text"
                              size="small"
                              icon={<LinkOutlined />}
                              onClick={() => { setSelectedEntity(entity); setRelateOpen(true); }}
                              style={{ color: TEXT_MUTED, fontSize: 13, borderRadius: 8, width: 30, height: 30, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                            />
                          </Tooltip>
                          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
                            <Tooltip title="删除">
                              <Button type="text" size="small" icon={<DeleteOutlined />} danger loading={deletingId === id} style={{ fontSize: 13, borderRadius: 8, width: 30, height: 30, display: 'flex', alignItems: 'center', justifyContent: 'center' }} />
                            </Tooltip>
                          </Popconfirm>
                        </Space>
                      </div>
                      <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          padding: '3px 10px',
                          borderRadius: 6,
                          background: `${color}10`,
                          color: color,
                          fontFamily: BODY_FONT,
                          fontSize: 11,
                          fontWeight: 600,
                        }}>
                          {typeCfg?.icon && <span style={{ fontSize: 10, display: 'inline-flex', alignItems: 'center' }}>{typeCfg.icon}</span>}
                          {label}
                        </span>
                      </div>
                    </div>
                    <div style={{ padding: '8px 18px 0' }}>
                      <div style={{
                        fontFamily: BODY_FONT,
                        fontSize: 13,
                        color: desc ? TEXT_MUTED : TEXT_LIGHT,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        lineHeight: 1.5,
                        fontStyle: desc ? 'normal' : 'italic',
                      }}>
                        {desc || '暂无描述'}
                      </div>
                    </div>
                    <div style={{
                      margin: '12px 18px 0',
                      padding: '10px 0 14px',
                      borderTop: `1px solid ${BORDER_LIGHT}`,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{
                          fontSize: 11,
                          color: TEXT_LIGHT,
                          fontFamily: BODY_FONT,
                          fontWeight: 500,
                          letterSpacing: 0.3,
                        }}>
                          提及次数
                        </span>
                        <span style={{
                          fontSize: 14,
                          fontWeight: 700,
                          color: color,
                          ...NUM_STYLE,
                        }}>
                          {mentionCount}
                        </span>
                      </div>
                      <div style={{
                        height: 4,
                        borderRadius: 2,
                        background: BORDER_LIGHT,
                        overflow: 'hidden',
                      }}>
                        <div style={{
                          height: '100%',
                          borderRadius: 2,
                          background: `linear-gradient(90deg, ${color}, ${color}BB)`,
                          width: `${mentionPct}%`,
                          transition: 'width 0.3s ease',
                        }} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
            {entities.length > ENTITY_PAGE_SIZE && (
              <div className="entity-pagination" style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 24 }}>
                <Pagination
                  current={entityPage}
                  pageSize={ENTITY_PAGE_SIZE}
                  total={entities.length}
                  onChange={setEntityPage}
                  size="small"
                  showTotal={t => `共 ${t} 条`}
                />
              </div>
            )}
          </>
        )}
      </div>

      <Modal
        className="entity-modal"
        open={addOpen}
        onCancel={() => { setAddOpen(false); addForm.resetFields(); }}
        onOk={handleAdd}
        width={520}
        okText="添加"
        cancelText="取消"
        title="添加实体"
        styles={{ content: { borderRadius: 16 }, mask: { borderRadius: 16 } }}
      >
        <Form form={addForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="实体名称" rules={[{ required: true, message: '请输入实体名称' }]}>
            <Input placeholder="例如: 料卡、洗钱通道" style={{ borderRadius: 10 }} />
          </Form.Item>
          <Form.Item name="type" label="实体类型" rules={[{ required: true, message: '请选择类型' }]}>
            <Select options={ENTITY_TYPES.map(t => ({ value: t.value, label: t.label }))} placeholder="选择类型" />
          </Form.Item>
          <Form.Item name="value" label="实体值">
            <Input placeholder="实体的具体值，如URL、账号等" style={{ borderRadius: 10 }} />
          </Form.Item>
          <Form.Item name="source" label="来源">
            <Input placeholder="情报来源" style={{ borderRadius: 10 }} />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={3} placeholder="实体描述信息" style={{ borderRadius: 10 }} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        className="entity-modal"
        open={relateOpen}
        onCancel={() => { setRelateOpen(false); relateForm.resetFields(); }}
        onOk={handleRelate}
        width={480}
        okText="创建关联"
        cancelText="取消"
        title="创建关联"
        styles={{ content: { borderRadius: 16 }, mask: { borderRadius: 16 } }}
      >
        <div style={{ marginTop: 16 }}>
          {selectedEntity && (
            <div style={{
              padding: 14,
              background: '#1C1F35',
              borderRadius: 10,
              border: `1px solid ${BORDER_LIGHT}`,
              marginBottom: 16,
            }}>
              <span style={{ fontSize: 12, fontFamily: BODY_FONT, color: TEXT_LIGHT }}>当前实体 </span>
              <span style={{ fontWeight: 600, fontFamily: BODY_FONT, fontSize: 13, color: ACCENT_BLUE }}>{String(selectedEntity.name || selectedEntity.value || '—')}</span>
            </div>
          )}
          <Form form={relateForm} layout="vertical">
            <Form.Item name="target_id" label="目标实体ID" rules={[{ required: true, message: '请输入目标实体ID' }]}>
              <Input placeholder="输入要关联的实体ID" style={{ borderRadius: 10 }} />
            </Form.Item>
            <Form.Item name="relationship_type" label="关系类型" rules={[{ required: true, message: '请选择关系类型' }]}>
              <Select options={[
                { value: 'related_to', label: '相关' },
                { value: 'uses', label: '使用' },
                { value: 'belongs_to', label: '属于' },
                { value: 'communicates_with', label: '通信' },
                { value: 'located_in', label: '位于' },
              ]} placeholder="选择关系类型" />
            </Form.Item>
            <Form.Item name="description" label="关系描述">
              <Input.TextArea rows={2} placeholder="描述两个实体之间的关系" style={{ borderRadius: 10 }} />
            </Form.Item>
          </Form>
        </div>
      </Modal>
    </div>
  );
};

export default Entities;
