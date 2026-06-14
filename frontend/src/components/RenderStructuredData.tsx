import React from 'react';
import { Tag, Progress, Tooltip } from 'antd';
import {
  CheckCircleOutlined, CloseCircleOutlined, WarningOutlined,
  InfoCircleOutlined, SafetyCertificateOutlined, ThunderboltOutlined,
  AimOutlined, BugOutlined, LinkOutlined, UserOutlined,
  GlobalOutlined, CalendarOutlined, FieldNumberOutlined,
  RiseOutlined, FallOutlined, MinusOutlined, BranchesOutlined,
  FileTextOutlined, EyeOutlined, ApiOutlined
} from '@ant-design/icons';

type StructuredData = Record<string, unknown> | unknown[] | null | undefined;

const KEY_ZH: Record<string, string> = {
  entity_id: '实体ID', entity_name: '实体名称', entity_type: '实体类型',
  confidence: '置信度', risk_score: '风险评分', threat_level: '威胁等级',
  prediction: '预测结果', attack_type: '攻击类型', attack_vector: '攻击向量',
  target: '攻击目标', source: '来源', sources: '来源',
  probability: '概率', likelihood: '可能性', severity: '严重程度',
  impact: '影响', description: '描述', summary: '摘要', detail: '详情',
  recommendation: '建议', recommendations: '建议', mitigation: '缓解措施',
  indicators: '指标', iocs: '威胁指标', ioc: '威胁指标',
  related_entities: '关联实体', related_intelligence: '关联情报',
  aliases: '别名', name: '名称', value: '值', context: '上下文',
  status: '状态', type: '类型', category: '分类', stage: '阶段',
  score: '评分', rank: '排名', level: '等级',
  fingerprint: '行为指纹', fingerprint_vector: '指纹向量',
  similarity: '相似度', same_source_entities: '同源实体',
  attribution_report: '归因报告', evidence: '证据', evidence_chain: '证据链',
  verified: '验证结果', valid: '是否有效', is_valid: '是否有效',
  hallucination_detected: '幻觉检出', hallucination_score: '幻觉评分',
  hallucinations: '幻觉项', reason: '原因', reasons: '原因',
  chain: '溯源链', evolution: '演化记录', stages: '阶段记录',
  drift_velocity: '漂移速度', drift_direction: '漂移方向',
  drift_history: '漂移历史', migration_path: '迁移路径',
  migration_targets: '迁移目标', term: '术语', meaning: '含义',
  original_meaning: '原始含义', current_meaning: '当前含义',
  zero_day_score: '零日评分', zero_day_detected: '零日检出',
  is_zero_day: '是否零日', novelty_score: '新颖度评分',
  detection_result: '检测结果', detections: '检测结果',
  path: '路径', paths: '路径', nodes: '节点', edges: '边',
  community: '社区', communities: '社区', members: '成员',
  first_seen: '首次出现', last_seen: '最近出现', last_updated: '最近更新',
  created_at: '创建时间', updated_at: '更新时间', collected_at: '采集时间',
  timestamp: '时间戳', date: '日期', time: '时间',
  total: '总数', count: '数量', total_entities: '实体总数',
  total_relations: '关系总数', total_intelligence: '情报总数',
  node_count: '节点数', edge_count: '边数',
  relation_count: '关系数', entity_count: '实体数',
  intelligence_id: '情报ID', pir_ids: '情报需求',
  report_type: '报告类型', content: '内容', title: '标题',
  metadata: '元数据', properties: '属性', label: '标签',
  graph: '图谱', subgraph: '子图谱',
  analysis: '分析结果', result: '结果', results: '结果',
  warning_level: '预警等级', warning_type: '预警类型',
  early_warning: '早期预警', warnings: '预警',
  simulation: '模拟结果', propagation: '传播路径',
  affected_entities: '受影响实体', risk_factors: '风险因素',
  attack_patterns: '攻击模式', tactics: '战术', techniques: '技术',
  procedures: '程序',ttp: 'TTP',
  actor: '攻击者', actors: '攻击者', victim: '受害者',
  malware: '恶意软件', tools: '工具', infrastructure: '基础设施',
  campaign: '攻击活动', campaigns: '攻击活动',
  degree: '连接度', centrality: '中心度', betweenness: '介数中心度',
  pagerank: 'PageRank', community_id: '社区编号',
  source_entity_id: '源实体', target_entity_id: '目标实体',
  source_entity_value: '源实体名称', target_entity_value: '目标实体名称',
  source_entity_type: '源实体类型', target_entity_type: '目标实体类型',
  relation_type: '关系类型',
  records: '记录', record_count: '记录数',
  total_chains: '溯源链总数', total_records: '记录总数',
  verified_count: '已验证通过', hallucination_count: '幻觉检出数',
  total_intel_scanned: '扫描情报数', total_detections: '检测总数',
  drift_results: '漂移分析结果',
  entities: '实体列表', relations: '关系列表',
  new_meaning: '新含义', old_meaning: '旧含义',
  domain_from: '源领域', domain_to: '目标领域',
  timestamp_first: '首次时间戳', timestamp_last: '最近时间戳',
  matched_terms: '匹配术语', decoded_text: '解码文本',
  found_terms: '发现术语', unmatched: '未匹配',
  intel_ids: '情报ID列表', pir_id: '情报需求ID',
  intelligence_ids: '情报ID列表', task_id: '任务ID',
  sections: '报告章节', raw_content: '原始内容',
  cleaned_content: '清洗后内容', analyzed_content: '分析后内容',
  blacktalk_count: '暗语数量', entities_count: '实体数量',
  search_query: '搜索内容', matches: '匹配结果',
  snapshot: '快照', snapshots: '快照列表',
  from_stage: '起始阶段', to_stage: '目标阶段',
  processing_time: '处理耗时', model_used: '使用模型',
  token_count: 'Token数量',
};

const VALUE_ZH: Record<string, string> = {
  true: '是', false: '否', yes: '是', no: '否',
  null: '无', none: '无', unknown: '未知',
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
  raw: '原始', cleaned: '已清洗', analyzed: '已分析',
  raw_collection: '原始采集', enriched: '已增强', reported: '已报告', pir_generated: '已生成需求',
  draft: '草稿', generating: '生成中', completed: '已完成', failed: '失败',
  pending: '待处理', processing: '处理中', active: '活跃', inactive: '不活跃',
  person: '人物', organization: '组织', phone: '手机', account: '账号',
  website: '网站', ip: 'IP地址', location: '地点', email: '邮箱',
  tool: '工具', blacktalk: '暗语', malware: '恶意软件', service: '服务',
  crypto_wallet: '加密钱包', payment_method: '支付方式', domain: '域名', url: 'URL', hash: '哈希',
  comprehensive: '综合分析', threat_assessment: '威胁研判', trend_analysis: '趋势分析', entity_profile: '实体画像',
  uses: '使用', belongs_to: '属于', communicates_with: '通信', operates: '运营',
  sells: '出售', buys: '购买', associated_with: '关联', located_in: '位于',
  controls: '控制', derived_from: '衍生自',
  predict: '攻击预测', simulate: '攻击模拟', warning: '早期预警',
  detect: '零日检测', drift: '语义漂移', migration: '语义迁移',
  verify: '溯源验证', evolution: '演化追踪', hallucination: '幻觉检测', chain: '溯源链', search: '内容搜索',
  fingerprint: '指纹分析', findSame: '同源发现', report: '归因报告',
};

const THREAT_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  critical: { bg: 'rgba(239,68,68,0.08)', color: '#DC2626', border: 'rgba(239,68,68,0.2)' },
  high: { bg: 'rgba(245,158,11,0.08)', color: '#D97706', border: 'rgba(245,158,11,0.2)' },
  medium: { bg: 'rgba(30,64,175,0.06)', color: '#1E40AF', border: 'rgba(30,64,175,0.15)' },
  low: { bg: 'rgba(34,197,94,0.06)', color: '#16A34A', border: 'rgba(34,197,94,0.15)' },
  info: { bg: 'rgba(8,145,178,0.06)', color: '#0891B2', border: 'rgba(8,145,178,0.15)' },
};

const STATUS_STYLES: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
  true: { icon: <CheckCircleOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
  false: { icon: <CloseCircleOutlined />, color: '#DC2626', bg: 'rgba(239,68,68,0.06)' },
  yes: { icon: <CheckCircleOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
  no: { icon: <CloseCircleOutlined />, color: '#DC2626', bg: 'rgba(239,68,68,0.06)' },
  valid: { icon: <CheckCircleOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
  invalid: { icon: <CloseCircleOutlined />, color: '#DC2626', bg: 'rgba(239,68,68,0.06)' },
  verified: { icon: <SafetyCertificateOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
  completed: { icon: <CheckCircleOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
  failed: { icon: <CloseCircleOutlined />, color: '#DC2626', bg: 'rgba(239,68,68,0.06)' },
  critical: { icon: <WarningOutlined />, color: '#DC2626', bg: 'rgba(239,68,68,0.06)' },
  high: { icon: <WarningOutlined />, color: '#D97706', bg: 'rgba(245,158,11,0.06)' },
  medium: { icon: <InfoCircleOutlined />, color: '#1E40AF', bg: 'rgba(30,64,175,0.06)' },
  low: { icon: <InfoCircleOutlined />, color: '#16A34A', bg: 'rgba(34,197,94,0.06)' },
};

function translateKey(k: string): string {
  if (KEY_ZH[k]) return KEY_ZH[k];
  for (const [en, zh] of Object.entries(KEY_ZH)) {
    if (k.startsWith(en + '_')) return zh + k.slice(en.length).replace(/_/g, '');
  }
  return k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function translateValue(v: unknown): string {
  if (v == null) return '无';
  const s = String(v).toLowerCase();
  if (VALUE_ZH[s]) return VALUE_ZH[s];
  return String(v);
}

function isTimestamp(k: string, v: unknown): boolean {
  if (!v || typeof v !== 'string') return false;
  const kl = k.toLowerCase();
  if (!kl.includes('time') && !kl.includes('date') && !kl.includes('_at') && !kl.includes('seen')) return false;
  return /^\d{4}-\d{2}-\d{2}/.test(v) || /^\d{4}\/\d{2}\/\d{2}/.test(v);
}

function formatTimestamp(v: string): string {
  try {
    const d = new Date(v);
    if (isNaN(d.getTime())) return v;
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMs / 3600000);
    const diffDay = Math.floor(diffMs / 86400000);
    let relative = '';
    if (diffMin < 1) relative = '刚刚';
    else if (diffMin < 60) relative = `${diffMin}分钟前`;
    else if (diffHr < 24) relative = `${diffHr}小时前`;
    else if (diffDay < 7) relative = `${diffDay}天前`;
    else if (diffDay < 30) relative = `${Math.floor(diffDay / 7)}周前`;
    else relative = `${Math.floor(diffDay / 30)}个月前`;
    const dateStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const timeStr = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    return `${dateStr} ${timeStr}（${relative}）`;
  } catch {
    return v;
  }
}

function isConfidenceKey(k: string): boolean {
  const kl = k.toLowerCase();
  return kl === 'confidence' || kl === 'similarity' || kl === 'probability' || kl === 'likelihood' || kl.includes('score') || kl === 'novelty_score' || kl === 'hallucination_score' || kl === 'risk_score' || kl === 'zero_day_score';
}

function isPercentageValue(v: unknown): boolean {
  return typeof v === 'number' && v >= 0 && v <= 1;
}

function isUUID(v: unknown): boolean {
  return typeof v === 'string' && /^[0-9a-f]{32}$/i.test(v);
}

function shortenId(v: string): string {
  if (v.length <= 12) return v;
  return `${v.slice(0, 8)}…${v.slice(-4)}`;
}

const ValueRenderer: React.FC<{ k: string; v: unknown; depth: number }> = ({ k, v, depth }) => {
  if (v == null) return <span style={{ color: '#9CA3AF', fontSize: 12 }}>—</span>;

  if (typeof v === 'boolean') {
    const st = v ? STATUS_STYLES.true : STATUS_STYLES.false;
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 9999, background: st.bg, color: st.color, fontSize: 12, fontWeight: 600 }}>
        {st.icon} {v ? '是' : '否'}
      </span>
    );
  }

  if (isUUID(v)) {
    return (
      <Tooltip title={String(v)}>
        <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: '#6B7280', background: 'rgba(30,64,175,0.04)', padding: '2px 8px', borderRadius: 4, cursor: 'help' }}>
          {shortenId(String(v))}
        </span>
      </Tooltip>
    );
  }

  if (isTimestamp(k, v)) {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: '#6B7280' }}>
        <CalendarOutlined style={{ fontSize: 12, color: '#9CA3AF' }} />
        {formatTimestamp(String(v))}
      </span>
    );
  }

  if (isConfidenceKey(k) && typeof v === 'number' && v >= 0 && v <= 1) {
    const pct = Math.round(v * 100);
    let status: 'success' | 'normal' | 'exception' | 'active' = 'normal';
    let color = '#1E40AF';
    if (pct >= 80) { status = 'success'; color = '#059669'; }
    else if (pct >= 50) { status = 'normal'; color = '#1E40AF'; }
    else if (pct >= 30) { status = 'active'; color = '#B45309'; }
    else { status = 'exception'; color = '#B91C1C'; }
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Progress percent={pct} size="small" style={{ width: 100, margin: 0 }} strokeColor={color} status={status} />
        <span style={{ fontSize: 13, fontWeight: 700, color }}>{pct}%</span>
      </div>
    );
  }

  if (typeof v === 'number') {
    if (k.toLowerCase().includes('velocity') || k.toLowerCase().includes('drift')) {
      const isPos = v > 0;
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 13, fontWeight: 600, color: isPos ? '#DC2626' : '#16A34A' }}>
          {isPos ? <RiseOutlined /> : v < 0 ? <FallOutlined /> : <MinusOutlined />}
          {v.toFixed(4)}
        </span>
      );
    }
    return <span style={{ fontSize: 13, fontWeight: 600, color: '#0C0E12', fontFamily: "'IBM Plex Mono', monospace" }}>{v.toLocaleString()}</span>;
  }

  if (typeof v === 'string') {
    const vl = v.toLowerCase();
    if (THREAT_COLORS[vl]) {
      const tc = THREAT_COLORS[vl];
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 12px', borderRadius: 9999, background: tc.bg, color: tc.color, fontSize: 12, fontWeight: 600, border: `1px solid ${tc.border}` }}>
          <WarningOutlined style={{ fontSize: 11 }} />
          {translateValue(v)}
        </span>
      );
    }
    if (STATUS_STYLES[vl]) {
      const ss = STATUS_STYLES[vl];
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 9999, background: ss.bg, color: ss.color, fontSize: 12, fontWeight: 600 }}>
          {ss.icon} {translateValue(v)}
        </span>
      );
    }
    if (VALUE_ZH[vl] && VALUE_ZH[vl] !== v) {
      return <Tag style={{ margin: 0, borderRadius: 9999, fontSize: 11, fontWeight: 500 }}>{VALUE_ZH[vl]}</Tag>;
    }
    if (v.length > 120) {
      return (
        <Tooltip title={v}>
          <span style={{ fontSize: 12, color: '#6B7280', lineHeight: 1.6, display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{v}</span>
        </Tooltip>
      );
    }
    return <span style={{ fontSize: 12, color: '#6B7280', lineHeight: 1.6 }}>{v}</span>;
  }

  if (Array.isArray(v)) {
    if (v.length === 0) return <span style={{ color: '#9CA3AF', fontSize: 12 }}>无</span>;
    if (v.length <= 5 && v.every(item => typeof item === 'string' && item.length < 30)) {
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {v.map((item, i) => (
            <Tag key={i} style={{ margin: 0, borderRadius: 9999, fontSize: 10, fontWeight: 500, background: 'rgba(30,64,175,0.06)', color: '#1E40AF', border: '1px solid rgba(30,64,175,0.12)' }}>
              {String(item).length > 20 ? shortenId(String(item)) : String(item)}
            </Tag>
          ))}
        </div>
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {v.slice(0, 8).map((item, i) => (
          <div key={i} style={{ padding: '8px 12px', background: 'rgba(30,64,175,0.02)', borderRadius: 8, border: '1px solid rgba(30,64,175,0.06)' }}>
            {item != null && typeof item === 'object'
              ? <InlineObjectRenderer data={item as Record<string, unknown>} depth={depth + 1} />
              : <ValueRenderer k={`${k}[${i}]`} v={item} depth={depth} />
            }
          </div>
        ))}
        {v.length > 8 && <span style={{ fontSize: 11, color: '#9CA3AF' }}>…还有 {v.length - 8} 项</span>}
      </div>
    );
  }

  if (typeof v === 'object' && v !== null) {
    return <InlineObjectRenderer data={v as Record<string, unknown>} depth={depth + 1} />;
  }

  return <span style={{ fontSize: 12, color: '#6B7280' }}>{String(v)}</span>;
};

const InlineObjectRenderer: React.FC<{ data: Record<string, unknown>; depth: number }> = ({ data, depth }) => {
  const entries = Object.entries(data);
  if (entries.length === 0) return <span style={{ color: '#9CA3AF', fontSize: 12 }}>空</span>;

  if (depth > 3) {
    return <pre style={{ whiteSpace: 'pre-wrap', fontSize: 11, margin: 0, color: '#9CA3AF', background: 'rgba(0,0,0,0.02)', padding: 8, borderRadius: 6 }}>{JSON.stringify(data, null, 1)}</pre>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {entries.map(([k, v]) => (
        <div key={k}>
          <div style={{ fontSize: 11, color: '#9CA3AF', fontWeight: 600, marginBottom: 3, display: 'flex', alignItems: 'center', gap: 4 }}>
            <FieldNumberOutlined style={{ fontSize: 9 }} />
            {translateKey(k)}
          </div>
          <div style={{ paddingLeft: 8 }}>
            <ValueRenderer k={k} v={v} depth={depth} />
          </div>
        </div>
      ))}
    </div>
  );
};

const RenderStructuredData: React.FC<{ data: StructuredData; emptyText?: string; maxEntries?: number; title?: string }> = ({
  data,
  emptyText = '执行后查看结果',
  maxEntries = 12,
  title,
}) => {
  if (!data) {
    return (
      <div style={{ textAlign: 'center', padding: 32 }}>
        <ApiOutlined style={{ fontSize: 32, color: '#D1D5DB', marginBottom: 8 }} />
        <div style={{ color: '#9CA3AF', fontSize: 13 }}>{emptyText}</div>
      </div>
    );
  }

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return (
        <div style={{ textAlign: 'center', padding: 32 }}>
          <ApiOutlined style={{ fontSize: 32, color: '#D1D5DB', marginBottom: 8 }} />
          <div style={{ color: '#9CA3AF', fontSize: 13 }}>{emptyText}</div>
        </div>
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {title && <div style={{ fontSize: 13, fontWeight: 700, color: '#0C0E12', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}><BranchesOutlined style={{ color: '#1E40AF' }} />{title}</div>}
        {data.slice(0, maxEntries).map((item, i) => (
          <div key={i} style={{ padding: 12, background: '#FFFFFF', borderRadius: 10, border: '1px solid rgba(30,64,175,0.08)', boxShadow: '0 1px 4px rgba(0,0,0,0.03)' }}>
            {item != null && typeof item === 'object'
              ? <InlineObjectRenderer data={item as Record<string, unknown>} depth={0} />
              : <ValueRenderer k={`item`} v={item} depth={0} />
            }
          </div>
        ))}
        {data.length > maxEntries && (
          <div style={{ textAlign: 'center', padding: 8, fontSize: 12, color: '#9CA3AF' }}>
            显示前 {maxEntries} 项，共 {data.length} 项
          </div>
        )}
      </div>
    );
  }

  if (typeof data === 'object') {
    const entries = Object.entries(data);
    if (entries.length === 0) {
      return (
        <div style={{ textAlign: 'center', padding: 32 }}>
          <ApiOutlined style={{ fontSize: 32, color: '#D1D5DB', marginBottom: 8 }} />
          <div style={{ color: '#9CA3AF', fontSize: 13 }}>{emptyText}</div>
        </div>
      );
    }

    const topEntries = entries.slice(0, maxEntries);

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {title && <div style={{ fontSize: 14, fontWeight: 700, color: '#0C0E12', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}><FileTextOutlined style={{ color: '#1E40AF' }} />{title}</div>}
        {topEntries.map(([k, v]) => {
          const zhKey = translateKey(k);
          const isObjVal = v != null && typeof v === 'object' && !Array.isArray(v);
          const isArrVal = Array.isArray(v);

          return (
            <div key={k} style={{ padding: isObjVal || isArrVal ? 14 : '10px 14px', background: '#FFFFFF', borderRadius: 10, border: '1px solid rgba(30,64,175,0.08)', boxShadow: '0 1px 4px rgba(0,0,0,0.03)' }}>
              <div style={{ fontSize: 12, color: '#1E40AF', fontWeight: 600, marginBottom: isObjVal || isArrVal ? 8 : 6, display: 'flex', alignItems: 'center', gap: 5 }}>
                <EyeOutlined style={{ fontSize: 10 }} />
                {zhKey}
                {isArrVal && <span style={{ fontSize: 10, color: '#9CA3AF', fontWeight: 400 }}>({(v as unknown[]).length}项)</span>}
              </div>
              <ValueRenderer k={k} v={v} depth={0} />
            </div>
          );
        })}
        {entries.length > maxEntries && (
          <div style={{ textAlign: 'center', padding: 8, fontSize: 12, color: '#9CA3AF' }}>
            显示前 {maxEntries} 个字段，共 {entries.length} 个
          </div>
        )}
      </div>
    );
  }

  return <div style={{ fontSize: 13, color: '#6B7280', padding: 12, background: '#FFFFFF', borderRadius: 8, border: '1px solid rgba(30,64,175,0.08)' }}>{String(data)}</div>;
};

export default RenderStructuredData;
