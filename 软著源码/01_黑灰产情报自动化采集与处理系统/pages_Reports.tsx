import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Button, Modal, Form, Input, Select, Tag, Space, Spin, Empty,
  Popconfirm, Tooltip, Drawer, Pagination,
} from 'antd';
import {
  PlusOutlined, EditOutlined, EyeOutlined, DownloadOutlined,
  DeleteOutlined, FileTextOutlined, CheckCircleOutlined, SyncOutlined,
  ReloadOutlined, SearchOutlined,
} from '@ant-design/icons';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell } from 'recharts';
import ReactMarkdown from 'react-markdown';
import { reportsApi, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import StatCard from '../components/StatCard';
import { StaggeredBarShape } from '../components/AnimatedChart';

const REPORT_TYPES = [
  { value: 'threat_intelligence', label: '威胁情报' },
  { value: 'incident_analysis', label: '事件分析' },
  { value: 'vulnerability', label: '漏洞报告' },
  { value: 'malware_analysis', label: '恶意软件分析' },
  { value: 'campaign', label: '攻击活动' },
  { value: 'weekly', label: '周报' },
  { value: 'monthly', label: '月报' },
];

const TYPE_COLORS: Record<string, string> = {
  threat_intelligence: '#DC2626',
  incident_analysis: '#2563EB',
  vulnerability: '#EA580C',
  malware_analysis: '#7C3AED',
  campaign: '#0D9488',
  weekly: '#EAB308',
  monthly: '#16A34A',
};


const STATUS_MAP: Record<string, { label: string; color: string; dim: string }> = {
  completed: { label: '已完成', color: '#16A34A', dim: 'var(--green-dim)' },
  generating: { label: '生成中', color: '#2563EB', dim: 'var(--blue-dim)' },
  draft: { label: '草稿', color: '#EAB308', dim: 'var(--yellow-dim)' },
  failed: { label: '失败', color: '#DC2626', dim: 'var(--red-dim)' },
};

const Reports: React.FC = () => {
  const message = useAntdMessage();
  const [reports, setReports] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | undefined>(undefined);
  const [generateOpen, setGenerateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [reportPage, setReportPage] = useState(1);
  const REPORT_PAGE_SIZE = 12;
  const [exporting, setExporting] = useState(false);
  const [viewDrawerOpen, setViewDrawerOpen] = useState(false);
  const [selectedReport, setSelectedReport] = useState<Record<string, unknown> | null>(null);
  const [reportContent, setReportContent] = useState('');
  const [contentLoading, setContentLoading] = useState(false);
  const [generateForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const heroRef = useRef<HTMLDivElement>(null);
  const cardGridRef = useRef<HTMLDivElement>(null);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await reportsApi.list({ report_type: typeFilter });
      const d = res as unknown as Record<string, unknown>;
      setReports((d?.items || []) as Record<string, unknown>[]);
    } catch { setReports([]); } finally { setLoading(false); }
  };

  useEffect(() => { fetchReports(); }, [search, typeFilter]);

  useEffect(() => {
    if (heroRef.current) {
      gsap.fromTo(heroRef.current, { y: 16, opacity: 0 }, { y: 0, opacity: 1, duration: 0.5, ease: 'power2.out' });
    }
  }, []);

  useEffect(() => {
    if (cardGridRef.current) {
      const cards = cardGridRef.current.querySelectorAll('.report-card-item');
      gsap.fromTo(cards, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.04, ease: 'power2.out' });
    }
  }, [reports]);

  const getReportId = (r: Record<string, unknown>) => String(r.id || r.report_id);

  const stats = useMemo(() => {
    const total = reports.length;
    const completed = reports.filter(r => String(r.status).toLowerCase() === 'completed').length;
    const generating = reports.filter(r => String(r.status).toLowerCase() === 'generating').length;
    return { total, completed, generating };
  }, [reports]);

  const typeDist = useMemo(() => {
    const map: Record<string, number> = {};
    reports.forEach(r => { const t = String(r.type || 'other'); map[t] = (map[t] || 0) + 1; });
    return Object.entries(map).map(([name, value]) => ({
      name: REPORT_TYPES.find(t => t.value === name)?.label || name,
      value,
    }));
  }, [reports]);

  const handleGenerate = async () => {
    try {
      const values = await generateForm.validateFields();
      await reportsApi.generate(values);
      message.success('报告生成任务已创建');
      setGenerateOpen(false);
      generateForm.resetFields();
      fetchReports();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleView = async (report: Record<string, unknown>) => {
    const id = getReportId(report);
    setSelectedReport(report);
    setViewDrawerOpen(true);
    setContentLoading(true);
    try {
      const res = await reportsApi.get(id);
      const d = res as unknown as Record<string, unknown>;
      setReportContent(String(d.content || d.markdown || d.body || ''));
    } catch { setReportContent(''); } finally { setContentLoading(false); }
  };

  const handleOpenEdit = (report: Record<string, unknown>) => {
    setSelectedReport(report);
    editForm.setFieldsValue({
      title: report.title,
      type: report.type,
      summary: report.summary,
    });
    setEditOpen(true);
  };

  const handleEdit = async () => {
    if (!selectedReport) return;
    try {
      const values = await editForm.validateFields();
      const id = getReportId(selectedReport);
      await reportsApi.update(id, values);
      message.success('报告已更新');
      setEditOpen(false);
      editForm.resetFields();
      fetchReports();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleExport = async (report: Record<string, unknown>) => {
    setSelectedReport(report);
    setExportOpen(true);
  };

  const handleDoExport = async (format: string) => {
    if (!selectedReport || exporting) return;
    const id = getReportId(selectedReport);
    setExporting(true);
    try {
      const res = await reportsApi.export(id, format);
      const d = res as Record<string, unknown>;
      if (d.url) {
        window.open(String(d.url), '_blank');
      } else if (d.content) {
        const blob = new Blob([String(d.content)], { type: format === 'pdf' ? 'application/pdf' : 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${String(selectedReport.title || 'report')}.${format === 'pdf' ? 'pdf' : 'md'}`;
        a.click();
        URL.revokeObjectURL(url);
      }
      message.success(`已导出为 ${format.toUpperCase()}`);
      setExportOpen(false);
    } catch (err) { message.error(getErrorMessage(err)); }
    finally { setExporting(false); }
  };

  const handleDelete = async (id: string) => {
    try { await reportsApi.delete(id); message.success('报告已删除'); fetchReports(); } catch (err) { message.error(getErrorMessage(err)); }
  };

  const tooltipStyle: React.CSSProperties = { background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-0)', padding: '8px 12px' };

  const statCards = [
    { label: '报告总数', value: stats.total, color: '#1E40AF', icon: <FileTextOutlined /> },
    { label: '已完成', value: stats.completed, color: '#16A34A', icon: <CheckCircleOutlined /> },
    { label: '生成中', value: stats.generating, color: '#2563EB', icon: <SyncOutlined /> },
  ];

  return (
    <div style={{ padding: 0, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <style>{`
        .report-card-item {
          transition: all 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }
        .report-card-item:hover {
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
            报告中心
          </h1>
          <p style={{ fontSize: 14, color: '#6B7280', margin: '6px 0 0', fontFamily: 'var(--font-body)' }}>
            AI报告生成·多格式导出·DeepSeek驱动
          </p>
        </div>
        <Space size={8} style={{ position: 'relative', zIndex: 1 }}>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setGenerateOpen(true)}
            style={{ background: 'rgba(255,255,255,0.2)', border: '1px solid rgba(255,255,255,0.3)', color: '#1E3A5F', backdropFilter: 'blur(8px)', borderRadius: 8, fontWeight: 500 }}
          >
            生成报告
          </Button>
          <Tooltip title="刷新数据">
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchReports}
              style={{ background: 'rgba(255,255,255,0.15)', border: '1px solid rgba(255,255,255,0.25)', color: '#1E3A5F', backdropFilter: 'blur(8px)', borderRadius: 8 }}
            >
              刷新
            </Button>
          </Tooltip>
        </Space>
      </div>

      <div style={{ padding: '16px 32px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 16 }}>
          {statCards.map((card) => (
            <StatCard
              key={card.label}
              icon={card.icon}
              label={card.label}
              value={card.value}
              color={card.color}
            />
          ))}
        </div>
      </div>

      {typeDist.length > 0 && (
        <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, margin: '0 32px 16px' }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>类型分布</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={typeDist} layout="vertical" margin={{ top: 4, right: 20, left: 72, bottom: 4 }} barCategoryGap="20%" barGap={4}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" horizontal={false} vertical={false} />
              <XAxis type="number" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={68} />
              <RTooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
              <Bar dataKey="value" barSize={16} radius={[0, 6, 6, 0]} isAnimationActive={false} shape={<StaggeredBarShape layout="horizontal" radius={[0, 6, 6, 0]} />}>
                {typeDist.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div style={{ padding: '0 32px', marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Space size={8}>
          <Select placeholder="类型筛选" value={typeFilter} onChange={setTypeFilter} allowClear style={{ width: 140 }} options={REPORT_TYPES.map(t => ({ value: t.value, label: t.label }))} />
          <Input placeholder="搜索报告" value={search} onChange={(e) => setSearch(e.target.value)} allowClear style={{ width: 200 }} prefix={<SearchOutlined style={{ color: 'var(--text-3)' }} />} />
        </Space>
      </div>

      <div style={{ padding: '0 32px' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
        ) : reports.length === 0 ? (
          <div style={{ padding: '40px 0', textAlign: 'center' }}>
            <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无报告，点击「生成报告」创建第一份报告</span>}>
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setGenerateOpen(true)}>生成报告</Button>
            </Empty>
          </div>
        ) : (
          <>
          <div ref={cardGridRef} style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {reports.slice((reportPage - 1) * REPORT_PAGE_SIZE, reportPage * REPORT_PAGE_SIZE).map((report) => {
              const type = String(report.type || 'other');
              const typeColor = TYPE_COLORS[type] || '#64748B';
              const typeLabel = REPORT_TYPES.find(t => t.value === type)?.label || type;
              const statusKey = String(report.status || 'draft').toLowerCase();
              const statusCfg = STATUS_MAP[statusKey] || STATUS_MAP.draft;
              const id = getReportId(report);
              return (
                <div key={id} className="report-card-item" style={{ background: 'var(--bg-1)', borderRadius: 10, border: '1px solid var(--border)', display: 'flex', overflow: 'hidden' }}>
                  <div style={{ width: 4, background: typeColor, flexShrink: 0 }} />
                  <div style={{ flex: 1, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {String(report.title || '—')}
                      </div>
                      <Space size={4} style={{ flexShrink: 0 }}>
                        <Tag style={{ background: `${typeColor}15`, color: typeColor, border: 'none', fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>
                          {typeLabel}
                        </Tag>
                        <Tag style={{ background: statusCfg.dim, color: statusCfg.color, border: 'none', fontSize: 11, borderRadius: 20, padding: '0 8px', lineHeight: '20px' }}>
                          {statusCfg.label}
                        </Tag>
                      </Space>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 11 }}>
                        {report.created_at ? String(report.created_at).slice(0, 10) : '—'}
                      </span>
                      <Space size={2}>
                        <Tooltip title="查看"><Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handleView(report)} style={{ color: 'var(--primary)' }} /></Tooltip>
                        <Tooltip title="编辑"><Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleOpenEdit(report)} style={{ color: 'var(--primary)' }} /></Tooltip>
                        <Tooltip title="导出"><Button type="text" size="small" icon={<DownloadOutlined />} onClick={() => handleExport(report)} style={{ color: 'var(--primary)' }} /></Tooltip>
                        <Popconfirm title="确认删除？" onConfirm={() => handleDelete(id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
                          <Tooltip title="删除"><Button type="text" size="small" icon={<DeleteOutlined />} danger /></Tooltip>
                        </Popconfirm>
                      </Space>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          {reports.length > REPORT_PAGE_SIZE && (
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
              <Pagination current={reportPage} pageSize={REPORT_PAGE_SIZE} total={reports.length} onChange={setReportPage} size="small" showTotal={t => `共 ${t} 条`} />
            </div>
          )}
          </>
        )}
      </div>

      <Modal open={generateOpen} onCancel={() => { setGenerateOpen(false); generateForm.resetFields(); }} onOk={handleGenerate} width={600} okText="生成" cancelText="取消" title="生成报告">
        <Form form={generateForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="title" label="报告标题" rules={[{ required: true, message: '请输入标题' }]}><Input placeholder="例如: 2024年Q4威胁情报分析报告" /></Form.Item>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="type" label="报告类型" rules={[{ required: true, message: '请选择类型' }]}><Select options={REPORT_TYPES} placeholder="选择类型" /></Form.Item>
            <Form.Item name="format" label="输出格式"><Select options={[{ value: 'markdown', label: 'Markdown' }, { value: 'html', label: 'HTML' }, { value: 'pdf', label: 'PDF' }]} placeholder="选择格式" defaultValue="markdown" /></Form.Item>
          </div>
          <Form.Item name="summary" label="摘要说明"><Input.TextArea rows={3} placeholder="简要描述报告内容和目标" /></Form.Item>
          <Form.Item name="data_sources" label="数据来源"><Input.TextArea rows={2} placeholder="指定数据来源，如情报库、IoC数据等" /></Form.Item>
          <Form.Item name="template_id" label="模板ID"><Input placeholder="可选：指定提示词模板ID" /></Form.Item>
        </Form>
      </Modal>

      <Modal open={editOpen} onCancel={() => { setEditOpen(false); editForm.resetFields(); }} onOk={handleEdit} width={520} okText="保存" cancelText="取消" title="编辑报告">
        <Form form={editForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="title" label="报告标题" rules={[{ required: true, message: '请输入标题' }]}><Input placeholder="报告标题" /></Form.Item>
          <Form.Item name="type" label="报告类型"><Select options={REPORT_TYPES} placeholder="选择类型" /></Form.Item>
          <Form.Item name="summary" label="摘要"><Input.TextArea rows={4} placeholder="报告摘要" /></Form.Item>
        </Form>
      </Modal>

      <Modal open={exportOpen} onCancel={() => setExportOpen(false)} width={400} footer={null} title="导出报告">
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16 }}>
            选择导出格式:
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            {[
              { format: 'markdown', label: 'Markdown', color: 'var(--primary)' },
              { format: 'html', label: 'HTML', color: 'var(--orange)' },
              { format: 'pdf', label: 'PDF', color: 'var(--red)' },
            ].map((item) => (
              <div key={item.format} onClick={() => handleDoExport(item.format)} style={{ padding: 24, background: exporting ? 'var(--bg-3)' : 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', textAlign: 'center', cursor: exporting ? 'not-allowed' : 'pointer', transition: 'all 0.2s', opacity: exporting ? 0.6 : 1 }}>
                <DownloadOutlined style={{ fontSize: 24, color: item.color, marginBottom: 8 }} spin={exporting} />
                <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-0)' }}>{exporting ? '导出中...' : item.label}</div>
              </div>
            ))}
          </div>
        </div>
      </Modal>

      <Drawer
        open={viewDrawerOpen}
        onClose={() => { setViewDrawerOpen(false); setReportContent(''); }}
        width={680}
        title={selectedReport ? String(selectedReport.title || '报告详情') : '报告详情'}
      >
        {contentLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
        ) : reportContent ? (
          <div style={{ fontSize: 14, lineHeight: 1.8, color: 'var(--text-1)' }} className="markdown-body">
            <ReactMarkdown>{reportContent}</ReactMarkdown>
          </div>
        ) : (
          <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无报告内容</span>} />
        )}
      </Drawer>
    </div>
  );
};

export default Reports;
