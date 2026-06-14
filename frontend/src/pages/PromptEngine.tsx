import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Table, Button, Modal, Form, Input, Select, Tag, Space, Spin,
  Tooltip, Popconfirm, Slider, Collapse, Empty, Statistic,
} from 'antd';
import {
  PlusOutlined, EditOutlined, PlayCircleOutlined,
  BranchesOutlined, ExperimentOutlined, DeleteOutlined, SearchOutlined,
  ThunderboltOutlined, AppstoreOutlined, CodeOutlined,
} from '@ant-design/icons';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import { StaggeredBarShape } from '../components/AnimatedChart';

const CATEGORIES = [
  { value: 'analysis', label: '分析类' },
  { value: 'generation', label: '生成类' },
  { value: 'extraction', label: '提取类' },
  { value: 'translation', label: '翻译类' },
  { value: 'classification', label: '分类类' },
];

const CATEGORY_COLORS: Record<string, string> = {
  analysis: '#2563EB',
  generation: '#16A34A',
  extraction: '#7C3AED',
  translation: '#0D9488',
  classification: '#EA580C',
};


const PromptEngine: React.FC = () => {
  const message = useAntdMessage();
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [renderModalOpen, setRenderModalOpen] = useState(false);
  const [versionModalOpen, setVersionModalOpen] = useState(false);
  const [abTestModalOpen, setAbTestModalOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<Record<string, unknown> | null>(null);
  const [versions, setVersions] = useState<Record<string, unknown>[]>([]);
  const [renderResult, setRenderResult] = useState('');
  const [renderVars, setRenderVars] = useState<Record<string, string>>({});
  const [renderLoading, setRenderLoading] = useState(false);
  const [abVersionA, setAbVersionA] = useState<number | undefined>(undefined);
  const [abVersionB, setAbVersionB] = useState<number | undefined>(undefined);
  const [abTrafficSplit, setAbTrafficSplit] = useState(50);
  const [abRunning, setAbRunning] = useState(false);
  const [abResult, setAbResult] = useState<Record<string, unknown> | null>(null);
  const [createVersionLoading, setCreateVersionLoading] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const res = await api.promptEngine.list({ search: search || undefined });
      const d = res as Record<string, unknown>;
      setTemplates((d?.items || d?.data || []) as Record<string, unknown>[]);
    } catch {
      setTemplates([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTemplates(); }, [search]);

  const extractVariables = (content: string): string[] => {
    const matches = content.match(/\{\{(\w+)\}\}/g);
    if (!matches) return [];
    return [...new Set(matches.map((m) => m.replace(/\{\{|\}\}/g, '')))];
  };

  const getTemplateId = (tpl: Record<string, unknown>) => String(tpl.id || tpl.template_id);

  const stats = useMemo(() => {
    const total = templates.length;
    const active = templates.filter(t => {
      const s = String(t.status);
      return s === 'ACTIVE' || s === 'active';
    }).length;
    const totalVars = templates.reduce((acc, t) => {
      const content = String(t.user_prompt_template || t.content || t.template_content || '');
      return acc + extractVariables(content).length;
    }, 0);
    const avgVars = total > 0 ? (totalVars / total).toFixed(1) : '0';
    return { total, active, avgVars };
  }, [templates]);

  const categoryDist = useMemo(() => {
    const map: Record<string, number> = {};
    templates.forEach(t => {
      const cat = String(t.category || 'other');
      map[cat] = (map[cat] || 0) + 1;
    });
    return Object.entries(map).map(([name, value]) => ({
      name: CATEGORIES.find(c => c.value === name)?.label || name,
      value,
    }));
  }, [templates]);

  const handleCreate = async () => {
    try {
      const values = await createForm.validateFields();
      await api.promptEngine.create(values);
      message.success('模板创建成功');
      setCreateModalOpen(false);
      createForm.resetFields();
      fetchTemplates();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleEdit = async () => {
    if (!selectedTemplate) return;
    try {
      const values = await editForm.validateFields();
      const id = getTemplateId(selectedTemplate);
      await api.promptEngine.update(id, values);
      message.success('模板更新成功');
      setEditModalOpen(false);
      editForm.resetFields();
      fetchTemplates();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleOpenEdit = (tpl: Record<string, unknown>) => {
    setSelectedTemplate(tpl);
    editForm.setFieldsValue({
      name: tpl.name || tpl.template_name,
      content: tpl.user_prompt_template || tpl.content || tpl.template_content,
      category: tpl.category,
      variables_json: tpl.variables_json || JSON.stringify(extractVariables(String(tpl.user_prompt_template || tpl.content || tpl.template_content || ''))),
      tags_json: tpl.tags_json || '[]',
    });
    setEditModalOpen(true);
  };

  const handleOpenRender = (tpl: Record<string, unknown>) => {
    setSelectedTemplate(tpl);
    setRenderResult('');
    const content = String(tpl.user_prompt_template || tpl.content || tpl.template_content || '');
    const vars = extractVariables(content);
    const initialVars: Record<string, string> = {};
    vars.forEach((v) => { initialVars[v] = ''; });
    setRenderVars(initialVars);
    setRenderModalOpen(true);
  };

  const handleRender = async () => {
    if (!selectedTemplate) return;
    setRenderLoading(true);
    try {
      const id = getTemplateId(selectedTemplate);
      const res = await api.promptEngine.render(id, renderVars);
      const d = res as Record<string, unknown>;
      setRenderResult(String(d?.rendered || d?.result || d?.content || ''));
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setRenderLoading(false);
    }
  };

  const handleOpenVersions = async (tpl: Record<string, unknown>) => {
    setSelectedTemplate(tpl);
    setVersionModalOpen(true);
    try {
      const id = getTemplateId(tpl);
      const vRes = await api.promptEngine.getVersions(id);
      const vd = vRes as Record<string, unknown>;
      setVersions((vd?.items || vd?.versions || []) as Record<string, unknown>[]);
    } catch {
      setVersions([]);
    }
  };

  const handleCreateVersion = async () => {
    if (!selectedTemplate) return;
    setCreateVersionLoading(true);
    try {
      const id = getTemplateId(selectedTemplate);
      await api.promptEngine.createVersion(id);
      message.success('新版本已创建');
      const vRes = await api.promptEngine.getVersions(id);
      const vd = vRes as Record<string, unknown>;
      setVersions((vd?.items || vd?.versions || []) as Record<string, unknown>[]);
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setCreateVersionLoading(false);
    }
  };

  const handleOpenABTest = async (tpl: Record<string, unknown>) => {
    setSelectedTemplate(tpl);
    setAbVersionA(undefined);
    setAbVersionB(undefined);
    setAbTrafficSplit(50);
    setAbRunning(false);
    setAbResult(null);
    setAbTestModalOpen(true);
    try {
      const id = getTemplateId(tpl);
      const vRes = await api.promptEngine.getVersions(id);
      const vd = vRes as Record<string, unknown>;
      setVersions((vd?.items || vd?.versions || []) as Record<string, unknown>[]);
    } catch {
      setVersions([]);
    }
  };

  const handleRunABTest = async () => {
    if (!selectedTemplate || !abVersionA || !abVersionB) {
      message.warning('请选择版本A和版本B');
      return;
    }
    setAbRunning(true);
    setAbResult(null);
    try {
      const id = getTemplateId(selectedTemplate);
      const res = await api.promptEngine.createABTest({
        template_id: id,
        version_a: abVersionA,
        version_b: abVersionB,
        traffic_split: abTrafficSplit / 100,
      });
      setAbResult(res as Record<string, unknown>);
      message.success('A/B测试已启动');
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setAbRunning(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.promptEngine.delete(id);
      message.success('模板已删除');
      fetchTemplates();
    } catch (err) {
      message.error(getErrorMessage(err));
    }
  };

  const getCategoryLabel = useCallback((v: string) => CATEGORIES.find((c) => c.value === v)?.label || v, []);

  const versionOptions = useMemo(
    () => versions.map((v, i) => ({
      value: Number(v.version) || i + 1,
      label: `v${Number(v.version) || i + 1} — ${String(v.created_at || v.updated_at || '').slice(0, 10)}`,
    })),
    [versions]
  );

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: Record<string, unknown>) => (
        <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>
          {String(record.name || record.template_name || text)}
        </span>
      ),
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      width: 100,
      render: (category: string) => (
        <Tag
          style={{
            background: CATEGORY_COLORS[category] ? `${CATEGORY_COLORS[category]}15` : 'var(--bg-3)',
            color: CATEGORY_COLORS[category] || 'var(--text-2)',
            border: 'none',
          }}
        >
          {getCategoryLabel(category)}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status: string) => {
        const isActive = status === 'ACTIVE' || status === 'active';
        return (
          <Tag
            style={{
              background: isActive ? 'var(--green-dim)' : 'var(--yellow-dim)',
              color: isActive ? 'var(--green)' : 'var(--yellow)',
              border: 'none',
            }}
          >
            {isActive ? '活跃' : '草稿'}
          </Tag>
        );
      },
    },
    {
      title: '变量数',
      key: 'variables',
      width: 72,
      render: (_: unknown, record: Record<string, unknown>) => {
        const content = String(record.user_prompt_template || record.content || record.template_content || '');
        return (
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--primary-light)', fontSize: 14, fontWeight: 600 }}>
            {extractVariables(content).length}
          </span>
        );
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 140,
      render: (text: string) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>
          {text ? String(text).slice(0, 10) : '--'}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      render: (_: unknown, record: Record<string, unknown>) => {
        const id = getTemplateId(record);
        return (
          <Space size={2}>
            <Tooltip title="编辑">
              <Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleOpenEdit(record)} />
            </Tooltip>
            <Tooltip title="渲染">
              <Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleOpenRender(record)} />
            </Tooltip>
            <Tooltip title="版本">
              <Button type="text" size="small" icon={<BranchesOutlined />} onClick={() => handleOpenVersions(record)} />
            </Tooltip>
            <Tooltip title="A/B测试">
              <Button type="text" size="small" icon={<ExperimentOutlined />} onClick={() => handleOpenABTest(record)} />
            </Tooltip>
            <Popconfirm title="确认删除此模板？" onConfirm={() => handleDelete(id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
              <Tooltip title="删除">
                <Button type="text" size="small" icon={<DeleteOutlined />} danger />
              </Tooltip>
            </Popconfirm>
          </Space>
        );
      },
    },
  ];

  const tooltipStyle: React.CSSProperties = {
    background: 'var(--bg-2)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    fontSize: 12,
    color: 'var(--text-0)',
    padding: '8px 12px',
  };

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>
          提示词工程
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>
          设计、管理和优化AI提示词模板，支持变量注入和版本管理
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <AppstoreOutlined style={{ fontSize: 16, color: 'var(--primary)' }} />
            <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>模板总数</span>
          </div>
          <Statistic value={stats.total} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--text-0)', fontWeight: 700 }} />
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <ThunderboltOutlined style={{ fontSize: 16, color: 'var(--green)' }} />
            <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>活跃模板</span>
          </div>
          <Statistic value={stats.active} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: 700 }} />
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <CodeOutlined style={{ fontSize: 16, color: 'var(--purple)' }} />
            <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>平均变量数</span>
          </div>
          <Statistic value={stats.avgVars} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)', fontWeight: 700 }} />
        </div>
      </div>

      {categoryDist.length > 0 && (
        <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>分类分布</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={categoryDist} layout="vertical" margin={{ top: 4, right: 20, left: 60, bottom: 4 }} barCategoryGap="20%" barGap={4}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" horizontal={false} vertical={false} />
              <XAxis type="number" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#7C7F9A', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={56} />
              <RTooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="value" barSize={16} radius={[0, 6, 6, 0]} isAnimationActive={false} shape={<StaggeredBarShape layout="horizontal" radius={[0, 6, 6, 0]} />}>
                {categoryDist.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Input
          placeholder="搜索模板"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
          allowClear
          prefix={<SearchOutlined style={{ color: 'var(--text-3)' }} />}
        />
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>
          创建模板
        </Button>
      </div>

      <Collapse
        defaultActiveKey={['templates']}
        items={[{
          key: 'templates',
          label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>模板列表</span>,
          children: loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
          ) : templates.length === 0 ? (
            <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无模板，点击「创建模板」开始设计提示词</span>}>
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>创建模板</Button>
            </Empty>
          ) : (
            <Table
              dataSource={templates}
              columns={columns}
              rowKey={(record) => getTemplateId(record)}
              pagination={{ pageSize: 10, showSizeChanger: false }}
              locale={{ emptyText: '暂无模板，点击新建创建第一个模板' }}
            />
          ),
        }]}
      />

      <Modal title="新建提示词模板" open={createModalOpen} onOk={handleCreate} onCancel={() => { setCreateModalOpen(false); createForm.resetFields(); }} width={640} okText="创建">
        <Form form={createForm} layout="vertical" style={{ marginTop: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入模板名称' }]}>
              <Input placeholder="输入模板名称" />
            </Form.Item>
            <Form.Item name="category" label="分类" rules={[{ required: true, message: '请选择分类' }]}>
              <Select options={CATEGORIES} placeholder="选择分类" />
            </Form.Item>
          </div>
          <Form.Item name="content" label="模板内容" rules={[{ required: true, message: '请输入模板内容' }]}
            extra={<span style={{ fontSize: 11, color: 'var(--text-3)' }}>使用 {'{{variable}}'} 语法定义变量</span>}>
            <Input.TextArea rows={8} placeholder="使用 {{variable}} 语法定义变量" style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }} />
          </Form.Item>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="variables_json" label="变量定义 (JSON)">
              <Input.TextArea rows={3} placeholder='["var1", "var2"]' style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
            </Form.Item>
            <Form.Item name="tags_json" label="标签 (JSON)">
              <Input.TextArea rows={3} placeholder='["tag1", "tag2"]' style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
            </Form.Item>
          </div>
        </Form>
      </Modal>

      <Modal title="编辑模板" open={editModalOpen} onOk={handleEdit} onCancel={() => { setEditModalOpen(false); editForm.resetFields(); }} width={640} okText="保存">
        <Form form={editForm} layout="vertical" style={{ marginTop: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入模板名称' }]}>
              <Input placeholder="输入模板名称" />
            </Form.Item>
            <Form.Item name="category" label="分类">
              <Select options={CATEGORIES} placeholder="选择分类" />
            </Form.Item>
          </div>
          <Form.Item name="content" label="模板内容" rules={[{ required: true, message: '请输入模板内容' }]}>
            <Input.TextArea rows={8} style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }} />
          </Form.Item>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="variables_json" label="变量定义 (JSON)">
              <Input.TextArea rows={3} style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
            </Form.Item>
            <Form.Item name="tags_json" label="标签 (JSON)">
              <Input.TextArea rows={3} style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
            </Form.Item>
          </div>
        </Form>
      </Modal>

      <Modal title="模板渲染" open={renderModalOpen} onCancel={() => { setRenderModalOpen(false); setRenderResult(''); setRenderVars({}); }} width={640} footer={null}>
        {selectedTemplate && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>原始模板</div>
            <div style={{ background: 'var(--bg-0)', borderRadius: 'var(--radius)', padding: 16, fontFamily: 'var(--font-mono)', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap', color: 'var(--text-1)', maxHeight: 200, overflowY: 'auto', border: '1px solid var(--border)' }}>
              {String(selectedTemplate.user_prompt_template || selectedTemplate.content || selectedTemplate.template_content || '')}
            </div>
            {Object.keys(renderVars).length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>变量注入</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {Object.keys(renderVars).map((v) => (
                    <div key={v}>
                      <div style={{ marginBottom: 4 }}><Tag style={{ fontFamily: 'var(--font-mono)' }}>{`{{${v}}}`}</Tag></div>
                      <Input size="small" placeholder={`输入 ${v}`} value={renderVars[v]} onChange={(e) => setRenderVars((prev) => ({ ...prev, [v]: e.target.value }))} />
                    </div>
                  ))}
                </div>
              </div>
            )}
            <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleRender} loading={renderLoading} block style={{ marginTop: 16 }}>渲染预览</Button>
            {renderResult && (
              <div style={{ marginTop: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', padding: 16, border: '1px solid var(--border)', fontSize: 13, lineHeight: 1.8, whiteSpace: 'pre-wrap', color: 'var(--text-0)', maxHeight: 200, overflowY: 'auto' }}>
                {renderResult}
              </div>
            )}
          </div>
        )}
      </Modal>

      <Modal title="版本管理" open={versionModalOpen} onCancel={() => setVersionModalOpen(false)} width={560}
        footer={<Button type="primary" icon={<PlusOutlined />} onClick={handleCreateVersion} loading={createVersionLoading}>创建新版本</Button>}>
        {selectedTemplate && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-0)', marginBottom: 16 }}>
              {String(selectedTemplate.name || selectedTemplate.template_name || '')}
            </div>
            {versions.length === 0 ? (
              <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>暂无版本记录，点击「创建新版本」开始</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {versions.map((v, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', background: i === 0 ? 'var(--primary-dim)' : 'var(--bg-1)', borderRadius: 'var(--radius)', border: `1px solid ${i === 0 ? 'var(--primary)' : 'var(--border)'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Tag style={{ background: i === 0 ? 'var(--primary-dim)' : 'var(--bg-3)', color: i === 0 ? 'var(--primary)' : 'var(--text-2)', border: 'none' }}>{`v${String(v.version || i + 1)}`}</Tag>
                      {i === 0 && <Tag style={{ background: 'var(--green-dim)', color: 'var(--green)', border: 'none' }}>当前</Tag>}
                    </div>
                    <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>{String(v.created_at || v.updated_at || '').slice(0, 10)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Modal>

      <Modal title="A/B 测试" open={abTestModalOpen} onCancel={() => setAbTestModalOpen(false)} width={600} footer={null}>
        <div style={{ marginTop: 16 }}>
          {selectedTemplate && (
            <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 20 }}>
              模板: <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{String(selectedTemplate.name || selectedTemplate.template_name || '')}</span>
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
            <div style={{ padding: 16, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>版本 A — 对照组</div>
              <Select style={{ width: '100%' }} placeholder="选择版本A" value={abVersionA} onChange={setAbVersionA} options={versionOptions} />
            </div>
            <div style={{ padding: 16, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>版本 B — 实验组</div>
              <Select style={{ width: '100%' }} placeholder="选择版本B" value={abVersionB} onChange={setAbVersionB} options={versionOptions} />
            </div>
          </div>
          <div style={{ padding: 16, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>流量分配</span>
              <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--text-1)' }}>A: {100 - abTrafficSplit}% / B: {abTrafficSplit}%</span>
            </div>
            <Slider min={10} max={90} value={abTrafficSplit} onChange={setAbTrafficSplit} />
          </div>
          <Button type="primary" icon={<ExperimentOutlined />} onClick={handleRunABTest} loading={abRunning} block disabled={!abVersionA || !abVersionB}>运行 A/B 测试</Button>
          {abResult && (
            <div style={{ marginTop: 20 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ padding: 20, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', textAlign: 'center' }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>版本 A</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color: 'var(--text-0)', fontWeight: 500 }}>{String(abResult.score_a ?? abResult.metric_a ?? '—')}</div>
                </div>
                <div style={{ padding: 20, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', textAlign: 'center' }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>版本 B</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color: 'var(--text-0)', fontWeight: 500 }}>{String(abResult.score_b ?? abResult.metric_b ?? '—')}</div>
                </div>
              </div>
              {String(abResult.winner || '') !== '' && (
                <div style={{ marginTop: 12, padding: 12, borderRadius: 'var(--radius)', textAlign: 'center', background: 'var(--green-dim)', border: '1px solid var(--border)' }}>
                  <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--green)' }}>胜出: {String(abResult.winner).toUpperCase()}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default PromptEngine;
