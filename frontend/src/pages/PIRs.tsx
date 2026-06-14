import React, { useEffect, useState, useMemo } from 'react';
import { Table, Tag, Button, Space, Input, Select, Modal, Spin, Empty, Descriptions, Progress, Form, Tooltip, Popconfirm, Collapse, Card, Statistic } from 'antd';
import {
  PlusOutlined,
  DeleteOutlined,
  EyeOutlined,
  ExperimentOutlined,
  ReloadOutlined,
  RocketOutlined,
  EditOutlined,
  SearchOutlined,
  AlertOutlined,
  CheckCircleOutlined,
  SyncOutlined,
  DownloadOutlined,
} from '@ant-design/icons';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, Cell } from 'recharts';
import dayjs from 'dayjs';
import { pirsApi, getErrorMessage } from '../services/api';
import type { PIR, PIRTask } from '../types';
import { useAntdMessage } from '../utils/hooks';
import { StaggeredBarShape } from '../components/AnimatedChart';

const { TextArea } = Input;

const PRIORITY_CFG: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: '严重', color: 'var(--red)', bg: 'var(--red-dim)' },
  high: { label: '高', color: 'var(--orange)', bg: 'var(--orange-dim)' },
  medium: { label: '中', color: 'var(--yellow)', bg: 'var(--yellow-dim)' },
  low: { label: '低', color: 'var(--green)', bg: 'var(--green-dim)' },
};

const STATUS_CFG: Record<string, { label: string; color: string }> = {
  draft: { label: '草稿', color: 'default' },
  active: { label: '激活', color: 'processing' },
  executing: { label: '执行中', color: 'processing' },
  fulfilled: { label: '已完成', color: 'success' },
  archived: { label: '归档', color: 'default' },
};

const TASK_STATUS_CFG: Record<string, { label: string; color: string }> = {
  pending: { label: '待执行', color: 'default' },
  running: { label: '运行中', color: 'processing' },
  completed: { label: '完成', color: 'success' },
  failed: { label: '失败', color: 'error' },
};

const PIRs: React.FC = () => {
  const message = useAntdMessage();
  const [data, setData] = useState<PIR[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [priorityFilter, setPriorityFilter] = useState<string | undefined>();
  const [searchText, setSearchText] = useState('');

  const [createVisible, setCreateVisible] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [createForm] = Form.useForm();

  const [editVisible, setEditVisible] = useState(false);
  const [editLoading, setEditLoading] = useState(false);
  const [editForm] = Form.useForm();
  const [editingPir, setEditingPir] = useState<PIR | null>(null);

  const [detailVisible, setDetailVisible] = useState(false);
  const [detail, setDetail] = useState<PIR | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [tasksVisible, setTasksVisible] = useState(false);
  const [tasks, setTasks] = useState<PIRTask[]>([]);
  const [tasksLoading, setTasksLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await pirsApi.list({ offset: (page - 1) * 20, limit: 20, status: statusFilter, priority: priorityFilter });
      let items = res.items || [];
      if (searchText) {
        items = items.filter((p: PIR) =>
          p.title.toLowerCase().includes(searchText.toLowerCase()) ||
          p.description?.toLowerCase().includes(searchText.toLowerCase()) ||
          p.keywords?.some(k => k.toLowerCase().includes(searchText.toLowerCase()))
        );
      }
      setData(items);
      setTotal(searchText ? items.length : res.total);
    } catch {
      setData([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, [page, statusFilter, priorityFilter]);
  useEffect(() => { if (searchText === '') fetchData(); }, [searchText]);

  const handleCreate = async () => {
    try {
      const values = await createForm.validateFields();
      setCreateLoading(true);
      await pirsApi.create({
        title: values.title,
        description: values.description || undefined,
        priority: values.priority || 'medium',
        keywords: values.keywords ? values.keywords.split(/[,，\s]+/).filter(Boolean) : undefined,
        target_sources: values.target_sources ? values.target_sources.split(/[,，\s]+/).filter(Boolean) : undefined,
      });
      message.success('需求已创建');
      setCreateVisible(false);
      createForm.resetFields();
      fetchData();
    } catch (err) {
      if (err && typeof err === 'object' && 'errorFields' in (err as object)) return;
      message.error(`创建失败: ${getErrorMessage(err)}`);
    } finally {
      setCreateLoading(false);
    }
  };

  const handleEdit = async () => {
    if (!editingPir) return;
    try {
      const values = await editForm.validateFields();
      setEditLoading(true);
      await pirsApi.update(editingPir.id, {
        title: values.title, description: values.description, priority: values.priority,
        keywords: values.keywords ? values.keywords.split(/[,，\s]+/).filter(Boolean) : [],
        target_sources: values.target_sources ? values.target_sources.split(/[,，\s]+/).filter(Boolean) : [],
      });
      message.success('需求已更新');
      setEditVisible(false);
      setEditingPir(null);
      fetchData();
    } catch (err) {
      if (err && typeof err === 'object' && 'errorFields' in (err as object)) return;
      message.error(`更新失败: ${getErrorMessage(err)}`);
    } finally {
      setEditLoading(false);
    }
  };

  const handleViewDetail = async (id: string) => {
    setDetailVisible(true);
    setDetailLoading(true);
    try { const res = await pirsApi.get(id); setDetail(res); }
    catch (err) { message.error(`获取详情失败: ${getErrorMessage(err)}`); }
    finally { setDetailLoading(false); }
  };

  const handleDelete = async (id: string) => {
    try { await pirsApi.delete(id); message.success('已删除'); fetchData(); }
    catch (err) { message.error(`删除失败: ${getErrorMessage(err)}`); }
  };

  const handleExportPIRs = () => {
    if (data.length === 0) {
      message.warning('没有可导出的数据');
      return;
    }
    const headers = ['ID', '标题', '优先级', '状态', '完成度', '创建时间'];
    const rows = data.map((p: PIR) => [
      p.id,
      `"${(p.title || '').replace(/"/g, '""')}"`,
      PRIORITY_CFG[p.priority]?.label || p.priority || '',
      STATUS_CFG[p.status]?.label || p.status || '',
      `${Math.round((p.fulfillment_score || 0) * 100)}%`,
      p.created_at || '',
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map((r: string[]) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pirs_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    message.success(`已导出 ${data.length} 条需求`);
  };

  const handleDecompose = async (id: string) => {
    try { const res = await pirsApi.decompose(id); message.success(`已分解为 ${res.task_count} 个任务`); fetchData(); }
    catch (err) { message.error(`分解失败: ${getErrorMessage(err)}`); }
  };

  const handleExecute = async (id: string) => {
    try { await pirsApi.execute(id); message.success('执行已启动'); fetchData(); }
    catch (err) { message.error(`执行失败: ${getErrorMessage(err)}`); }
  };

  const handleShowTasks = async (pirId: string) => {
    setTasksVisible(true);
    setTasksLoading(true);
    try { const res = await pirsApi.listTasks(pirId); setTasks(res || []); }
    catch (err) { message.error(`获取任务失败: ${getErrorMessage(err)}`); }
    finally { setTasksLoading(false); }
  };

  const openEditModal = (pir: PIR) => {
    setEditingPir(pir);
    editForm.setFieldsValue({ title: pir.title, description: pir.description, priority: pir.priority, keywords: pir.keywords?.join(', ') || '', target_sources: pir.target_sources?.join(', ') || '' });
    setEditVisible(true);
  };

  const highPriorityCount = data.filter(d => d.priority === 'critical' || d.priority === 'high').length;
  const fulfilledCount = data.filter(d => d.status === 'fulfilled').length;
  const activeCount = data.filter(d => d.status === 'active' || d.status === 'executing').length;
  const totalCount = data.length;

  const pieData = useMemo(() => {
    const counts: Record<string, number> = {};
    data.forEach(d => { counts[d.priority] = (counts[d.priority] || 0) + 1; });
    return Object.entries(counts).map(([key, value]) => ({
      name: PRIORITY_CFG[key]?.label || key,
      value,
      key,
    }));
  }, [data]);

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>优先情报需求</h1>
          <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>管理情报收集优先级，分解执行情报采集任务</p>
        </div>
        <Space size={8}>
          <Button icon={<DownloadOutlined />} onClick={handleExportPIRs} disabled={data.length === 0}>导出CSV</Button>
          <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateVisible(true)}>创建PIR</Button>
        </Space>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>总需求</span>} value={totalCount} valueStyle={{ color: 'var(--text-0)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>高优先级</span>} value={highPriorityCount} valueStyle={{ color: 'var(--red)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<AlertOutlined />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>执行中</span>} value={activeCount} valueStyle={{ color: 'var(--blue)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<SyncOutlined spin={activeCount > 0} />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>已完成</span>} value={fulfilledCount} valueStyle={{ color: 'var(--green)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<CheckCircleOutlined />} />
        </Card>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16, marginBottom: 24 }}>
        <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>优先级分布</div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={pieData} layout="vertical" margin={{ top: 4, right: 20, left: 60, bottom: 4 }} barCategoryGap="20%" barGap={4}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.04)" horizontal={false} vertical={false} />
                <XAxis type="number" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={56} />
                <RTooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
                <Bar dataKey="value" barSize={16} radius={[0, 6, 6, 0]} isAnimationActive={false} shape={<StaggeredBarShape layout="horizontal" radius={[0, 6, 6, 0]} />}>
                  {pieData.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>暂无数据</span>} />
          )}
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 4 }}>筛选</div>
          <div>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>状态</label>
            <Select placeholder="全部状态" value={statusFilter} onChange={setStatusFilter} allowClear style={{ width: '100%' }} options={Object.entries(STATUS_CFG).map(([k, val]) => ({ label: val.label, value: k }))} />
          </div>
          <div>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>优先级</label>
            <Select placeholder="全部优先级" value={priorityFilter} onChange={setPriorityFilter} allowClear style={{ width: '100%' }} options={Object.entries(PRIORITY_CFG).map(([k, val]) => ({ label: val.label, value: k }))} />
          </div>
          <div>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>搜索</label>
            <Input placeholder="搜索标题、描述、关键词" prefix={<SearchOutlined style={{ color: 'var(--text-3)', fontSize: 12 }} />} value={searchText} onChange={e => setSearchText(e.target.value)} onPressEnter={fetchData} allowClear onClear={fetchData} />
          </div>
          <div style={{ marginTop: 'auto', fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>共 {total} 条</div>
        </div>
      </div>

      <Collapse
        defaultActiveKey={['pirTable']}
        items={[{
          key: 'pirTable',
          label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>PIR 列表</span>,
          children: (
            <Table
              dataSource={data}
              rowKey="id"
              size="middle"
              loading={loading}
              locale={{ emptyText: <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无需求，点击"创建PIR"添加第一个需求</span>} /> }}
              pagination={{ current: page, total, pageSize: 20, onChange: setPage, showTotal: t => `共 ${t} 条`, showSizeChanger: false }}
              columns={[
                { title: '标题', dataIndex: 'title', ellipsis: true, render: (val: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500, fontSize: 13 }}>{val}</span> },
                { title: '优先级', dataIndex: 'priority', width: 80, render: (val: string) => { const c = PRIORITY_CFG[val]; if (!c) return <Tag>{val}</Tag>; return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 10px', borderRadius: 9999, background: c.bg, color: c.color, fontSize: 11, fontWeight: 500 }}>{c.label}</span>; } },
                { title: '状态', dataIndex: 'status', width: 80, render: (val: string) => { const c = STATUS_CFG[val]; return c ? <Tag color={c.color} style={{ margin: 0, borderRadius: 9999, fontWeight: 500 }}>{c.label}</Tag> : <Tag style={{ margin: 0 }}>{val}</Tag>; } },
                { title: '关键词', dataIndex: 'keywords', width: 150, render: (val: string[]) => val?.length ? <Space size={2} wrap>{val.slice(0, 3).map(k => <Tag key={k} style={{ fontSize: 10, margin: 0, borderRadius: 9999, background: 'var(--primary-dim)', color: 'var(--primary)', border: 'none' }}>{k}</Tag>)}{val.length > 3 && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>+{val.length - 3}</span>}</Space> : <span style={{ color: 'var(--text-3)' }}>—</span> },
                { title: '完成度', dataIndex: 'fulfillment_score', width: 120, render: (val: number) => { const pct = Math.round((val || 0) * 100); const color = pct >= 70 ? 'var(--green)' : pct >= 40 ? 'var(--yellow)' : 'var(--red)'; return <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Progress percent={pct} size="small" showInfo={false} strokeColor={color} style={{ width: 60, marginBottom: 0 }} /><span style={{ fontSize: 11, fontWeight: 600, color, fontFamily: 'var(--font-mono)' }}>{pct}%</span></div>; } },
                { title: '创建时间', dataIndex: 'created_at', width: 110, render: (val: string) => <span style={{ color: 'var(--text-3)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>{val ? dayjs(val).format('MM-DD HH:mm') : '—'}</span> },
                { title: '', width: 160, render: (_: unknown, r: PIR) => <Space size={2}>
                  <Tooltip title="查看"><Button type="text" size="small" icon={<EyeOutlined style={{ color: 'var(--text-2)', fontSize: 13 }} />} onClick={() => handleViewDetail(r.id)} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip>
                  <Tooltip title="分解为子任务"><Button type="text" size="small" icon={<ExperimentOutlined style={{ color: 'var(--text-2)', fontSize: 13 }} />} onClick={() => handleDecompose(r.id)} disabled={r.status === 'fulfilled' || r.status === 'archived'} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip>
                  <Tooltip title="执行需求"><Button type="text" size="small" icon={<RocketOutlined style={{ color: 'var(--text-2)', fontSize: 13 }} />} onClick={() => handleExecute(r.id)} disabled={r.status === 'fulfilled' || r.status === 'archived'} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip>
                  <Tooltip title="子任务"><Button type="text" size="small" icon={<EyeOutlined style={{ color: 'var(--text-2)', fontSize: 13 }} />} onClick={() => handleShowTasks(r.id)} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip>
                  <Tooltip title="编辑"><Button type="text" size="small" icon={<EditOutlined style={{ color: 'var(--text-2)', fontSize: 13 }} />} onClick={() => openEditModal(r)} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip>
                  <Popconfirm title="确认删除？" onConfirm={() => handleDelete(r.id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}><Tooltip title="删除"><Button type="text" size="small" danger icon={<DeleteOutlined />} style={{ borderRadius: 'var(--radius)', width: 28, height: 28 }} /></Tooltip></Popconfirm>
                </Space> },
              ]}
            />
          ),
        }]}
      />

      <Modal title="新增需求" open={createVisible} onCancel={() => setCreateVisible(false)} onOk={handleCreate} confirmLoading={createLoading} width={560} okText="创建">
        <Form form={createForm} layout="vertical" initialValues={{ title: '', description: '', priority: 'medium', keywords: '', target_sources: '' }} style={{ marginTop: 16 }}>
          <Form.Item name="title" label="标题" rules={[{ required: true, message: '请输入标题' }]} extra="需求的简短描述"><Input placeholder="例如：追踪某黑产团伙最新活动" /></Form.Item>
          <Form.Item name="description" label="描述" extra="详细说明需求背景和目标"><TextArea rows={3} placeholder="描述需求的详细内容" /></Form.Item>
          <div style={{ display: 'flex', gap: 16 }}>
            <Form.Item name="priority" label="优先级" style={{ flex: 1 }} extra="决定执行顺序"><Select style={{ width: '100%' }} options={Object.entries(PRIORITY_CFG).map(([k, val]) => ({ label: val.label, value: k }))} /></Form.Item>
            <Form.Item name="keywords" label="关键词" style={{ flex: 1 }} extra="逗号分隔"><Input placeholder="关键词1, 关键词2" /></Form.Item>
          </div>
          <Form.Item name="target_sources" label="目标来源" extra="指定情报采集的数据源，逗号分隔"><Input placeholder="source1, source2" /></Form.Item>
        </Form>
      </Modal>

      <Modal title="编辑需求" open={editVisible} onCancel={() => { setEditVisible(false); setEditingPir(null); }} onOk={handleEdit} confirmLoading={editLoading} width={560} okText="保存">
        <Form form={editForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="title" label="标题" rules={[{ required: true, message: '请输入标题' }]}><Input placeholder="需求标题" /></Form.Item>
          <Form.Item name="description" label="描述"><TextArea rows={3} placeholder="需求描述" /></Form.Item>
          <div style={{ display: 'flex', gap: 16 }}>
            <Form.Item name="priority" label="优先级" style={{ flex: 1 }}><Select style={{ width: '100%' }} options={Object.entries(PRIORITY_CFG).map(([k, val]) => ({ label: val.label, value: k }))} /></Form.Item>
            <Form.Item name="keywords" label="关键词" style={{ flex: 1 }}><Input placeholder="逗号分隔" /></Form.Item>
          </div>
          <Form.Item name="target_sources" label="目标来源"><Input placeholder="逗号分隔" /></Form.Item>
        </Form>
      </Modal>

      <Modal title="需求详情" open={detailVisible} onCancel={() => setDetailVisible(false)} footer={null} width={640}>
        {detailLoading ? <Spin style={{ display: 'block', margin: '24px auto' }} /> : detail ? (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="ID"><span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-2)' }}>{detail.id}</span></Descriptions.Item>
            <Descriptions.Item label="标题">{detail.title}</Descriptions.Item>
            <Descriptions.Item label="描述">{detail.description || '—'}</Descriptions.Item>
            <Descriptions.Item label="优先级">{(() => { const c = PRIORITY_CFG[detail.priority]; return c ? <span style={{ color: c.color, fontWeight: 500 }}>{c.label}</span> : detail.priority; })()}</Descriptions.Item>
            <Descriptions.Item label="状态">{(() => { const c = STATUS_CFG[detail.status]; return c ? <Tag color={c.color} style={{ borderRadius: 9999 }}>{c.label}</Tag> : detail.status; })()}</Descriptions.Item>
            <Descriptions.Item label="完成度"><span style={{ color: detail.fulfillment_score >= 0.7 ? 'var(--green)' : detail.fulfillment_score >= 0.4 ? 'var(--yellow)' : 'var(--red)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{Math.round((detail.fulfillment_score || 0) * 100)}%</span></Descriptions.Item>
            <Descriptions.Item label="关键词">{detail.keywords?.join(', ') || '—'}</Descriptions.Item>
            <Descriptions.Item label="目标来源">{detail.target_sources?.join(', ') || '—'}</Descriptions.Item>
            {detail.results_summary && <Descriptions.Item label="结果摘要">{detail.results_summary}</Descriptions.Item>}
          </Descriptions>
        ) : <Empty />}
      </Modal>

      <Modal title="子任务" open={tasksVisible} onCancel={() => setTasksVisible(false)} footer={null} width={640}>
        {tasksLoading ? <Spin style={{ display: 'block', margin: '24px auto' }} /> : (
          <Table dataSource={tasks} rowKey="id" size="small" pagination={false} locale={{ emptyText: <Empty description="暂无任务" /> }}
            columns={[
              { title: 'Agent', dataIndex: 'agent_type', width: 100, render: (val: string) => <span style={{ fontWeight: 500, color: 'var(--text-0)' }}>{val}</span> },
              { title: '描述', dataIndex: 'task_description', ellipsis: true, render: (val: string) => <span style={{ color: 'var(--text-2)' }}>{val || '—'}</span> },
              { title: '状态', dataIndex: 'status', width: 80, render: (val: string) => { const c = TASK_STATUS_CFG[val]; return <Tag color={c?.color || 'default'} style={{ margin: 0, borderRadius: 9999, fontWeight: 500 }}>{c?.label || val}</Tag>; } },
              { title: '结果', dataIndex: 'result', width: 80, render: (val: unknown) => val ? <Button type="text" size="small" style={{ fontSize: 11, color: 'var(--primary)' }} onClick={() => Modal.info({ title: '任务结果', content: <pre style={{ whiteSpace: 'pre-wrap', fontSize: 11, maxHeight: 300, overflow: 'auto', color: 'var(--text-1)' }}>{JSON.stringify(val, null, 2)}</pre>, width: 520 })}>查看</Button> : <span style={{ color: 'var(--text-3)' }}>—</span> },
            ]}
          />
        )}
      </Modal>
    </div>
  );
};

export default PIRs;
