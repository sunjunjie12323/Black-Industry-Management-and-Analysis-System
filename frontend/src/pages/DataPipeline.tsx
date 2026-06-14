import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Table, Button, Modal, Form, Input, Select, Tag, Space, Spin,
  Tooltip, Popconfirm, Collapse, Empty,
} from 'antd';
import {
  PlusOutlined, PlayCircleOutlined, EyeOutlined,
  DeleteOutlined, PartitionOutlined, RightOutlined,
  DatabaseOutlined, SyncOutlined, CheckCircleOutlined, CloseCircleOutlined,
} from '@ant-design/icons';
import { BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, ResponsiveContainer, Cell } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';
import { StaggeredBarShape } from '../components/AnimatedChart';

const TASK_TYPES = [
  { value: 'import', label: '导入' },
  { value: 'clean', label: '清洗' },
  { value: 'label', label: '标注' },
  { value: 'augment', label: '增强' },
  { value: 'convert', label: '格式转换' },
  { value: 'filter', label: '过滤' },
  { value: 'merge', label: '合并' },
  { value: 'sample', label: '采样' },
];

const TYPE_COLORS: Record<string, string> = {
  import: '#2563EB',
  clean: '#0D9488',
  label: '#7C3AED',
  augment: '#16A34A',
  convert: '#EA580C',
  filter: '#EAB308',
  merge: '#1E40AF',
  sample: '#DC2626',
};

const STATUS_MAP: Record<string, { label: string; color: string; dim: string }> = {
  PENDING: { label: '待执行', color: '#EAB308', dim: 'var(--yellow-dim)' },
  RUNNING: { label: '运行中', color: '#2563EB', dim: 'var(--blue-dim)' },
  COMPLETED: { label: '已完成', color: '#16A34A', dim: 'var(--green-dim)' },
  FAILED: { label: '失败', color: '#DC2626', dim: 'var(--red-dim)' },
  CANCELLED: { label: '已取消', color: 'var(--text-3)', dim: 'var(--bg-3)' },
};

const CountUpNumber: React.FC<{ value: number; style?: React.CSSProperties }> = ({ value, style }) => {
  const counterRef = useRef({ val: 0 });
  const [display, setDisplay] = useState(0);
  const hasAnimated = useRef(false);

  useEffect(() => {
    if (!hasAnimated.current) {
      hasAnimated.current = true;
      counterRef.current.val = 0;
      setDisplay(0);
      const tween = gsap.to(counterRef.current, {
        val: value,
        duration: ANIM_CONFIG.statCard.counterDuration,
        ease: 'power2.out',
        onUpdate: () => { setDisplay(Math.round(counterRef.current.val)); },
        onComplete: () => { setDisplay(value); },
      });
      return () => { tween.kill(); };
    } else {
      const tween = gsap.to(counterRef.current, {
        val: value,
        duration: 0.6,
        ease: 'power2.out',
        onUpdate: () => { setDisplay(Math.round(counterRef.current.val)); },
        onComplete: () => { setDisplay(value); },
      });
      return () => { tween.kill(); };
    }
  }, [value]);

  return <div style={style}>{display}</div>;
};

const DataPipeline: React.FC = () => {
  const message = useAntdMessage();
  const [tasks, setTasks] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | undefined>(undefined);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [pipelineModalOpen, setPipelineModalOpen] = useState(false);
  const [selectedTask, setSelectedTask] = useState<Record<string, unknown> | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [pipelineSteps, setPipelineSteps] = useState<Record<string, unknown>[]>([
    { type: 'import', name: '导入数据', config: {} },
    { type: 'clean', name: '数据清洗', config: {} },
    { type: 'label', name: '智能标注', config: {} },
    { type: 'augment', name: '数据增强', config: {} },
    { type: 'convert', name: '格式转换', config: {} },
  ]);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [runningPipeline, setRunningPipeline] = useState(false);
  const [pipelineStatus, setPipelineStatus] = useState<Record<string, unknown> | null>(null);
  const [form] = Form.useForm();

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const res = await api.dataPipeline.listTasks({ search: search || undefined, type: typeFilter });
      const d = res as Record<string, unknown>;
      const rawItems = d?.items || d?.data || [];
      setTasks(Array.isArray(rawItems) ? rawItems as Record<string, unknown>[] : []);
    } catch {
      setTasks([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTasks(); }, [search, typeFilter]);

  const getTaskId = (task: Record<string, unknown>) => String(task.id || task.task_id);

  const stats = useMemo(() => {
    const total = tasks.length;
    const running = tasks.filter(t => String(t.status) === 'RUNNING').length;
    const completed = tasks.filter(t => String(t.status) === 'COMPLETED').length;
    const failed = tasks.filter(t => String(t.status) === 'FAILED').length;
    return { total, running, completed, failed };
  }, [tasks]);

  const typeDist = useMemo(() => {
    const map: Record<string, number> = {};
    tasks.forEach(t => {
      const type = String(t.type || 'other');
      map[type] = (map[type] || 0) + 1;
    });
    return Object.entries(map).map(([name, value]) => ({
      name: TASK_TYPES.find(t => t.value === name)?.label || name,
      value,
    }));
  }, [tasks]);

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      await api.dataPipeline.createTask(values);
      message.success('任务创建成功');
      setCreateModalOpen(false);
      form.resetFields();
      fetchTasks();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleExecute = async (id: string) => {
    try {
      await api.dataPipeline.executeTask(id);
      message.success('任务已开始执行');
      fetchTasks();
    } catch (err) {
      message.error(getErrorMessage(err));
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await api.dataPipeline.cancelTask(id);
      message.success('任务已取消');
      fetchTasks();
    } catch (err) {
      message.error(getErrorMessage(err));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.dataPipeline.deleteTask(id);
      message.success('任务已删除');
      fetchTasks();
    } catch (err) {
      message.error(getErrorMessage(err));
    }
  };

  const handleViewDetail = async (task: Record<string, unknown>) => {
    const id = getTaskId(task);
    setSelectedTask(task);
    setDetailModalOpen(true);
    setDetailLoading(true);
    try {
      const res = await api.dataPipeline.getTask(id);
      setSelectedTask(res as Record<string, unknown>);
    } catch {} finally {
      setDetailLoading(false);
    }
  };

  const handleRunPipeline = async () => {
    setPipelineRunning(true);
    setRunningPipeline(true);
    try {
      const res = await api.dataPipeline.runPipeline(pipelineSteps);
      setPipelineStatus(res as Record<string, unknown>);
      message.success('流水线已启动');
      fetchTasks();
    } catch (err) {
      message.error(getErrorMessage(err));
    } finally {
      setPipelineRunning(false);
      setRunningPipeline(false);
    }
  };

  const handleCheckPipelineStatus = async (pipelineId: string) => {
    try {
      const res = await api.dataPipeline.getPipelineStatus(pipelineId);
      setPipelineStatus(res as Record<string, unknown>);
    } catch (err) {
      message.error(getErrorMessage(err));
    }
  };

  const formatJSON = (data: unknown): string => {
    if (!data) return '';
    if (typeof data === 'string') {
      try { return JSON.stringify(JSON.parse(data), null, 2); } catch { return String(data); }
    }
    try { return JSON.stringify(data, null, 2); } catch { return String(data); }
  };

  const tooltipStyle: React.CSSProperties = {
    background: 'var(--bg-2)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    fontSize: 12,
    color: 'var(--text-0)',
    padding: '8px 12px',
  };

  const columns = [
    {
      title: '任务名',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: Record<string, unknown>) => (
        <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{String(record.name || text || '未命名任务')}</span>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type: string) => {
        const t = TASK_TYPES.find((t) => t.value === type);
        const color = TYPE_COLORS[type] || 'var(--text-2)';
        return <Tag style={{ background: `${color}15`, color, border: 'none' }}>{t?.label || type}</Tag>;
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (status: string) => {
        const cfg = STATUS_MAP[status] || STATUS_MAP.PENDING;
        return <Tag style={{ background: cfg.dim, color: cfg.color, border: 'none' }}>{cfg.label}</Tag>;
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 140,
      render: (text: string) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>{text ? String(text).slice(0, 10) : '--'}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      render: (_: unknown, record: Record<string, unknown>) => {
        const id = getTaskId(record);
        const status = String(record.status);
        return (
          <Space size={2}>
            <Tooltip title="查看详情">
              <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handleViewDetail(record)} />
            </Tooltip>
            {(status === 'PENDING' || status === 'pending') && (
              <Tooltip title="执行任务">
                <Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleExecute(id)} />
              </Tooltip>
            )}
            {status === 'RUNNING' && (
              <Tooltip title="取消任务">
                <Button type="text" size="small" onClick={() => handleCancel(id)}>取消</Button>
              </Tooltip>
            )}
            <Popconfirm title="确定删除此任务？" onConfirm={() => handleDelete(id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
              <Tooltip title="删除">
                <Button type="text" size="small" icon={<DeleteOutlined />} danger />
              </Tooltip>
            </Popconfirm>
          </Space>
        );
      },
    },
  ];

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>
          数据预处理
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>
          构建ETL流水线，完成数据导入、清洗、标注、增强等预处理任务
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { icon: <DatabaseOutlined style={{ fontSize: 16, color: 'var(--primary)' }} />, label: '任务总数', value: stats.total, color: 'var(--text-0)' },
          { icon: <SyncOutlined spin={stats.running > 0} style={{ fontSize: 16, color: 'var(--blue)' }} />, label: '运行中', value: stats.running, color: 'var(--blue)' },
          { icon: <CheckCircleOutlined style={{ fontSize: 16, color: 'var(--green)' }} />, label: '已完成', value: stats.completed, color: 'var(--green)' },
          { icon: <CloseCircleOutlined style={{ fontSize: 16, color: 'var(--red)' }} />, label: '失败', value: stats.failed, color: 'var(--red)' },
        ].map((item, idx) => (
          <div
            key={idx}
            style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, transition: 'all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)', cursor: 'default', opacity: 0, transform: 'translateY(12px)' }}
            ref={(el) => { if (el) { gsap.fromTo(el, { y: 12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.4, delay: idx * 0.08, ease: 'power2.out', clearProps: 'opacity,y' }); } }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 24px rgba(0,0,0,0.08)'; }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              {item.icon}
              <span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>{item.label}</span>
            </div>
            <CountUpNumber value={item.value} style={{ fontFamily: 'var(--font-mono)', color: item.color, fontWeight: 700, fontSize: 24, lineHeight: 1 }} />
          </div>
        ))}
      </div>

      {typeDist.length > 0 && (
        <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>任务类型分布</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={typeDist} margin={{ top: 8, right: 8, left: -8, bottom: 0 }} barCategoryGap="20%" barGap={4}>
              <XAxis dataKey="name" tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#9C9C9C', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} width={40} />
              <RTooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
              <Bar dataKey="value" barSize={16} radius={[4, 4, 0, 0]} isAnimationActive={false} shape={<StaggeredBarShape radius={[4, 4, 0, 0]} />}>
                {typeDist.map((_, i) => <Cell key={i} fill={['#475569', '#C4532B', '#3A5F8A', '#3D7A4A'][i % 4]} fillOpacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Space size={8}>
          <Select placeholder="类型筛选" value={typeFilter} onChange={setTypeFilter} allowClear style={{ width: 120 }} options={TASK_TYPES.map((t) => ({ value: t.value, label: t.label }))} />
        </Space>
        <Space size={8}>
          <Button icon={<PartitionOutlined />} onClick={() => setPipelineModalOpen(true)}>运行流水线</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>创建任务</Button>
        </Space>
      </div>

      <Collapse
        className="fade-in-up stagger-4"
        defaultActiveKey={['tasks']}
        items={[{
          key: 'tasks',
          label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>任务列表</span>,
          children: loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
          ) : tasks.length === 0 ? (
            <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无任务，点击「创建任务」或「运行流水线」开始</span>}>
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>创建任务</Button>
            </Empty>
          ) : (
            <Table dataSource={tasks} columns={columns} rowKey={(record) => getTaskId(record)} pagination={{ pageSize: 10, showSizeChanger: false }} />
          ),
        }]}
      />

      <Modal title="创建任务" open={createModalOpen} onOk={handleCreate} onCancel={() => { setCreateModalOpen(false); form.resetFields(); }} width={520} okText="创建">
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="任务名称" rules={[{ required: true, message: '请输入任务名称' }]}>
            <Input placeholder="输入任务名称" />
          </Form.Item>
          <Form.Item name="type" label="任务类型" rules={[{ required: true, message: '请选择任务类型' }]}>
            <Select options={TASK_TYPES.map((t) => ({ value: t.value, label: t.label }))} placeholder="选择类型" />
          </Form.Item>
          <Form.Item name="config_json" label="配置 (JSON)">
            <Input.TextArea rows={6} placeholder='{"key": "value"}' style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="任务详情" open={detailModalOpen} onCancel={() => setDetailModalOpen(false)} width={640} footer={null}>
        {detailLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
        ) : selectedTask ? (
          <div style={{ marginTop: 16 }}>
            <div style={{ padding: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: 16 }}>
              <div style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-0)', marginBottom: 8 }}>{String(selectedTask.name || '未命名任务')}</div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <Tag style={{ background: `${TYPE_COLORS[String(selectedTask.type)] || 'var(--text-2)'}15`, color: TYPE_COLORS[String(selectedTask.type)] || 'var(--text-2)', border: 'none' }}>
                  {TASK_TYPES.find((t) => t.value === selectedTask.type)?.label || String(selectedTask.type || '')}
                </Tag>
                <Tag style={{ background: (STATUS_MAP[String(selectedTask.status)] || STATUS_MAP.PENDING).dim, color: (STATUS_MAP[String(selectedTask.status)] || STATUS_MAP.PENDING).color, border: 'none' }}>
                  {(STATUS_MAP[String(selectedTask.status)] || STATUS_MAP.PENDING).label}
                </Tag>
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>{String(selectedTask.created_at || '—')}</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>输入数据</div>
                <div style={{ background: 'var(--bg-0)', borderRadius: 'var(--radius)', padding: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-2)', maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                  {selectedTask.input_data || selectedTask.input ? formatJSON(selectedTask.input_data ?? selectedTask.input) : '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>输出数据</div>
                <div style={{ background: 'var(--bg-0)', borderRadius: 'var(--radius)', padding: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-2)', maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                  {selectedTask.output_data || selectedTask.output ? formatJSON(selectedTask.output_data ?? selectedTask.output) : '—'}
                </div>
              </div>
            </div>
            {selectedTask.log && String(selectedTask.log) !== '' ? (
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>日志</div>
                <div style={{ background: 'var(--bg-0)', borderRadius: 'var(--radius)', padding: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-2)', maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--border)' }}>
                  {String(selectedTask.log)}
                </div>
              </div>
            ) : null}
          </div>
        ) : null}
      </Modal>

      <Modal title="运行流水线" open={pipelineModalOpen} onCancel={() => { setPipelineModalOpen(false); setPipelineStatus(null); }} width={720}
        footer={
          <Space>
            {pipelineStatus && pipelineStatus.pipeline_id ? (
              <Button onClick={() => handleCheckPipelineStatus(String(pipelineStatus.pipeline_id))}>查询状态</Button>
            ) : null}
            <Button type="primary" icon={<PartitionOutlined />} onClick={handleRunPipeline} loading={runningPipeline} disabled={pipelineSteps.length === 0}>运行</Button>
          </Space>
        }>
        <div style={{ marginTop: 16 }}>
          <div style={{ padding: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 12 }}>流程预览</div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap', gap: 8 }}>
              {pipelineSteps.map((step, i) => {
                const t = TASK_TYPES.find((t) => t.value === step.type);
                const color = TYPE_COLORS[String(step.type)] || 'var(--text-2)';
                return (
                  <React.Fragment key={i}>
                    <div style={{ padding: '8px 12px', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', textAlign: 'center' }}>
                      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-0)' }}>{String(step.name)}</div>
                      <Tag style={{ marginTop: 4, background: `${color}15`, color, border: 'none' }}>{t?.label || String(step.type)}</Tag>
                    </div>
                    {i < pipelineSteps.length - 1 && <RightOutlined style={{ color: 'var(--text-3)', fontSize: 10 }} />}
                  </React.Fragment>
                );
              })}
            </div>
          </div>
          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>步骤管理</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12, maxHeight: 280, overflowY: 'auto' }}>
            {pipelineSteps.map((step, i) => {
              const color = TYPE_COLORS[String(step.type)] || 'var(--text-2)';
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--primary)', width: 20, fontWeight: 600 }}>{i + 1}</span>
                  <span style={{ flex: 1, fontSize: 13, color: 'var(--text-0)' }}>{String(step.name)}</span>
                  <Tag style={{ background: `${color}15`, color, border: 'none' }}>{TASK_TYPES.find((t) => t.value === step.type)?.label || String(step.type)}</Tag>
                  <Space size={2}>
                    <Button type="text" size="small" disabled={i === 0} onClick={() => setPipelineSteps((prev) => { const arr = [...prev]; [arr[i - 1], arr[i]] = [arr[i], arr[i - 1]]; return arr; })}>↑</Button>
                    <Button type="text" size="small" disabled={i === pipelineSteps.length - 1} onClick={() => setPipelineSteps((prev) => { const arr = [...prev]; [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]]; return arr; })}>↓</Button>
                    <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={() => setPipelineSteps((prev) => prev.filter((_, idx) => idx !== i))} />
                  </Space>
                </div>
              );
            })}
          </div>
          <Select style={{ width: 200 }} placeholder="添加步骤" options={TASK_TYPES.map((t) => ({ value: t.value, label: t.label }))} onChange={(v) => { const t = TASK_TYPES.find((t) => t.value === v); setPipelineSteps((prev) => [...prev, { type: v, name: t?.label || v, config: {} }]); }} value={undefined} />
          {pipelineStatus && (
            <div style={{ marginTop: 16, padding: 16, borderRadius: 'var(--radius)', background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>流水线状态</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Pipeline ID</span>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-0)', marginTop: 4 }}>{String(pipelineStatus.pipeline_id || pipelineStatus.id || '--')}</div>
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>状态</span>
                  <div style={{ fontSize: 13, fontWeight: 500, marginTop: 4, color: String(pipelineStatus.status).toLowerCase() === 'completed' ? 'var(--green)' : String(pipelineStatus.status).toLowerCase() === 'failed' ? 'var(--red)' : String(pipelineStatus.status).toLowerCase() === 'running' ? 'var(--blue)' : 'var(--yellow)' }}>{String(pipelineStatus.status || '--')}</div>
                </div>
                <div>
                  <span style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>步骤数</span>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color: 'var(--text-0)', fontWeight: 500, marginTop: 4 }}>{String(pipelineStatus.step_count || pipelineStatus.total_steps || pipelineSteps.length)}</div>
                </div>
              </div>
              {Array.isArray(pipelineStatus.steps) && pipelineStatus.steps.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>步骤详情</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {(pipelineStatus.steps as Record<string, unknown>[]).map((step, i) => {
                      const stepStatus = String(step.status || '').toLowerCase();
                      const stepColor = stepStatus === 'completed' ? 'var(--green)' : stepStatus === 'failed' ? 'var(--red)' : stepStatus === 'running' ? 'var(--blue)' : 'var(--yellow)';
                      return (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--primary)', width: 20 }}>{i + 1}</span>
                          <span style={{ flex: 1, fontSize: 12, color: 'var(--text-0)' }}>{String(step.name || step.type || `步骤 ${i + 1}`)}</span>
                          <span style={{ fontSize: 11, color: stepColor, fontWeight: 500 }}>{String(step.status || 'pending')}</span>
                          {step.message ? <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 4 }}>({String(step.message)})</span> : null}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default DataPipeline;
