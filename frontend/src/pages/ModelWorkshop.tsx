import React, { Suspense, useEffect, useState, useCallback } from 'react';
import { Spin, Table, Button, Modal, Form, Input, Select, Tag, message, Empty, Typography } from 'antd';
import { PlusOutlined, SearchOutlined, DeleteOutlined, TranslationOutlined } from '@ant-design/icons';
import { useSearchParams } from 'react-router-dom';
import {
  AppstoreOutlined, LineChartOutlined,
  ExperimentOutlined,
} from '@ant-design/icons';
import { blacktalkApi } from '../services/api';
import type { BlackTalkTerm, BlackTalkStats } from '../types';

const PromptEngine = React.lazy(() => import('./PromptEngine'));
const Attribution = React.lazy(() => import('./Attribution'));

const TAB_MAP: Record<string, string> = {
  prompts: '0',
  blacktalk: '1',
  attribution: '2',
};

const TAB_MAP_REV: Record<string, string> = {
  '0': 'prompts',
  '1': 'blacktalk',
  '2': 'attribution',
};

const TAB_CONFIG = [
  { key: '0', label: '提示词工程', icon: AppstoreOutlined, color: '#6C5CE7' },
  { key: '1', label: '黑话词典', icon: TranslationOutlined, color: '#FFB020' },
  { key: '2', label: '归因分析', icon: LineChartOutlined, color: '#00E676' },
];

const CATEGORY_OPTIONS = [
  { value: '通用', label: '通用' },
  { value: '诈骗', label: '诈骗' },
  { value: '赌博', label: '赌博' },
  { value: '洗钱', label: '洗钱' },
  { value: '黑产工具', label: '黑产工具' },
  { value: '暗网', label: '暗网' },
];

const CATEGORY_COLOR_MAP: Record<string, string> = {
  '通用': '#6B7280',
  '诈骗': '#DC2626',
  '赌博': '#F59E0B',
  '洗钱': '#3B82F6',
  '黑产工具': '#8B5CF6',
  '暗网': '#1E293B',
};

const BlackTalkDictionary: React.FC = () => {
  const [terms, setTerms] = useState<BlackTalkTerm[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<BlackTalkStats | null>(null);
  const [searchText, setSearchText] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string | undefined>(undefined);
  const [addModalOpen, setAddModalOpen] = useState(false);
  const [decodeModalOpen, setDecodeModalOpen] = useState(false);
  const [decodeText, setDecodeText] = useState('');
  const [decodeResult, setDecodeResult] = useState<{
    found_terms: Array<{ term: string; meaning: string; position: number[] }>;
    decoded_text: string;
  } | null>(null);
  const [decoding, setDecoding] = useState(false);
  const [addForm] = Form.useForm();
  const [adding, setAdding] = useState(false);

  const fetchTerms = useCallback(async () => {
    setLoading(true);
    try {
      const res = await blacktalkApi.listTerms({
        search: searchText || undefined,
        category: categoryFilter,
        limit: 100,
      });
      setTerms(res.items);
      setTotal(res.total);
    } catch {
      message.error('加载黑话术语失败');
    } finally {
      setLoading(false);
    }
  }, [searchText, categoryFilter]);

  const fetchStats = useCallback(async () => {
    try {
      const s = await blacktalkApi.getStats();
      setStats(s);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    fetchTerms();
  }, [fetchTerms]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleAdd = async () => {
    try {
      const values = await addForm.validateFields();
      setAdding(true);
      await blacktalkApi.addTerm(
        values.term,
        values.meaning,
        values.context,
        values.source,
        values.category,
      );
      message.success('术语添加成功');
      setAddModalOpen(false);
      addForm.resetFields();
      fetchTerms();
      fetchStats();
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error('添加术语失败');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await blacktalkApi.listTerms({ limit: 1 });
      setTerms(prev => prev.filter(t => t.id !== id));
      setTotal(prev => prev - 1);
      message.success('已删除');
      fetchTerms();
      fetchStats();
    } catch {
      message.error('删除失败');
    }
  };

  const handleDecode = async () => {
    if (!decodeText.trim()) {
      message.warning('请输入待解码文本');
      return;
    }
    setDecoding(true);
    setDecodeResult(null);
    try {
      const res = await blacktalkApi.decode(decodeText);
      setDecodeResult({
        found_terms: res.found_terms || [],
        decoded_text: res.decoded_text || '',
      });
    } catch {
      message.error('解码失败');
    } finally {
      setDecoding(false);
    }
  };

  const columns = [
    {
      title: '术语',
      dataIndex: 'term',
      key: 'term',
      width: 140,
      render: (text: string) => (
        <span style={{ fontWeight: 600, color: '#E8E9ED', fontFamily: '"Inter", sans-serif' }}>{text}</span>
      ),
    },
    {
      title: '含义',
      dataIndex: 'meaning',
      key: 'meaning',
      ellipsis: true,
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      width: 100,
      render: (cat: string) => (
        <Tag
          color={CATEGORY_COLOR_MAP[cat] || '#6B7280'}
          style={{ borderRadius: 4, fontSize: 12, margin: 0 }}
        >
          {cat || '通用'}
        </Tag>
      ),
    },
    {
      title: '语境',
      dataIndex: 'context',
      key: 'context',
      width: 180,
      ellipsis: true,
      render: (text: string) => text || <span style={{ color: '#7C7F9A' }}>—</span>,
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120,
      ellipsis: true,
      render: (text: string) => text || <span style={{ color: '#7C7F9A' }}>—</span>,
    },
    {
      title: '操作',
      key: 'action',
      width: 72,
      render: (_: unknown, record: BlackTalkTerm) => (
        <Button
          type="text"
          danger
          size="small"
          icon={<DeleteOutlined />}
          onClick={() => handleDelete(record.id)}
        />
      ),
    },
  ];

  const renderStatsRow = () => {
    if (!stats) return null;
    const catEntries = Object.entries(stats.categories || {});
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        padding: '12px 0',
        fontSize: 13,
        fontFamily: '"Inter", sans-serif',
        color: '#7C7F9A',
        flexWrap: 'wrap',
      }}>
        <span>
          共 <span style={{ fontWeight: 700, color: '#E8E9ED', fontSize: 16 }}>{stats.total_terms}</span> 条术语
        </span>
        {catEntries.length > 0 && (
          <>
            <span style={{ color: 'rgba(255,255,255,0.12)' }}>|</span>
            {catEntries.map(([cat, count]) => (
              <span key={cat} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <span style={{
                  display: 'inline-block',
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: CATEGORY_COLOR_MAP[cat] || '#6B7280',
                }} />
                {cat} <span style={{ fontWeight: 600, color: '#E8E9ED' }}>{count}</span>
              </span>
            ))}
          </>
        )}
      </div>
    );
  };

  const renderDecodeModal = () => (
    <Modal
      open={decodeModalOpen}
      onCancel={() => { setDecodeModalOpen(false); setDecodeResult(null); setDecodeText(''); }}
      title={<span style={{ fontFamily: '"Inter", sans-serif', fontWeight: 700 }}>黑话解码</span>}
      footer={null}
      width={640}
      destroyOnHidden
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Input.TextArea
          rows={4}
          placeholder="输入包含黑话的文本，系统将自动识别并解码..."
          value={decodeText}
          onChange={e => setDecodeText(e.target.value)}
          style={{ fontSize: 13, fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif' }}
        />
        <Button
          type="primary"
          icon={<TranslationOutlined />}
          loading={decoding}
          onClick={handleDecode}
          style={{ alignSelf: 'flex-end' }}
        >
          解码
        </Button>

        {decodeResult && (
          <div style={{
            marginTop: 8,
            padding: 16,
            background: 'rgba(20,22,37,0.80)',
            borderRadius: 12,
            border: '1px solid rgba(255,255,255,0.06)',
          }}>
            {decodeResult.found_terms.length > 0 ? (
              <>
                <div style={{ marginBottom: 12 }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12, fontFamily: '"Inter", sans-serif' }}>
                    识别到 {decodeResult.found_terms.length} 个黑话术语：
                  </Typography.Text>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                    {decodeResult.found_terms.map((ft, idx) => (
                      <Tag
                        key={idx}
                        color="blue"
                        style={{ fontSize: 12, borderRadius: 4 }}
                      >
                        {ft.term} → {ft.meaning}
                      </Tag>
                    ))}
                  </div>
                </div>
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12, fontFamily: '"Inter", sans-serif' }}>
                    解码结果：
                  </Typography.Text>
                  <div style={{
                    marginTop: 4,
                    padding: '8px 12px',
                    background: 'rgba(20,22,37,0.80)',
                    borderRadius: 8,
                    border: '1px solid rgba(255,255,255,0.06)',
                    fontSize: 13,
                    lineHeight: 1.8,
                    fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif',
                    color: '#E8E9ED',
                  }}>
                    {decodeResult.decoded_text}
                  </div>
                </div>
              </>
            ) : (
              <Empty
                description="未识别到黑话术语"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                style={{ padding: '12px 0' }}
              />
            )}
          </div>
        )}
      </div>
    </Modal>
  );

  const renderAddModal = () => (
    <Modal
      open={addModalOpen}
      onCancel={() => { setAddModalOpen(false); addForm.resetFields(); }}
      title={<span style={{ fontFamily: '"Inter", sans-serif', fontWeight: 700 }}>添加术语</span>}
      onOk={handleAdd}
      confirmLoading={adding}
      okText="添加"
      cancelText="取消"
      destroyOnHidden
    >
      <Form
        form={addForm}
        layout="vertical"
        style={{ marginTop: 8 }}
      >
        <Form.Item
          name="term"
          label="术语"
          rules={[{ required: true, message: '请输入术语' }]}
        >
          <Input placeholder="如：跑路、水房" style={{ fontSize: 13 }} />
        </Form.Item>
        <Form.Item
          name="meaning"
          label="含义"
          rules={[{ required: true, message: '请输入含义' }]}
        >
          <Input placeholder="术语的含义解释" style={{ fontSize: 13 }} />
        </Form.Item>
        <Form.Item name="category" label="分类" initialValue="通用">
          <Select options={CATEGORY_OPTIONS} />
        </Form.Item>
        <Form.Item name="context" label="语境">
          <Input placeholder="术语使用的语境场景" style={{ fontSize: 13 }} />
        </Form.Item>
        <Form.Item name="source" label="来源">
          <Input placeholder="术语来源" style={{ fontSize: 13 }} />
        </Form.Item>
      </Form>
    </Modal>
  );

  return (
    <div style={{ padding: 24, minHeight: '100%' }}>
      {renderStatsRow()}

      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        marginBottom: 16,
        flexWrap: 'wrap',
      }}>
        <Input
          placeholder="搜索术语..."
          prefix={<SearchOutlined style={{ color: '#7C7F9A' }} />}
          value={searchText}
          onChange={e => setSearchText(e.target.value)}
          allowClear
          style={{ width: 240, fontSize: 13 }}
        />
        <Select
          placeholder="分类筛选"
          allowClear
          value={categoryFilter}
          onChange={v => setCategoryFilter(v)}
          options={CATEGORY_OPTIONS}
          style={{ width: 140 }}
        />
        <div style={{ flex: 1 }} />
        <Button
          icon={<TranslationOutlined />}
          onClick={() => setDecodeModalOpen(true)}
        >
          黑话解码
        </Button>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setAddModalOpen(true)}
        >
          添加术语
        </Button>
      </div>

      <Table
        dataSource={terms}
        columns={columns}
        rowKey="id"
        loading={loading}
        size="middle"
        pagination={{
          total,
          pageSize: 20,
          showSizeChanger: false,
          showTotal: t => `共 ${t} 条`,
          style: { marginTop: 12 },
        }}
        style={{
          background: '#141625',
          borderRadius: 8,
          border: '1px solid rgba(255,255,255,0.06)',
        }}
      />

      {renderAddModal()}
      {renderDecodeModal()}
    </div>
  );
};

const ModelWorkshop: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeKey = TAB_MAP[tabParam || 'prompts'] || '0';

  useEffect(() => {
    document.title = '黑话分析 - 黑灰产情报分析平台';
  }, []);

  const renderContent = () => {
    if (activeKey === '1') {
      return <BlackTalkDictionary />;
    }
    return (
      <Suspense fallback={
        <div style={{ padding: 64, textAlign: 'center' }}>
          <Spin />
        </div>
      }>
        {activeKey === '0' && <PromptEngine />}
        {activeKey === '2' && <Attribution />}
      </Suspense>
    );
  };

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        background: '#141625',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '16px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 36,
            height: 36,
            borderRadius: 10,
            background: 'rgba(108,92,231,0.12)',
            color: '#6C5CE7',
            fontSize: 16,
          }}>
            <ExperimentOutlined />
          </span>
          <div>
            <h1 style={{
              fontSize: 18,
              fontWeight: 700,
              fontFamily: '"Space Grotesk", "PingFang SC", sans-serif',
              color: '#E8E9ED',
              margin: 0,
              letterSpacing: '-0.01em',
            }}>
              黑话分析
            </h1>
          </div>
        </div>
      </div>

      <div style={{
        background: '#141625',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        padding: '0 32px',
        display: 'flex',
        alignItems: 'stretch',
        gap: 0,
        height: 48,
        flexShrink: 0,
      }}>
        {TAB_CONFIG.map((item) => {
          const isActive = activeKey === item.key;
          const IconComp = item.icon;
          return (
            <button
              key={item.key}
              onClick={() => {
                const tabName = TAB_MAP_REV[item.key];
                setSearchParams(tabName ? { tab: tabName } : {});
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '0 18px',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? `2px solid ${item.color}` : '2px solid transparent',
                cursor: 'pointer',
                fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif',
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                color: isActive ? item.color : '#7C7F9A',
                transition: 'all 0.2s ease',
              }}
              onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.color = '#B0B3C5'; }}
              onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.color = '#7C7F9A'; }}
            >
              <IconComp style={{ fontSize: 14 }} />
              {item.label}
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        {renderContent()}
      </div>
    </div>
  );
};

export default ModelWorkshop;
