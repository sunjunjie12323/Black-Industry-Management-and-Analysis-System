import React, { useState } from 'react';
import { Card, Input, Button, Table, Tag, message, Tabs, Space, Statistic, Row, Col, Select, Slider } from 'antd';
import { MergeCellsOutlined, CopyOutlined, WarningOutlined, BranchesOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { TextArea } = Input;

const IntelligenceFusion: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('fuse');
  const [intelligenceIds, setIntelligenceIds] = useState('');
  const [fusionStrategy, setFusionStrategy] = useState('weighted_average');
  const [fuseResult, setFuseResult] = useState<any>(null);
  const [dedupThreshold, setDedupThreshold] = useState(0.85);
  const [dedupResult, setDedupResult] = useState<any>(null);
  const [conflictIds, setConflictIds] = useState('');
  const [conflictResult, setConflictResult] = useState<any>(null);
  const [evidenceJson, setEvidenceJson] = useState('');
  const [evidenceResult, setEvidenceResult] = useState<any>(null);
  const [contradictionId, setContradictionId] = useState('');
  const [contradictionResult, setContradictionResult] = useState<any>(null);
  const [provenanceId, setProvenanceId] = useState('');
  const [provenanceResult, setProvenanceResult] = useState<any>(null);

  // 融合情报
  const handleFuse = async () => {
    if (!intelligenceIds.trim()) {
      message.warning('请输入情报ID列表');
      return;
    }
    const ids = intelligenceIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的情报ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.intelligenceFusion.fuse(ids, fusionStrategy);
      setFuseResult(result);
      message.success('情报融合完成');
    } catch (error: any) {
      message.error(error?.message || '融合失败');
    } finally {
      setLoading(false);
    }
  };

  // 去重
  const handleDeduplicate = async () => {
    setLoading(true);
    try {
      const result = await api.intelligenceFusion.deduplicate(dedupThreshold);
      setDedupResult(result);
      message.success('去重完成');
    } catch (error: any) {
      message.error(error?.message || '去重失败');
    } finally {
      setLoading(false);
    }
  };

  // 解决冲突
  const handleResolveConflicts = async () => {
    if (!conflictIds.trim()) {
      message.warning('请输入情报ID列表');
      return;
    }
    const ids = conflictIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的情报ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.intelligenceFusion.resolveConflicts(ids);
      setConflictResult(result);
      message.success('冲突解决完成');
    } catch (error: any) {
      message.error(error?.message || '解决失败');
    } finally {
      setLoading(false);
    }
  };

  // 聚合证据
  const handleAggregateEvidence = async () => {
    if (!evidenceJson.trim()) {
      message.warning('请输入证据JSON数组');
      return;
    }

    try {
      const evidenceList = JSON.parse(evidenceJson);
      if (!Array.isArray(evidenceList)) {
        message.error('请输入JSON数组');
        return;
      }
      setLoading(true);
      const result = await api.intelligenceFusion.aggregateEvidence(evidenceList);
      setEvidenceResult(result);
      message.success('证据聚合完成');
    } catch (error: any) {
      if (error instanceof SyntaxError) {
        message.error('JSON格式错误');
      } else {
        message.error(error?.message || '聚合失败');
      }
    } finally {
      setLoading(false);
    }
  };

  // 检测矛盾
  const handleDetectContradictions = async () => {
    if (!contradictionId.trim()) {
      message.warning('请输入情报ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.intelligenceFusion.detectContradictions(contradictionId);
      setContradictionResult(result);
      message.success('矛盾检测完成');
    } catch (error: any) {
      message.error(error?.message || '检测失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取溯源
  const handleGetProvenance = async () => {
    if (!provenanceId.trim()) {
      message.warning('请输入融合情报ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.intelligenceFusion.getProvenance(provenanceId);
      setProvenanceResult(result);
      message.success('获取溯源成功');
    } catch (error: any) {
      message.error(error?.message || '获取失败');
    } finally {
      setLoading(false);
    }
  };

  // 去重结果表格列
  const dedupColumns = [
    {
      title: '组ID',
      dataIndex: 'group_id',
      key: 'group_id',
      width: 100
    },
    {
      title: '相似度',
      dataIndex: 'similarity',
      key: 'similarity',
      width: 120,
      render: (sim: number) => (
        <span style={{ color: sim >= 0.9 ? '#f5222d' : sim >= 0.8 ? '#faad14' : '#52c41a' }}>
          {(sim * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '重复情报ID',
      dataIndex: 'items',
      key: 'items',
      render: (ids: string[]) => (
        <Space wrap>
          {ids?.map(id => (
            <Tag key={id} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              {id.slice(0, 8)}...
            </Tag>
          ))}
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>情报融合</h1>
      <p style={{ color: 'var(--text-2)', marginBottom: 24 }}>
        基于TF-IDF去重、Dempster-Shafer证据融合和溯源图进行多源情报融合
      </p>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        {
          key: 'fuse',
          label: '情报融合',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  情报ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={intelligenceIds}
                  onChange={e => setIntelligenceIds(e.target.value)}
                  placeholder="请输入情报ID，每行一个&#10;例如：&#10;intel-001&#10;intel-002&#10;intel-003"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  融合策略
                </label>
                <Select
                  value={fusionStrategy}
                  onChange={setFusionStrategy}
                  style={{ width: 200 }}
                  options={[
                    { value: 'weighted_average', label: '加权平均' },
                    { value: 'max_confidence', label: '最大置信度' },
                    { value: 'majority_vote', label: '多数投票' },
                    { value: 'dempster_shafer', label: 'Dempster-Shafer' }
                  ]}
                />
              </div>

              <Button
                type="primary"
                icon={<MergeCellsOutlined />}
                loading={loading}
                onClick={handleFuse}
                size="large"
              >
                开始融合
              </Button>

              {fuseResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 16 }}>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="去重数量"
                          value={fuseResult.duplicates_removed || 0}
                          prefix={<CopyOutlined />}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="解决冲突"
                          value={fuseResult.conflicts_resolved || 0}
                          prefix={<WarningOutlined />}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="置信度提升"
                          value={((fuseResult.confidence_boost || 0) * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{ color: '#52c41a' }}
                        />
                      </Card>
                    </Col>
                  </Row>

                  <Card title="融合结果">
                    <pre style={{
                      background: 'var(--bg-2)',
                      padding: 16,
                      borderRadius: 8,
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12
                    }}>
                      {JSON.stringify(fuseResult.fused_result, null, 2)}
                    </pre>
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'dedup',
          label: '语义去重',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  相似度阈值: {(dedupThreshold * 100).toFixed(0)}%
                </label>
                <Slider
                  min={0.5}
                  max={1}
                  step={0.01}
                  value={dedupThreshold}
                  onChange={setDedupThreshold}
                  style={{ width: 400 }}
                />
              </div>

              <Button
                type="primary"
                icon={<CopyOutlined />}
                loading={loading}
                onClick={handleDeduplicate}
                size="large"
              >
                开始去重
              </Button>

              {dedupResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 16 }}>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="总情报数"
                          value={dedupResult.total_items || 0}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="唯一情报"
                          value={dedupResult.unique_items || 0}
                          valueStyle={{ color: '#52c41a' }}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="重复组数"
                          value={dedupResult.duplicate_groups || 0}
                          valueStyle={{ color: '#faad14' }}
                        />
                      </Card>
                    </Col>
                  </Row>

                  {dedupResult.duplicates && dedupResult.duplicates.length > 0 && (
                    <Card title="重复情报组">
                      <Table
                        dataSource={dedupResult.duplicates}
                        columns={dedupColumns}
                        rowKey="group_id"
                        pagination={{ pageSize: 10 }}
                        size="middle"
                      />
                    </Card>
                  )}
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'conflict',
          label: '冲突解决',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  情报ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={conflictIds}
                  onChange={e => setConflictIds(e.target.value)}
                  placeholder="请输入存在冲突的情报ID，每行一个"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<WarningOutlined />}
                loading={loading}
                onClick={handleResolveConflicts}
                size="large"
              >
                解决冲突
              </Button>

              {conflictResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="冲突解决结果">
                    <pre style={{
                      background: 'var(--bg-2)',
                      padding: 16,
                      borderRadius: 8,
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12
                    }}>
                      {JSON.stringify(conflictResult.resolved_intelligence, null, 2)}
                    </pre>
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'evidence',
          label: '证据聚合',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  证据JSON数组
                </label>
                <TextArea
                  rows={10}
                  value={evidenceJson}
                  onChange={e => setEvidenceJson(e.target.value)}
                  placeholder='请输入证据JSON数组，例如：&#10;[&#10;  {"source": "source1", "hypothesis": "H1", "belief": 0.7},&#10;  {"source": "source2", "hypothesis": "H1", "belief": 0.8}&#10;]'
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<MergeCellsOutlined />}
                loading={loading}
                onClick={handleAggregateEvidence}
                size="large"
              >
                聚合证据
              </Button>

              {evidenceResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="证据聚合结果">
                    <pre style={{
                      background: 'var(--bg-2)',
                      padding: 16,
                      borderRadius: 8,
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12
                    }}>
                      {JSON.stringify(evidenceResult.aggregated_evidence, null, 2)}
                    </pre>
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'contradiction',
          label: '矛盾检测',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  情报ID
                </label>
                <Input
                  value={contradictionId}
                  onChange={e => setContradictionId(e.target.value)}
                  placeholder="请输入情报ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <Button
                type="primary"
                icon={<WarningOutlined />}
                loading={loading}
                onClick={handleDetectContradictions}
                size="large"
                danger
              >
                检测矛盾
              </Button>

              {contradictionResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title={`矛盾检测结果（共 ${contradictionResult.contradictions?.length || 0} 个矛盾）`}>
                    {contradictionResult.contradictions && contradictionResult.contradictions.length > 0 ? (
                      <Table
                        dataSource={contradictionResult.contradictions}
                        columns={[
                          { title: '矛盾情报ID', dataIndex: 'contradiction_id', key: 'contradiction_id' },
                          {
                            title: '矛盾类型',
                            dataIndex: 'contradiction_type',
                            key: 'contradiction_type',
                            render: (type: string) => <Tag color="red">{type}</Tag>
                          },
                          { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
                          {
                            title: '严重程度',
                            dataIndex: 'severity',
                            key: 'severity',
                            render: (sev: string) => (
                              <Tag color={sev === 'high' ? 'red' : sev === 'medium' ? 'orange' : 'blue'}>
                                {sev}
                              </Tag>
                            )
                          }
                        ]}
                        rowKey="contradiction_id"
                        pagination={{ pageSize: 10 }}
                        size="middle"
                      />
                    ) : (
                      <div style={{ textAlign: 'center', padding: 24, color: 'var(--text-2)' }}>
                        未检测到矛盾
                      </div>
                    )}
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'provenance',
          label: '溯源图',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  融合情报ID
                </label>
                <Input
                  value={provenanceId}
                  onChange={e => setProvenanceId(e.target.value)}
                  placeholder="请输入融合情报ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <Button
                type="primary"
                icon={<BranchesOutlined />}
                loading={loading}
                onClick={handleGetProvenance}
                size="large"
              >
                获取溯源图
              </Button>

              {provenanceResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="溯源图">
                    <pre style={{
                      background: 'var(--bg-2)',
                      padding: 16,
                      borderRadius: 8,
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12,
                      maxHeight: 500
                    }}>
                      {JSON.stringify(provenanceResult.provenance_graph, null, 2)}
                    </pre>
                  </Card>
                </div>
              )}
            </Card>
          )
        }
      ]} />
    </div>
  );
};

export default IntelligenceFusion;
