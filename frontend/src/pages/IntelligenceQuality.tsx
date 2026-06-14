import React, { useState } from 'react';
import { Input, Button, Card, Table, Tag, Progress, Statistic, Row, Col, message, Tabs, Select, Space } from 'antd';
import { CheckCircleOutlined, WarningOutlined, CloseCircleOutlined, StarOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { TextArea } = Input;

const IntelligenceQuality: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('assess');
  const [intelligenceIds, setIntelligenceIds] = useState('');
  const [assessResult, setAssessResult] = useState<any>(null);
  const [source, setSource] = useState('');
  const [sourceReputation, setSourceReputation] = useState<any>(null);

  // 情报质量评估
  const handleAssess = async () => {
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
      const result = await api.intelligenceQuality.assess(ids);
      setAssessResult(result);
      message.success('质量评估完成');
    } catch (error: any) {
      message.error(error?.message || '评估失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取来源信誉
  const handleGetSourceReputation = async () => {
    if (!source.trim()) {
      message.warning('请输入来源名称');
      return;
    }

    setLoading(true);
    try {
      const result = await api.intelligenceQuality.getSourceReputation(source);
      setSourceReputation(result);
      message.success('查询成功');
    } catch (error: any) {
      message.error(error?.message || '查询失败');
    } finally {
      setLoading(false);
    }
  };

  // 更新来源信誉
  const handleUpdateSourceReputation = async (wasAccurate: boolean) => {
    if (!source.trim()) {
      message.warning('请输入来源名称');
      return;
    }

    setLoading(true);
    try {
      await api.intelligenceQuality.updateSourceReputation(source, wasAccurate);
      message.success(wasAccurate ? '已提升来源信誉' : '已降低来源信誉');
      handleGetSourceReputation();
    } catch (error: any) {
      message.error(error?.message || '更新失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取质量等级颜色
  const getGradeColor = (grade: string) => {
    const colorMap: Record<string, string> = {
      'A': '#52c41a',
      'B': '#1890ff',
      'C': '#faad14',
      'D': '#ff7a45',
      'F': '#f5222d'
    };
    return colorMap[grade] || '#8c8c8c';
  };

  // 评估结果表格列
  const assessColumns = [
    {
      title: '情报ID',
      dataIndex: 'intelligence_id',
      key: 'intelligence_id',
      width: 120,
      render: (id: string) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{id?.slice(0, 8)}...</span>
    },
    {
      title: '质量等级',
      dataIndex: 'grade',
      key: 'grade',
      width: 100,
      render: (grade: string) => (
        <Tag color={getGradeColor(grade)} style={{ fontWeight: 600 }}>
          {grade}
        </Tag>
      )
    },
    {
      title: '总体评分',
      dataIndex: 'overall_score',
      key: 'overall_score',
      width: 150,
      render: (score: number) => (
        <Progress
          percent={Math.round(score * 100)}
          size="small"
          strokeColor={score >= 0.8 ? '#52c41a' : score >= 0.6 ? '#1890ff' : score >= 0.4 ? '#faad14' : '#f5222d'}
        />
      )
    },
    {
      title: '可信度',
      dataIndex: 'credibility_score',
      key: 'credibility_score',
      width: 120,
      render: (score: number) => (
        <span style={{ color: score >= 0.7 ? '#52c41a' : score >= 0.5 ? '#faad14' : '#f5222d' }}>
          {(score * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '完整性',
      dataIndex: 'completeness_score',
      key: 'completeness_score',
      width: 120,
      render: (score: number) => (
        <span style={{ color: score >= 0.7 ? '#52c41a' : score >= 0.5 ? '#faad14' : '#f5222d' }}>
          {(score * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '时效性',
      dataIndex: 'timeliness_score',
      key: 'timeliness_score',
      width: 120,
      render: (score: number) => (
        <span style={{ color: score >= 0.7 ? '#52c41a' : score >= 0.5 ? '#faad14' : '#f5222d' }}>
          {(score * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '一致性',
      dataIndex: 'consistency_score',
      key: 'consistency_score',
      width: 120,
      render: (score: number) => (
        <span style={{ color: score >= 0.7 ? '#52c41a' : score >= 0.5 ? '#faad14' : '#f5222d' }}>
          {(score * 100).toFixed(1)}%
        </span>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>情报质量评估</h1>
      <p style={{ color: 'var(--text-2)', marginBottom: 24 }}>
        基于贝叶斯可信度、指数衰减时效、Jaccard一致性等算法评估情报质量
      </p>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        {
          key: 'assess',
          label: '质量评估',
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
              <Button
                type="primary"
                icon={<CheckCircleOutlined />}
                loading={loading}
                onClick={handleAssess}
                size="large"
              >
                开始评估
              </Button>

              {assessResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 24 }}>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="评估总数"
                          value={assessResult.summary?.total_count || 0}
                          prefix={<CheckCircleOutlined />}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="平均可信度"
                          value={((assessResult.summary?.avg_credibility || 0) * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{ color: assessResult.summary?.avg_credibility >= 0.7 ? '#52c41a' : '#faad14' }}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="平均完整性"
                          value={((assessResult.summary?.avg_completeness || 0) * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{ color: assessResult.summary?.avg_completeness >= 0.7 ? '#52c41a' : '#faad14' }}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="平均时效性"
                          value={((assessResult.summary?.avg_timeliness || 0) * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{ color: assessResult.summary?.avg_timeliness >= 0.7 ? '#52c41a' : '#faad14' }}
                        />
                      </Card>
                    </Col>
                  </Row>

                  <Table
                    dataSource={assessResult.assessments || []}
                    columns={assessColumns}
                    rowKey="intelligence_id"
                    pagination={{ pageSize: 10 }}
                    size="middle"
                  />
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'reputation',
          label: '来源信誉',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  来源名称
                </label>
                <Space.Compact style={{ width: '100%' }}>
                  <Input
                    value={source}
                    onChange={e => setSource(e.target.value)}
                    placeholder="请输入来源名称，如：telegram、darkweb、forum"
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                  <Button type="primary" loading={loading} onClick={handleGetSourceReputation}>
                    查询信誉
                  </Button>
                </Space.Compact>
              </div>

              {sourceReputation && (
                <div style={{ marginTop: 24 }}>
                  <Card title="来源信誉详情" style={{ marginBottom: 16 }}>
                    <Row gutter={16}>
                      <Col span={8}>
                        <Statistic
                          title="来源"
                          value={sourceReputation.source}
                          prefix={<StarOutlined />}
                        />
                      </Col>
                      <Col span={8}>
                        <Statistic
                          title="信誉评分"
                          value={(sourceReputation.reputation_score * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{
                            color: sourceReputation.reputation_score >= 0.7 ? '#52c41a' :
                                   sourceReputation.reputation_score >= 0.5 ? '#faad14' : '#f5222d'
                          }}
                        />
                      </Col>
                      <Col span={8}>
                        <Statistic
                          title="评估次数"
                          value={sourceReputation.trend?.length || 0}
                        />
                      </Col>
                    </Row>

                    <div style={{ marginTop: 24 }}>
                      <h4 style={{ marginBottom: 12 }}>信誉趋势</h4>
                      {sourceReputation.trend && sourceReputation.trend.length > 0 ? (
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {sourceReputation.trend.slice(-10).map((item: any, idx: number) => (
                            <Tag
                              key={idx}
                              color={item.score >= 0.7 ? 'green' : item.score >= 0.5 ? 'orange' : 'red'}
                            >
                              {(item.score * 100).toFixed(0)}%
                            </Tag>
                          ))}
                        </div>
                      ) : (
                        <p style={{ color: 'var(--text-2)' }}>暂无趋势数据</p>
                      )}
                    </div>

                    <div style={{ marginTop: 24 }}>
                      <h4 style={{ marginBottom: 12 }}>更新信誉</h4>
                      <Space>
                        <Button
                          type="primary"
                          icon={<CheckCircleOutlined />}
                          loading={loading}
                          onClick={() => handleUpdateSourceReputation(true)}
                          style={{ background: '#52c41a' }}
                        >
                          情报准确（+信誉）
                        </Button>
                        <Button
                          danger
                          icon={<CloseCircleOutlined />}
                          loading={loading}
                          onClick={() => handleUpdateSourceReputation(false)}
                        >
                          情报不准确（-信誉）
                        </Button>
                      </Space>
                    </div>
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

export default IntelligenceQuality;
