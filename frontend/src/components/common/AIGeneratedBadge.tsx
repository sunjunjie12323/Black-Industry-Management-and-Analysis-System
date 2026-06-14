import React from 'react';
import { Tag } from 'antd';
import { RobotOutlined } from '@ant-design/icons';

interface AIGeneratedBadgeProps {
  reviewStatus?: string;
  showStatus?: boolean;
}

const AIGeneratedBadge: React.FC<AIGeneratedBadgeProps> = ({ reviewStatus, showStatus = true }) => {
  const statusConfig: Record<string, { color: string; text: string }> = {
    PENDING: { color: 'orange', text: '待审核' },
    APPROVED: { color: 'green', text: '已审核' },
    REJECTED: { color: 'red', text: '已驳回' },
  };
  const config = reviewStatus ? statusConfig[reviewStatus] : null;
  return (
    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
      <Tag icon={<RobotOutlined />} color="purple">AI生成</Tag>
      {showStatus && config && <Tag color={config.color}>{config.text}</Tag>}
    </span>
  );
};

export default AIGeneratedBadge;
