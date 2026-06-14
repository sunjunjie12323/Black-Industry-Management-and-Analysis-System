import React, { useEffect, useRef } from 'react';
import { Space, Typography } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import gsap from 'gsap';

const { Text } = Typography;

interface ThinkingIndicatorProps {
  message?: string;
}

const ThinkingIndicator: React.FC<ThinkingIndicatorProps> = ({ message = '思考中...' }) => {
  const dotsRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!dotsRef.current) return;
    const tl = gsap.timeline({ repeat: -1 });
    tl.to(dotsRef.current, { duration: 0.3, onUpdate: () => { if (dotsRef.current) dotsRef.current.textContent = '.'; } })
      .to(dotsRef.current, { duration: 0.3, onUpdate: () => { if (dotsRef.current) dotsRef.current.textContent = '..'; } })
      .to(dotsRef.current, { duration: 0.3, onUpdate: () => { if (dotsRef.current) dotsRef.current.textContent = '...'; } });
    return () => { tl.kill(); };
  }, []);

  return (
    <Space style={{ padding: '8px 16px', background: 'var(--bg-2)', borderRadius: 8, display: 'inline-flex' }}>
      <LoadingOutlined style={{ fontSize: 16, color: 'var(--accent)' }} />
      <Text type="secondary">{message}<span ref={dotsRef} /></Text>
    </Space>
  );
};

export default ThinkingIndicator;
