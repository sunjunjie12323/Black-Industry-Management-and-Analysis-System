import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';

interface AIStreamRendererProps {
  content: string;
  isStreaming?: boolean;
  speed?: number;
  onComplete?: () => void;
}

const AIStreamRenderer: React.FC<AIStreamRendererProps> = ({ content, isStreaming = false, speed = 30, onComplete }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [displayedContent, setDisplayedContent] = useState('');
  const cursorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isStreaming && content) {
      setDisplayedContent(content);
      gsap.fromTo(containerRef.current, { opacity: 0 }, { opacity: 1, duration: 0.3 });
      return;
    }
    let index = 0;
    const interval = setInterval(() => {
      if (index < content.length) {
        setDisplayedContent(content.substring(0, index + 1));
        index++;
        if (cursorRef.current) {
          gsap.fromTo(cursorRef.current, { opacity: 0 }, { opacity: 1, duration: 0.1 });
        }
      } else {
        clearInterval(interval);
        onComplete?.();
      }
    }, speed);
    return () => clearInterval(interval);
  }, [content, isStreaming, speed]);

  return (
    <div ref={containerRef} style={{ position: 'relative', whiteSpace: 'pre-wrap', lineHeight: 1.7 }}>
      <div dangerouslySetInnerHTML={{ __html: formatMarkdown(displayedContent) }} />
      {isStreaming && (
        <div ref={cursorRef} style={{ display: 'inline-block', width: 2, height: '1em', background: '#1890ff', marginLeft: 2, verticalAlign: 'text-bottom', animation: 'blink 1s infinite' }} />
      )}
    </div>
  );
};

function formatMarkdown(text: string): string {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code style="background:#f5f5f5;padding:2px 6px;border-radius:3px;font-size:0.9em">$1</code>')
    .replace(/^### (.*?)$/gm, '<h4 style="margin:12px 0 6px;font-weight:600">$1</h4>')
    .replace(/^## (.*?)$/gm, '<h3 style="margin:16px 0 8px;font-weight:600">$1</h3>')
    .replace(/^# (.*?)$/gm, '<h2 style="margin:20px 0 10px;font-weight:600">$1</h2>')
    .replace(/^- (.*?)$/gm, '<div style="padding-left:16px;margin:4px 0">• $1</div>')
    .replace(/\n/g, '<br/>');
}

export default AIStreamRenderer;
