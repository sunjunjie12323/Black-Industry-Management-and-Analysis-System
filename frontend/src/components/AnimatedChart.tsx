import React, { useRef, useEffect, useState } from 'react';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

interface AnimatedChartProps {
  children: React.ReactNode;
  drawDelay?: number;
}

const AnimatedChart: React.FC<AnimatedChartProps> = ({ children, drawDelay = 0 }) => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const tween = gsap.fromTo(ref.current,
      { opacity: 0, scale: 0.98 },
      {
        opacity: 1,
        scale: 1,
        duration: ANIM_CONFIG.chart.drawDuration,
        ease: 'power2.out',
        delay: drawDelay,
        onComplete: () => {
          if (ref.current) ref.current.style.willChange = 'auto';
        },
      }
    );
    return () => { tween.kill(); };
  }, [drawDelay]);

  return (
    <div ref={ref} style={{ willChange: 'opacity, transform' }}>
      {children}
    </div>
  );
};

interface StaggeredBarShapeProps {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  fill?: string;
  fillOpacity?: number;
  radius?: number[];
  index?: number;
  totalBars?: number;
  layout?: 'horizontal' | 'vertical';
}

const STAGGER_DELAY_MS = 80;
const BASE_DELAY_MS = 400;
const ANIM_DURATION_MS = 600;

const StaggeredBarShape: React.FC<StaggeredBarShapeProps> = ({
  x = 0, y = 0, width = 0, height = 0,
  fill = '#2563EB', fillOpacity = 0.85,
  radius, index = 0, layout = 'vertical',
}) => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const delay = BASE_DELAY_MS + index * STAGGER_DELAY_MS;
    const timer = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(timer);
  }, [index]);

  if (layout === 'vertical') {
    const baseline = y + height;
    return (
      <rect
        x={x}
        y={visible ? y : baseline}
        width={width}
        height={visible ? height : 0}
        fill={fill}
        fillOpacity={fillOpacity}
        rx={radius?.[0] ?? 0}
        ry={radius?.[0] ?? 0}
        style={{
          transition: visible
            ? `y ${ANIM_DURATION_MS}ms cubic-bezier(0.34, 1.56, 0.64, 1), height ${ANIM_DURATION_MS}ms cubic-bezier(0.34, 1.56, 0.64, 1)`
            : 'none',
        }}
      />
    );
  }

  return (
    <rect
      x={visible ? x : 0}
      y={y}
      width={visible ? width : 0}
      height={height}
      fill={fill}
      fillOpacity={fillOpacity}
      rx={radius?.[0] ?? 0}
      ry={radius?.[0] ?? 0}
      style={{
        transition: visible
          ? `x ${ANIM_DURATION_MS}ms cubic-bezier(0.34, 1.56, 0.64, 1), width ${ANIM_DURATION_MS}ms cubic-bezier(0.34, 1.56, 0.64, 1)`
          : 'none',
      }}
    />
  );
};

interface StaggeredPieCellProps {
  cx?: number;
  cy?: number;
  innerRadius?: number;
  outerRadius?: number;
  startAngle?: number;
  endAngle?: number;
  fill?: string;
  index?: number;
}

const StaggeredPieCell: React.FC<StaggeredPieCellProps> = ({
  cx = 0, cy = 0, innerRadius = 0, outerRadius = 0,
  startAngle = 0, endAngle = 0, fill = '#2563EB', index = 0,
}) => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const delay = BASE_DELAY_MS + index * 120;
    const timer = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(timer);
  }, [index]);

  const midAngle = (startAngle + endAngle) / 2;
  const currentOuter = visible ? outerRadius : innerRadius;

  const startX = cx + innerRadius * Math.cos(-midAngle * Math.PI / 180);
  const startY = cy + innerRadius * Math.sin(-midAngle * Math.PI / 180);
  const endX = cx + currentOuter * Math.cos(-midAngle * Math.PI / 180);
  const endY = cy + currentOuter * Math.sin(-midAngle * Math.PI / 180);

  return (
    <path
      d={`M${startX},${startY} L${endX},${endY}`}
      fill={fill}
      opacity={visible ? 1 : 0}
      style={{
        transition: visible
          ? `opacity 0.5s ease-out, d 0.6s cubic-bezier(0.34, 1.56, 0.64, 1)`
          : 'none',
      }}
    />
  );
};

export { StaggeredBarShape, StaggeredPieCell };
export default AnimatedChart;
