import React, { useEffect, useRef, useState } from 'react';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  color: string;
  trend?: { value: number; direction: 'up' | 'down' };
  suffix?: string;
  index?: number;
}

const keyframes = `
@keyframes scFadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes scCountReveal {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes scLineGrow {
  from { transform: scaleX(0); }
  to { transform: scaleX(1); }
}
@keyframes scPulse {
  0%, 100% { opacity: 0.12; }
  50% { opacity: 0.2; }
}
`;

let styleInjected = false;

function injectStyles() {
  if (styleInjected) return;
  if (typeof document === 'undefined') return;
  const sheet = document.createElement('style');
  sheet.textContent = keyframes;
  document.head.appendChild(sheet);
  styleInjected = true;
}

const StatCard: React.FC<StatCardProps> = ({
  icon,
  label,
  value,
  color,
  trend,
  suffix,
  index = 0,
}) => {
  const [mounted, setMounted] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const counterRef = useRef({ val: 0 });
  const hasAnimated = useRef(false);
  const prevValue = useRef<typeof value>(value);
  const rafRef = useRef<number>(0);
  const innerTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [displayValue, setDisplayValue] = useState<typeof value>(
    typeof value === 'number' ? 0 : value
  );

  useEffect(() => {
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      if (innerTimerRef.current) clearTimeout(innerTimerRef.current);
    };
  }, []);

  useEffect(() => {
    injectStyles();
    const timer = setTimeout(() => {
      setMounted(true);
      innerTimerRef.current = setTimeout(() => setRevealed(true), 200);
    }, index * 100);
    return () => {
      clearTimeout(timer);
      if (innerTimerRef.current) clearTimeout(innerTimerRef.current);
    };
  }, [index]);

  useEffect(() => {
    if (typeof value !== 'number') {
      setDisplayValue(value);
      return;
    }
    if (!hasAnimated.current) {
      hasAnimated.current = true;
      counterRef.current.val = 0;
      setDisplayValue(0);
      const start = performance.now();
      const duration = 800;
      const to = value;
      const animate = (now: number) => {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(to * eased);
        setDisplayValue(current);
        if (progress < 1) {
          rafRef.current = requestAnimationFrame(animate);
        } else {
          setDisplayValue(to);
        }
      };
      rafRef.current = requestAnimationFrame(animate);
    } else if (prevValue.current !== value) {
      const from = typeof prevValue.current === 'number' ? prevValue.current : 0;
      const to = value;
      const start = performance.now();
      const duration = 600;
      const animate = (now: number) => {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(from + (to - from) * eased);
        setDisplayValue(current);
        if (progress < 1) {
          rafRef.current = requestAnimationFrame(animate);
        } else {
          setDisplayValue(to);
        }
      };
      rafRef.current = requestAnimationFrame(animate);
      prevValue.current = value;
    }
  }, [value]);

  const trendColor = trend?.direction === 'up' ? '#34D399' : '#EF4444';

  return (
    <div
      style={{
        background: 'linear-gradient(135deg, var(--glass-bg) 0%, rgba(28,31,53,0.6) 100%)',
        border: '1px solid rgba(108,92,231,0.08)',
        borderRadius: 16,
        padding: '24px 24px 20px 24px',
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
        cursor: 'default',
        position: 'relative',
        overflow: 'hidden',
        opacity: mounted ? 1 : 0,
        transform: mounted ? 'translateY(0)' : 'translateY(20px)',
        animation: mounted ? `scFadeInUp 0.5s cubic-bezier(0.22, 1, 0.36, 1) both` : 'none',
        animationDelay: mounted ? `${index * 100}ms` : '0ms',
        transition: 'all 0.3s cubic-bezier(0.22, 1, 0.36, 1)',
        boxShadow: '0 1px 3px rgba(0,0,0,0.2), 0 1px 2px rgba(0,0,0,0.3)',
        backdropFilter: 'blur(12px)',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-2px)';
        e.currentTarget.style.boxShadow = `0 12px 40px rgba(0,0,0,0.4), 0 0 0 1px ${color}20, 0 0 30px ${color}08`;
        e.currentTarget.style.borderColor = `${color}35`;
        e.currentTarget.style.background = 'linear-gradient(135deg, rgba(20,22,37,0.95) 0%, rgba(28,31,53,0.7) 100%)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.2), 0 1px 2px rgba(0,0,0,0.3)';
        e.currentTarget.style.borderColor = 'rgba(108,92,231,0.08)';
        e.currentTarget.style.background = 'linear-gradient(135deg, var(--glass-bg) 0%, rgba(28,31,53,0.6) 100%)';
      }}
    >
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        bottom: 0,
        width: '40%',
        background: `linear-gradient(135deg, ${color}0D 0%, transparent 100%)`,
        pointerEvents: 'none',
        zIndex: 0,
      }} />

      <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 0 }} xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id={`scDots${index}`} x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
            <circle cx="10" cy="10" r="1" fill={color} opacity="0.06" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill={`url(#scDots${index})`} />
      </svg>

      <div style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: 80,
        height: 80,
        background: `radial-gradient(circle at 100% 0%, ${color}0A, transparent 70%)`,
        pointerEvents: 'none',
        zIndex: 0,
      }} />

      <div style={{
        position: 'absolute',
        right: -16,
        bottom: -16,
        width: 100,
        height: 100,
        borderRadius: '50%',
        background: `${color}08`,
        pointerEvents: 'none',
        animation: 'scPulse 4s ease-in-out infinite',
      }} />

      <div style={{
        position: 'absolute',
        right: 8,
        top: 8,
        fontSize: 56,
        color: color,
        opacity: 0.05,
        lineHeight: 1,
        pointerEvents: 'none',
        zIndex: 0,
      }}>
        {icon}
      </div>

      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 3,
          background: `linear-gradient(90deg, ${color}, ${color}60, transparent)`,
          borderRadius: '3px 3px 0 0',
          transformOrigin: 'left center',
          animation: mounted ? `scLineGrow 0.6s cubic-bezier(0.22, 1, 0.36, 1) both` : 'none',
          animationDelay: mounted ? `${index * 100 + 200}ms` : '0ms',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 14, position: 'relative', zIndex: 1 }}>
        <span style={{
          width: 48,
          height: 48,
          borderRadius: '50%',
          background: `linear-gradient(135deg, ${color}20 0%, ${color}0A 100%)`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: color,
          fontSize: 22,
          flexShrink: 0,
          border: `1px solid ${color}15`,
          boxShadow: `0 2px 8px ${color}10, 0 0 16px ${color}06`,
        }}>
          {icon}
        </span>
        <span style={{
          fontFamily: '"DM Sans", sans-serif',
          fontSize: 13,
          fontWeight: 500,
          letterSpacing: '0.02em',
          color: 'var(--text-2)',
          lineHeight: 1,
        }}>
          {label}
        </span>
      </div>

      <div style={{
        display: 'flex',
        alignItems: 'baseline',
        gap: 8,
        opacity: revealed ? 1 : 0,
        transform: revealed ? 'translateY(0)' : 'translateY(10px)',
        animation: revealed ? `scCountReveal 0.4s cubic-bezier(0.22, 1, 0.36, 1) both` : 'none',
        position: 'relative',
        zIndex: 1,
        paddingLeft: 62,
      }}>
        <span style={{
          fontFamily: '"DM Sans", sans-serif',
          fontSize: 48,
          fontWeight: 700,
          color: 'var(--text-0)',
          lineHeight: 1.1,
          letterSpacing: '-0.02em',
          fontVariantNumeric: 'tabular-nums',
        }}>
          {displayValue}
        </span>
        {suffix && (
          <span style={{
            fontFamily: '"DM Sans", sans-serif',
            fontSize: 14,
            fontWeight: 500,
            color: 'var(--text-2)',
            lineHeight: 1,
          }}>
            {suffix}
          </span>
        )}
        {trend && (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            padding: '3px 8px',
            borderRadius: 6,
            background: trend.direction === 'up' ? 'rgba(48,164,108,0.08)' : 'rgba(229,72,77,0.08)',
            marginLeft: 4,
          }}>
            {trend.direction === 'up' ? (
              <ArrowUpOutlined style={{ fontSize: 10, color: trendColor }} />
            ) : (
              <ArrowDownOutlined style={{ fontSize: 10, color: trendColor }} />
            )}
            <span style={{
              fontFamily: '"DM Sans", sans-serif',
              fontSize: 12,
              color: trendColor,
              lineHeight: 1,
              fontWeight: 600,
              fontVariantNumeric: 'tabular-nums',
            }}>
              {Math.abs(trend.value).toFixed(1)}%
            </span>
          </span>
        )}
      </div>

      {trend && (
        <div style={{
          paddingLeft: 62,
          marginTop: -8,
          position: 'relative',
          zIndex: 1,
        }}>
          <span style={{
            fontFamily: '"DM Sans", sans-serif',
            fontSize: 11,
            color: 'var(--text-2)',
            lineHeight: 1,
            fontWeight: 400,
          }}>
            vs上周
          </span>
        </div>
      )}
    </div>
  );
};

export default StatCard;
