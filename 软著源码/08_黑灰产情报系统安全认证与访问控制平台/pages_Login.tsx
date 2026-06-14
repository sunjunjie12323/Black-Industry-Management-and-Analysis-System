import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Input, Button } from 'antd';
import { UserOutlined, LockOutlined, SafetyOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { authApi, getErrorMessage } from '../services/api';
import { tokenStorage } from '../utils/tokenStorage';
import { useAntdMessage } from '../utils/hooks';

const REMEMBER_KEY = 'threatintel_remember_user';

const FEATURES = [
  { title: '实时威胁监控', desc: '多源情报实时采集与智能分析', color: '#6C5CE7', icon: 'shield' },
  { title: '知识图谱关联', desc: '实体关系深度挖掘与可视化', color: '#0090FF', icon: 'graph' },
  { title: 'AI智能研判', desc: '大模型驱动的深度情报分析', color: '#30A46C', icon: 'brain' },
  { title: '攻击链预测', desc: '基于马尔可夫链的攻击趋势预判', color: '#E5484D', icon: 'target' },
];

const PARTICLE_COLORS = [
  'rgba(108,92,231,',
  'rgba(0,144,255,',
  'rgba(48,164,108,',
  'rgba(108,92,231,',
  'rgba(90,75,214,',
];

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  colorBase: string;
  opacity: number;
}

const ParticleCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animFrameRef = useRef<number>(0);
  const sizeRef = useRef({ width: 0, height: 0 });

  const initParticles = useCallback((width: number, height: number) => {
    const count = 80;
    const particles: Particle[] = [];
    for (let i = 0; i < count; i++) {
      const colorBase = PARTICLE_COLORS[Math.floor(Math.random() * PARTICLE_COLORS.length)];
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: -(Math.random() * 0.3 + 0.1),
        radius: Math.random() * 2.5 + 2,
        colorBase,
        opacity: Math.random() * 0.4 + 0.3,
      });
    }
    particlesRef.current = particles;
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const applySize = () => {
      const parent = canvas.parentElement;
      if (!parent) return;
      const dpr = window.devicePixelRatio || 1;
      const rect = parent.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);
      sizeRef.current = { width: rect.width, height: rect.height };
      if (particlesRef.current.length === 0) {
        initParticles(rect.width, rect.height);
      }
    };

    applySize();

    const resizeObserver = new ResizeObserver(() => {
      applySize();
    });
    if (canvas.parentElement) {
      resizeObserver.observe(canvas.parentElement);
    }

    const animate = () => {
      const w = sizeRef.current.width;
      const h = sizeRef.current.height;
      if (w === 0 || h === 0) {
        animFrameRef.current = requestAnimationFrame(animate);
        return;
      }

      ctx.clearRect(0, 0, w, h);

      const particles = particlesRef.current;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.y < -10) {
          p.y = h + 10;
          p.x = Math.random() * w;
        }
        if (p.x < -10) p.x = w + 10;
        if (p.x > w + 10) p.x = -10;
      }

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 150) {
            const lineOpacity = 0.15 * (1 - dist / 150);
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(108,92,231,${lineOpacity})`;
            ctx.lineWidth = 0.6;
            ctx.stroke();
          }
        }
      }

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `${p.colorBase}${p.opacity})`;
        ctx.fill();
      }

      animFrameRef.current = requestAnimationFrame(animate);
    };

    animFrameRef.current = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      resizeObserver.disconnect();
    };
  }, [initParticles]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 1,
        pointerEvents: 'none',
      }}
    />
  );
};

const ShieldIllustration: React.FC = () => (
  <svg width="280" height="320" viewBox="0 0 280 320" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="shieldGrad" x1="140" y1="0" x2="140" y2="320" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#6C5CE7" stopOpacity="0.15" />
        <stop offset="100%" stopColor="#6C5CE7" stopOpacity="0.02" />
      </linearGradient>
      <linearGradient id="shieldStroke" x1="140" y1="20" x2="140" y2="280" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#6C5CE7" stopOpacity="0.8" />
        <stop offset="100%" stopColor="#6C5CE7" stopOpacity="0.3" />
      </linearGradient>
    </defs>
    <path d="M140 30L50 75V165C50 230 85 280 140 300C195 280 230 230 230 165V75L140 30Z" fill="url(#shieldGrad)" stroke="url(#shieldStroke)" strokeWidth="2.5" />
    <path d="M140 55L72 88V165C72 218 98 258 140 276C182 258 208 218 208 165V88L140 55Z" fill="rgba(108,92,231,0.04)" stroke="rgba(108,92,231,0.12)" strokeWidth="1" />
    <path d="M112 160L132 180L172 140" stroke="#6C5CE7" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="140" cy="30" r="5" fill="#6C5CE7" opacity="0.6" />
    <circle cx="50" cy="75" r="5" fill="#6C5CE7" opacity="0.6" />
    <circle cx="230" cy="75" r="5" fill="#6C5CE7" opacity="0.6" />
    <line x1="140" y1="30" x2="140" y2="10" stroke="#6C5CE7" strokeWidth="1.5" opacity="0.4" />
    <line x1="50" y1="75" x2="30" y2="65" stroke="#6C5CE7" strokeWidth="1.5" opacity="0.4" />
    <line x1="230" y1="75" x2="250" y2="65" stroke="#6C5CE7" strokeWidth="1.5" opacity="0.4" />
    <circle cx="140" cy="10" r="3" fill="#6C5CE7" opacity="0.3" />
    <circle cx="30" cy="65" r="3" fill="#6C5CE7" opacity="0.3" />
    <circle cx="250" cy="65" r="3" fill="#6C5CE7" opacity="0.3" />
    <line x1="30" y1="65" x2="20" y2="90" stroke="#6C5CE7" strokeWidth="1" opacity="0.2" />
    <line x1="250" y1="65" x2="260" y2="90" stroke="#6C5CE7" strokeWidth="1" opacity="0.2" />
    <circle cx="20" cy="90" r="2" fill="#6C5CE7" opacity="0.2" />
    <circle cx="260" cy="90" r="2" fill="#6C5CE7" opacity="0.2" />
    <line x1="140" y1="10" x2="110" y2="18" stroke="#6C5CE7" strokeWidth="1" opacity="0.15" />
    <line x1="140" y1="10" x2="170" y2="18" stroke="#6C5CE7" strokeWidth="1" opacity="0.15" />
    <circle cx="110" cy="18" r="2" fill="#6C5CE7" opacity="0.15" />
    <circle cx="170" cy="18" r="2" fill="#6C5CE7" opacity="0.15" />
    <rect x="60" y="100" width="16" height="16" rx="3" fill="none" stroke="#6C5CE7" strokeWidth="1" opacity="0.15" transform="rotate(15 68 108)" />
    <circle cx="220" cy="120" r="10" fill="none" stroke="#0090FF" strokeWidth="1" opacity="0.15" />
    <polygon points="80,250 90,235 100,250" fill="none" stroke="#30A46C" strokeWidth="1" opacity="0.15" />
    <rect x="195" y="230" width="12" height="12" rx="2" fill="none" stroke="#E5484D" strokeWidth="1" opacity="0.15" transform="rotate(-10 201 236)" />
  </svg>
);

const FeatureIcon: React.FC<{ type: string; color: string }> = ({ type, color }) => {
  const iconMap: Record<string, React.ReactNode> = {
    shield: (
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <path d="M16 4L6 9V16C6 22.5 10 28 16 30C22 28 26 22.5 26 16V9L16 4Z" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <path d="M12 16L15 19L20 14" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    graph: (
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <circle cx="16" cy="8" r="4" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <circle cx="8" cy="24" r="4" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <circle cx="24" cy="24" r="4" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <line x1="16" y1="12" x2="10" y2="20" stroke={color} strokeWidth="1.5" opacity="0.6" />
        <line x1="16" y1="12" x2="22" y2="20" stroke={color} strokeWidth="1.5" opacity="0.6" />
        <line x1="12" y1="24" x2="20" y2="24" stroke={color} strokeWidth="1.5" opacity="0.6" />
      </svg>
    ),
    brain: (
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <circle cx="16" cy="16" r="12" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <path d="M10 16C10 12 13 10 16 10C19 10 22 12 22 16" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        <path d="M12 20C12 17 14 16 16 16C18 16 20 17 20 20" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="16" cy="14" r="2" fill={color} opacity="0.4" />
      </svg>
    ),
    target: (
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <circle cx="16" cy="16" r="12" stroke={color} strokeWidth="2" fill={`${color}15`} />
        <circle cx="16" cy="16" r="7" stroke={color} strokeWidth="1.5" fill="none" />
        <circle cx="16" cy="16" r="3" fill={color} opacity="0.6" />
        <line x1="16" y1="2" x2="16" y2="6" stroke={color} strokeWidth="1.5" />
        <line x1="16" y1="26" x2="16" y2="30" stroke={color} strokeWidth="1.5" />
        <line x1="2" y1="16" x2="6" y2="16" stroke={color} strokeWidth="1.5" />
        <line x1="26" y1="16" x2="30" y2="16" stroke={color} strokeWidth="1.5" />
      </svg>
    ),
  };
  return <>{iconMap[type] || null}</>;
};

const Login: React.FC = () => {
  const message = useAntdMessage();
  const [username, setUsername] = useState(() => localStorage.getItem(REMEMBER_KEY) || '');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(() => !!localStorage.getItem(REMEMBER_KEY));
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      message.warning('请输入用户名和密码');
      return;
    }
    setLoading(true);
    try {
      const res = await authApi.login(username, password);
      tokenStorage.setToken(res.access_token);
      tokenStorage.setUser(res.user);
      if (rememberMe) {
        localStorage.setItem(REMEMBER_KEY, username.trim());
      } else {
        localStorage.removeItem(REMEMBER_KEY);
      }
      if (res.must_change_password) {
        message.warning('请修改默认密码后再继续使用');
        navigate('/settings?tab=profile');
      } else {
        navigate('/');
      }
    } catch (e) {
      message.error(getErrorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = () => {
    message.info('请联系系统管理员重置密码');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', fontFamily: 'var(--font-body)' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes loginFadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes loginFadeInUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes loginSlideLeft { from { opacity: 0; transform: translateX(-32px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes loginFloat1 { 0%, 100% { transform: translateY(0) rotate(0deg); } 50% { transform: translateY(-12px) rotate(3deg); } }
        @keyframes loginFloat2 { 0%, 100% { transform: translateY(0) rotate(0deg); } 50% { transform: translateY(-8px) rotate(-2deg); } }
        @keyframes loginPulse { 0%, 100% { opacity: 0.5; } 50% { opacity: 1; } }
        @keyframes loginLineGrow { from { width: 0; } to { width: 56px; } }
        @keyframes loginShieldFloat { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-8px); } }
        @keyframes orbDrift1 { 0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.25; } 33% { transform: translate(30px, -20px) scale(1.1); opacity: 0.35; } 66% { transform: translate(-15px, 15px) scale(0.95); opacity: 0.2; } }
        @keyframes orbDrift2 { 0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.2; } 33% { transform: translate(-25px, 20px) scale(1.08); opacity: 0.3; } 66% { transform: translate(20px, -10px) scale(0.92); opacity: 0.15; } }
        @keyframes orbDrift3 { 0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.18; } 50% { transform: translate(15px, 25px) scale(1.12); opacity: 0.28; } }
        @keyframes orbDrift4 { 0%, 100% { transform: translate(0, 0) scale(0.95); opacity: 0.2; } 40% { transform: translate(-20px, -15px) scale(1.05); opacity: 0.3; } 80% { transform: translate(10px, 10px) scale(1); opacity: 0.15; } }

        .login-input .ant-input-affix-wrapper {
          background: #FFFFFF !important;
          border: 2px solid rgba(0,0,0,0.06) !important;
          border-radius: 14px !important;
          height: 50px !important;
          font-size: 15px !important;
          font-family: var(--font-body) !important;
          color: var(--text-0) !important;
          transition: all 0.25s ease !important;
          box-shadow: 0 2px 8px rgba(0,0,0,0.03) !important;
          padding: 0 16px !important;
        }
        .login-input .ant-input-affix-wrapper:hover {
          border-color: rgba(108,92,231,0.3) !important;
          box-shadow: 0 4px 16px rgba(108,92,231,0.08) !important;
        }
        .login-input .ant-input-affix-wrapper-focused,
        .login-input .ant-input-affix-wrapper:focus-within {
          border-color: #6C5CE7 !important;
          box-shadow: 0 0 0 4px rgba(108,92,231,0.1), 0 4px 16px rgba(108,92,231,0.08) !important;
        }
        .login-input .ant-input {
          background: transparent !important;
          border: none !important;
          font-size: 15px !important;
          font-family: var(--font-body) !important;
          color: var(--text-0) !important;
        }
        .login-input .ant-input::placeholder { color: var(--text-3) !important; }
        .login-input .ant-input-prefix { color: var(--text-3) !important; margin-right: 12px !important; }
        .login-input .ant-input-suffix .anticon { color: var(--text-3) !important; }

        .login-btn {
          background: #6C5CE7 !important;
          border: none !important;
          color: #FFFFFF !important;
          font-family: var(--font-body) !important;
          font-size: 16px !important;
          font-weight: 700 !important;
          border-radius: 14px !important;
          height: 52px !important;
          transition: all 0.3s cubic-bezier(0.22, 1, 0.36, 1) !important;
          box-shadow: 0 6px 24px rgba(108,92,231,0.35) !important;
          letter-spacing: 0.02em !important;
        }
        .login-btn:hover {
          background: #5A4BD6 !important;
          transform: translateY(-2px) !important;
          box-shadow: 0 8px 32px rgba(108,92,231,0.45) !important;
        }
        .login-btn:active {
          background: #4F3FC9 !important;
          transform: translateY(0) !important;
        }
      `}</style>

      <div style={{
        width: '58%',
        background: 'linear-gradient(135deg, #F8F7FF 0%, #FFFFFF 40%, #F5F3FF 100%)',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <ParticleCanvas />

        <div style={{
          position: 'absolute',
          top: -60,
          right: -40,
          width: 360,
          height: 360,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(108,92,231,0.25) 0%, rgba(108,92,231,0.1) 40%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 2,
          animation: 'orbDrift1 12s ease-in-out infinite',
        }} />
        <div style={{
          position: 'absolute',
          bottom: -40,
          left: -50,
          width: 320,
          height: 320,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(0,144,255,0.2) 0%, rgba(0,144,255,0.06) 40%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 2,
          animation: 'orbDrift2 15s ease-in-out infinite',
        }} />
        <div style={{
          position: 'absolute',
          top: '40%',
          left: '50%',
          width: 280,
          height: 280,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(48,164,108,0.18) 0%, rgba(48,164,108,0.04) 40%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 2,
          animation: 'orbDrift3 18s ease-in-out infinite',
        }} />
        <div style={{
          position: 'absolute',
          top: '15%',
          left: '10%',
          width: 240,
          height: 240,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(108,92,231,0.2) 0%, rgba(90,75,214,0.05) 40%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 2,
          animation: 'orbDrift4 14s ease-in-out infinite',
        }} />

        <div style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '60px 64px',
          position: 'relative',
          zIndex: 3,
        }}>
          <div style={{ animation: 'loginSlideLeft 0.7s cubic-bezier(0.22, 1, 0.36, 1) both' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 36 }}>
              <div style={{ animation: 'loginShieldFloat 4s ease-in-out infinite' }}>
                <ShieldIllustration />
              </div>
              <div>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 14,
                  fontWeight: 500,
                  color: '#6C5CE7',
                  letterSpacing: '0.06em',
                  display: 'block',
                  marginBottom: 12,
                }}>
                  /ThreatIntel
                </span>
                <h1 style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: 48,
                  fontWeight: 700,
                  color: 'var(--text-0)',
                  lineHeight: 1.15,
                  margin: 0,
                  letterSpacing: '-0.02em',
                }}>
                  黑灰产情报
                  <br />
                  分析平台
                </h1>
                <div style={{
                  width: 56,
                  height: 4,
                  background: '#6C5CE7',
                  borderRadius: 2,
                  marginTop: 20,
                  animation: 'loginLineGrow 0.8s cubic-bezier(0.22, 1, 0.36, 1) both',
                  animationDelay: '0.3s',
                }} />
              </div>
            </div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 16,
            animation: 'loginFadeInUp 0.6s cubic-bezier(0.22, 1, 0.36, 1) both',
            animationDelay: '0.3s',
          }}>
            {FEATURES.map((f, i) => (
              <div
                key={f.title}
                style={{
                  background: 'rgba(255,255,255,0.82)',
                  backdropFilter: 'blur(8px)',
                  WebkitBackdropFilter: 'blur(8px)',
                  borderRadius: 16,
                  padding: '20px 18px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 14,
                  border: `1px solid ${f.color}18`,
                  boxShadow: `0 2px 12px ${f.color}08`,
                  transition: 'all 0.3s cubic-bezier(0.22, 1, 0.36, 1)',
                  cursor: 'default',
                  position: 'relative',
                  overflow: 'hidden',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-3px)';
                  e.currentTarget.style.boxShadow = `0 8px 24px ${f.color}15`;
                  e.currentTarget.style.borderColor = `${f.color}30`;
                  e.currentTarget.style.background = 'rgba(255,255,255,0.92)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = `0 2px 12px ${f.color}08`;
                  e.currentTarget.style.borderColor = `${f.color}18`;
                  e.currentTarget.style.background = 'rgba(255,255,255,0.82)';
                }}
              >
                <div style={{
                  width: 48,
                  height: 48,
                  borderRadius: 14,
                  background: `${f.color}12`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  border: `1px solid ${f.color}20`,
                }}>
                  <FeatureIcon type={f.icon} color={f.color} />
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 16,
                    fontWeight: 700,
                    color: 'var(--text-0)',
                    marginBottom: 4,
                    lineHeight: 1.3,
                  }}>{f.title}</div>
                  <div style={{
                    fontFamily: 'var(--font-body)',
                    fontSize: 13,
                    color: 'var(--text-2)',
                    lineHeight: 1.5,
                  }}>{f.desc}</div>
                </div>
                <div style={{
                  position: 'absolute',
                  top: -8,
                  right: -8,
                  width: 40,
                  height: 40,
                  borderRadius: '50%',
                  background: `${f.color}08`,
                  pointerEvents: 'none',
                }} />
              </div>
            ))}
          </div>
        </div>

        <div style={{
          padding: '24px 64px 32px',
          position: 'relative',
          zIndex: 3,
          borderTop: '1px solid rgba(0,0,0,0.06)',
          background: 'rgba(255,255,255,0.6)',
          backdropFilter: 'blur(6px)',
          WebkitBackdropFilter: 'blur(6px)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-end',
        }}>
          <div style={{ display: 'flex', gap: 36 }}>
            {[
              { value: '1228+', label: '情报条目' },
              { value: '217', label: '实体节点' },
              { value: '761', label: '关联边' },
            ].map((s, i) => (
              <div key={s.label} style={{ animation: `loginFadeInUp 0.5s cubic-bezier(0.22, 1, 0.36, 1) both`, animationDelay: `${0.6 + i * 0.1}s` }}>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 28,
                  fontWeight: 700,
                  color: '#6C5CE7',
                  lineHeight: 1.2,
                }}>{s.value}</div>
                <div style={{
                  fontFamily: 'var(--font-body)',
                  fontSize: 12,
                  color: 'var(--text-3)',
                  marginTop: 2,
                }}>{s.label}</div>
              </div>
            ))}
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: 'var(--text-3)',
            letterSpacing: '0.05em',
          }}>
            © 2026 ThreatIntel
          </div>
        </div>
      </div>

      <div style={{
        width: '42%',
        background: 'linear-gradient(180deg, #F8F7FF 0%, #FFFFFF 40%, #FFFFFF 100%)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '80px 40px 60px',
        animation: 'loginFadeIn 0.6s cubic-bezier(0.22, 1, 0.36, 1) both',
        animationDelay: '0.15s',
        position: 'relative',
        borderLeft: '1px solid rgba(108,92,231,0.08)',
      }}>
        <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', opacity: 0.5 }} xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="loginDots2" x="0" y="0" width="32" height="32" patternUnits="userSpaceOnUse">
              <circle cx="16" cy="16" r="0.8" fill="rgba(108,92,231,0.1)" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#loginDots2)" />
        </svg>

        <div style={{
          position: 'absolute',
          top: '15%',
          right: '10%',
          width: 120,
          height: 120,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(108,92,231,0.06) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />

        <div style={{ width: '100%', maxWidth: 380, position: 'relative', zIndex: 1 }}>
          <div style={{
            width: 56,
            height: 56,
            borderRadius: 16,
            background: 'rgba(108,92,231,0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 32,
            border: '1px solid rgba(108,92,231,0.15)',
          }}>
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M14 2L4 7V14C4 20.5 8 25.5 14 27C20 25.5 24 20.5 24 14V7L14 2Z" stroke="#6C5CE7" strokeWidth="2" fill="rgba(108,92,231,0.08)" />
              <path d="M10 14L13 17L18 12" stroke="#6C5CE7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>

          <div style={{
            fontFamily: 'var(--font-display)',
            fontSize: 36,
            fontWeight: 700,
            color: 'var(--text-0)',
            lineHeight: 1.2,
            marginBottom: 8,
            letterSpacing: '-0.02em',
          }}>
            欢迎回来
          </div>

          <div style={{
            width: 40,
            height: 3,
            background: '#6C5CE7',
            borderRadius: 2,
            marginBottom: 12,
            animation: 'loginLineGrow 0.8s cubic-bezier(0.22, 1, 0.36, 1) both',
            animationDelay: '0.4s',
          }} />

          <div style={{
            fontFamily: 'var(--font-body)',
            fontSize: 15,
            color: 'var(--text-2)',
            marginBottom: 40,
          }}>
            登录以访问威胁情报分析平台
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div>
              <label style={{
                display: 'block',
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                color: 'var(--text-2)',
                marginBottom: 8,
                fontWeight: 600,
              }}>
                用户名
              </label>
              <div className="login-input">
                <Input
                  prefix={<UserOutlined style={{ fontSize: 16 }} />}
                  placeholder="请输入用户名"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onPressEnter={handleLogin}
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label style={{
                display: 'block',
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                color: 'var(--text-2)',
                marginBottom: 8,
                fontWeight: 600,
              }}>
                密码
              </label>
              <div className="login-input">
                <Input.Password
                  prefix={<LockOutlined style={{ fontSize: 16 }} />}
                  placeholder="请输入密码"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onPressEnter={handleLogin}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 14,
                color: 'var(--text-2)',
                cursor: 'pointer',
                userSelect: 'none',
                fontFamily: 'var(--font-body)',
              }}>
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={e => setRememberMe(e.target.checked)}
                  style={{ accentColor: '#6C5CE7', width: 16, height: 16, cursor: 'pointer' }}
                />
                记住我
              </label>
              <span
                style={{
                  fontSize: 14,
                  color: 'var(--text-3)',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-body)',
                  transition: 'color 0.2s ease',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.color = '#6C5CE7'; }}
                onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-3)'; }}
                onClick={handleForgotPassword}
              >
                忘记密码？
              </span>
            </div>

            <Button
              type="primary"
              block
              loading={loading}
              onClick={handleLogin}
              className="login-btn"
            >
              登录系统
            </Button>
          </div>

          <div style={{
            marginTop: 32,
            padding: '14px 20px',
            background: 'rgba(108,92,231,0.06)',
            borderRadius: 14,
            border: '1px solid rgba(108,92,231,0.1)',
            textAlign: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: 13,
            color: '#6C5CE7',
            letterSpacing: '0.03em',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
          }}>
            <SafetyOutlined style={{ fontSize: 15 }} />
            演示账号 / admin · Admin@2024
          </div>

          <div style={{
            marginTop: 40,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
          }}>
            <span style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#30A46C',
              display: 'inline-block',
              animation: 'loginPulse 2s ease-in-out infinite',
            }} />
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              color: 'var(--text-3)',
              letterSpacing: '0.05em',
            }}>
              安全连接 · SSL/TLS 加密
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
