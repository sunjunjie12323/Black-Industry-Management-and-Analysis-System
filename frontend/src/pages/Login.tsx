import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Input, Button } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate, Link } from 'react-router-dom';
import gsap from 'gsap';
import { authApi, getErrorMessage } from '../services/api';
import { tokenStorage } from '../utils/tokenStorage';
import { useAntdMessage } from '../utils/hooks';

const REMEMBER_KEY = 'threatintel_remember_user';

const AuroraCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const mouseRef = useRef({ x: 0.5, y: 0.5 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d')!;
    let w = 0, h = 0;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.parentElement!.getBoundingClientRect();
      w = rect.width; h = rect.height;
      canvas.width = w * dpr; canvas.height = h * dpr;
      canvas.style.width = `${w}px`; canvas.style.height = `${h}px`;
      ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr);
    };
    resize();
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    const onMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX / w, y: e.clientY / h };
    };
    window.addEventListener('mousemove', onMove);

    let t = 0;
    const orbs = [
      { x: 0.2, y: 0.3, r: 350, sx: 0.3, sy: 0.2, c: [99, 102, 241] },
      { x: 0.8, y: 0.7, r: 400, sx: 0.25, sy: 0.35, c: [139, 92, 246] },
      { x: 0.5, y: 0.2, r: 300, sx: 0.4, sy: 0.15, c: [79, 70, 229] },
      { x: 0.3, y: 0.8, r: 280, sx: 0.2, sy: 0.3, c: [168, 85, 247] },
      { x: 0.7, y: 0.4, r: 320, sx: 0.35, sy: 0.25, c: [67, 56, 202] },
    ];

    const particles: { x: number; y: number; vx: number; vy: number; s: number; o: number; c: number[]; l: number; ml: number }[] = [];
    for (let i = 0; i < 120; i++) {
      particles.push({
        x: Math.random() * 2000, y: Math.random() * 2000,
        vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
        s: Math.random() * 2.5 + 0.5, o: Math.random() * 0.6 + 0.1,
        c: [[99,102,241],[139,92,246],[168,85,247],[79,70,229]][Math.floor(Math.random()*4)],
        l: Math.random() * 800, ml: 600 + Math.random() * 600,
      });
    }

    const animate = () => {
      t += 0.004;
      ctx.fillStyle = '#07060E';
      ctx.fillRect(0, 0, w, h);

      const mx = mouseRef.current.x;
      const my = mouseRef.current.y;

      for (const orb of orbs) {
        const ox = (orb.x + Math.sin(t * orb.sx) * 0.12 + (mx - 0.5) * 0.05) * w;
        const oy = (orb.y + Math.cos(t * orb.sy) * 0.1 + (my - 0.5) * 0.05) * h;
        const pr = orb.r + Math.sin(t * 0.8 + orb.sx * 10) * 40;
        const g = ctx.createRadialGradient(ox, oy, 0, ox, oy, pr);
        g.addColorStop(0, `rgba(${orb.c.join(',')},0.12)`);
        g.addColorStop(0.4, `rgba(${orb.c.join(',')},0.05)`);
        g.addColorStop(1, `rgba(${orb.c.join(',')},0)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(ox, oy, pr, 0, Math.PI * 2); ctx.fill();
      }

      for (const p of particles) {
        p.x += p.vx; p.y += p.vy; p.l += 1;
        if (p.x < 0) p.x = w; if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = h; if (p.y > h) p.y = 0;
        const lr = p.l / p.ml;
        const fo = lr < 0.1 ? p.o * lr / 0.1 : lr > 0.85 ? p.o * (1 - (lr - 0.85) / 0.15) : p.o;
        const gg = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.s * 8);
        gg.addColorStop(0, `rgba(${p.c.join(',')},${fo * 0.25})`);
        gg.addColorStop(1, `rgba(${p.c.join(',')},0)`);
        ctx.fillStyle = gg; ctx.beginPath(); ctx.arc(p.x, p.y, p.s * 8, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = `rgba(${p.c.join(',')},${fo})`;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.s, 0, Math.PI * 2); ctx.fill();
        if (p.l >= p.ml) { p.x = Math.random() * w; p.y = Math.random() * h; p.l = 0; }
      }

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 120) {
            ctx.strokeStyle = `rgba(139,92,246,${0.06 * (1 - d / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y); ctx.stroke();
          }
        }
      }

      const cx = w * 0.5, cy = h * 0.45;
      for (let i = 0; i < 4; i++) {
        const rr = 120 + i * 60 + Math.sin(t * 0.6 + i) * 20;
        const rot = t * 0.08 * (i % 2 === 0 ? 1 : -1);
        ctx.save(); ctx.translate(cx, cy); ctx.rotate(rot);
        ctx.strokeStyle = `rgba(139,92,246,${0.04 - i * 0.008})`;
        ctx.lineWidth = 0.8;
        ctx.beginPath(); ctx.ellipse(0, 0, rr, rr * 0.45, 0, 0, Math.PI * 2); ctx.stroke();
        ctx.restore();
      }

      animRef.current = requestAnimationFrame(animate);
    };
    animRef.current = requestAnimationFrame(animate);
    return () => { cancelAnimationFrame(animRef.current); ro.disconnect(); window.removeEventListener('mousemove', onMove); };
  }, []);

  return <canvas ref={canvasRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 0 }} />;
};

const HexGrid: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const ctx = gsap.context(() => {
      const items = ref.current!.querySelectorAll('.hex-cell');
      items.forEach((el, i) => {
        gsap.fromTo(el, { opacity: 0, scale: 0 }, {
          opacity: 1, scale: 1, duration: 0.6, delay: 1.8 + i * 0.04,
          ease: 'back.out(1.7)',
        });
        gsap.to(el, {
          opacity: 0.15 + Math.random() * 0.15,
          duration: 2 + Math.random() * 2,
          repeat: -1, yoyo: true, ease: 'sine.inOut',
          delay: i * 0.1,
        });
      });
    });
    return () => ctx.revert();
  }, []);

  const cells = [];
  for (let row = 0; row < 8; row++) {
    for (let col = 0; col < 6; col++) {
      const offset = row % 2 === 0 ? 0 : 18;
      cells.push(
        <div key={`${row}-${col}`} className="hex-cell" style={{
          position: 'absolute',
          left: col * 36 + offset,
          top: row * 31,
          width: 32, height: 28,
          clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)',
          background: `rgba(139,92,246,${0.03 + Math.random() * 0.04})`,
          border: '0.5px solid rgba(139,92,246,0.06)',
          opacity: 0,
        }} />
      );
    }
  }

  return <div ref={ref} style={{ position: 'absolute', right: 40, bottom: 60, zIndex: 1, pointerEvents: 'none' }}>{cells}</div>;
};

const FloatingGlyphs: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const ctx = gsap.context(() => {
      const glyphs = ref.current!.querySelectorAll('.glyph');
      glyphs.forEach((g, i) => {
        gsap.to(g, {
          y: `+=${10 + Math.random() * 20}`,
          duration: 3 + Math.random() * 3,
          repeat: -1, yoyo: true, ease: 'sine.inOut',
          delay: i * 0.3,
        });
        gsap.to(g, { opacity: 0.08 + Math.random() * 0.12, duration: 4, repeat: -1, yoyo: true, ease: 'sine.inOut', delay: i * 0.5 });
      });
    });
    return () => ctx.revert();
  }, []);

  const symbols = ['⟐', '⬡', '◈', '⎔', '⏣', '⬢', '⏢', '⎊', '⍟', '⎈', '⌬', '⍟'];
  return (
    <div ref={ref} style={{ position: 'absolute', inset: 0, zIndex: 1, pointerEvents: 'none', overflow: 'hidden' }}>
      {symbols.map((s, i) => (
        <div key={i} className="glyph" style={{
          position: 'absolute',
          left: `${5 + Math.random() * 90}%`,
          top: `${5 + Math.random() * 90}%`,
          fontSize: 16 + Math.random() * 24,
          color: `rgba(139,92,246,0.06)`,
          fontFamily: 'monospace',
          opacity: 0.04,
          transform: `rotate(${Math.random() * 360}deg)`,
        }}>{s}</div>
      ))}
    </div>
  );
};

class LoginErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false };
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: '#07060E', color: '#8B5CF6', fontFamily: '"DM Sans", sans-serif',
        }}>
          页面加载异常，请刷新重试
        </div>
      );
    }
    return this.props.children;
  }
}

const Login: React.FC = () => {
  const message = useAntdMessage();
  const [username, setUsername] = useState(() => localStorage.getItem(REMEMBER_KEY) || '');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(() => !!localStorage.getItem(REMEMBER_KEY));
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const wrapRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const shieldRef = useRef<HTMLDivElement>(null);
  const badgeRef = useRef<HTMLDivElement>(null);
  const title1Ref = useRef<HTMLDivElement>(null);
  const title2Ref = useRef<HTMLDivElement>(null);
  const lineRef = useRef<HTMLDivElement>(null);
  const subRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const footRef = useRef<HTMLDivElement>(null);
  const scanRef = useRef<HTMLDivElement>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ defaults: { ease: 'expo.out' } });

      tl.fromTo(wrapRef.current, { opacity: 0 }, { opacity: 1, duration: 0.4 })
        .fromTo(cardRef.current,
          { opacity: 0, y: 60, scale: 0.92, rotateX: 8 },
          { opacity: 1, y: 0, scale: 1, rotateX: 0, duration: 1.4, ease: 'power4.out' },
          0.2
        )
        .fromTo(shieldRef.current,
          { opacity: 0, scale: 0, rotation: -270, filter: 'blur(10px)' },
          { opacity: 1, scale: 1, rotation: 0, filter: 'blur(0px)', duration: 1.6, ease: 'elastic.out(1, 0.4)' },
          0.5
        )
        .fromTo(badgeRef.current,
          { opacity: 0, y: -15, letterSpacing: '0.6em' },
          { opacity: 1, y: 0, letterSpacing: '0.2em', duration: 0.8 },
          0.9
        )
        .fromTo(title1Ref.current,
          { opacity: 0, y: 30, clipPath: 'inset(0 0 100% 0)', filter: 'blur(6px)' },
          { opacity: 1, y: 0, clipPath: 'inset(0 0 0% 0)', filter: 'blur(0px)', duration: 1 },
          1.0
        )
        .fromTo(title2Ref.current,
          { opacity: 0, y: 30, clipPath: 'inset(0 0 100% 0)', filter: 'blur(6px)' },
          { opacity: 1, y: 0, clipPath: 'inset(0 0 0% 0)', filter: 'blur(0px)', duration: 1 },
          1.15
        )
        .fromTo(lineRef.current,
          { scaleX: 0, opacity: 0 },
          { scaleX: 1, opacity: 1, duration: 1.2, ease: 'power4.out' },
          1.3
        )
        .fromTo(subRef.current,
          { opacity: 0, y: 12, filter: 'blur(4px)' },
          { opacity: 1, y: 0, filter: 'blur(0px)', duration: 0.7 },
          1.4
        );

      if (formRef.current) {
        tl.fromTo(formRef.current.querySelectorAll('[data-fi]'),
          { opacity: 0, y: 30, filter: 'blur(8px)' },
          { opacity: 1, y: 0, filter: 'blur(0px)', duration: 0.7, stagger: 0.09, ease: 'power3.out' },
          1.5
        );
      }

      tl.fromTo(footRef.current, { opacity: 0 }, { opacity: 1, duration: 0.6 }, 2.0)
        .fromTo(scanRef.current,
          { scaleX: 0 },
          { scaleX: 1, duration: 1.5, ease: 'power2.inOut', repeat: -1, yoyo: true, repeatDelay: 2 },
          2.2
        );

      gsap.to(shieldRef.current, {
        boxShadow: '0 0 60px rgba(139,92,246,0.5), 0 0 120px rgba(99,102,241,0.2)',
        duration: 3, repeat: -1, yoyo: true, ease: 'sine.inOut', delay: 2,
      });

      gsap.to(shieldRef.current, {
        rotation: 5, duration: 6, repeat: -1, yoyo: true, ease: 'sine.inOut', delay: 2,
      });

      gsap.to(cardRef.current, {
        boxShadow: '0 0 80px rgba(139,92,246,0.15), 0 30px 60px rgba(0,0,0,0.5)',
        duration: 5, repeat: -1, yoyo: true, ease: 'sine.inOut', delay: 1.5,
      });
    });

    return () => ctx.revert();
  }, []);

  useEffect(() => {
    return () => { mountedRef.current = false; };
  }, []);

  const handleLogin = useCallback(async () => {
    if (!username.trim() || !password.trim()) {
      message.warning('请输入用户名和密码');
      return;
    }
    setLoading(true);
    try {
      const res = await authApi.login(username, password);
      tokenStorage.setToken(res.access_token);
      tokenStorage.setUser(res.user);
      if (rememberMe) localStorage.setItem(REMEMBER_KEY, username.trim());
      else localStorage.removeItem(REMEMBER_KEY);

      gsap.to(cardRef.current, {
        opacity: 0, scale: 0.9, filter: 'blur(20px)', rotateX: -10,
        duration: 0.6, ease: 'power3.in',
        onComplete: () => {
          if (res.must_change_password) {
            message.warning('请修改默认密码后再继续使用');
            navigate('/settings?tab=profile');
          } else {
            navigate('/');
          }
        },
      });
    } catch (e) {
      message.error(getErrorMessage(e));
      if (formRef.current) {
        gsap.fromTo(formRef.current, { x: -12 },
          { x: 12, duration: 0.05, repeat: 6, yoyo: true, ease: 'power2.inOut',
            onComplete: () => gsap.to(formRef.current, { x: 0, duration: 0.15 }),
          }
        );
      }
      if (shieldRef.current) {
        gsap.fromTo(shieldRef.current, { filter: 'brightness(2) hue-rotate(30deg)' },
          { filter: 'brightness(1) hue-rotate(0deg)', duration: 0.4 }
        );
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [username, password, rememberMe, message, navigate]);

  return (
    <LoginErrorBoundary>
    <div ref={wrapRef} style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: '#07060E', position: 'relative', overflow: 'hidden', opacity: 0,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600;700;800&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@400;500;600;700;800&display=swap');

        .login-input .ant-input-affix-wrapper {
          background: rgba(20,18,40,0.6) !important;
          border: 1.5px solid rgba(139,92,246,0.12) !important;
          border-radius: 16px !important;
          height: 54px !important;
          font-size: 14px !important;
          font-family: 'DM Sans', sans-serif !important;
          color: #E2E0F0 !important;
          transition: all 0.4s cubic-bezier(0.22, 1, 0.36, 1) !important;
          padding: 0 20px !important;
          backdrop-filter: blur(16px) !important;
        }
        .login-input .ant-input-affix-wrapper:hover {
          border-color: rgba(139,92,246,0.3) !important;
          background: rgba(20,18,40,0.75) !important;
          box-shadow: 0 0 24px rgba(139,92,246,0.08) !important;
        }
        .login-input .ant-input-affix-wrapper-focused,
        .login-input .ant-input-affix-wrapper:focus-within {
          border-color: rgba(139,92,246,0.55) !important;
          box-shadow: 0 0 0 4px rgba(139,92,246,0.1), 0 0 40px rgba(139,92,246,0.12) !important;
          background: rgba(20,18,40,0.85) !important;
        }
        .login-input .ant-input {
          background: transparent !important; border: none !important;
          font-size: 14px !important; font-family: 'DM Sans', sans-serif !important;
          color: #E2E0F0 !important;
        }
        .login-input .ant-input::placeholder { color: #7C7F9A !important; }
        .login-input .ant-input-prefix {
          color: #7C7F9A !important; margin-right: 14px !important;
          font-size: 15px !important; transition: color 0.3s ease !important;
        }
        .login-input .ant-input-affix-wrapper-focused .ant-input-prefix,
        .login-input .ant-input-affix-wrapper:focus-within .ant-input-prefix {
          color: #A78BFA !important;
        }

        .login-btn {
          background: linear-gradient(135deg, #7C3AED 0%, #6366F1 40%, #8B5CF6 100%) !important;
          border: none !important; color: #FFFFFF !important;
          font-family: 'DM Sans', sans-serif !important;
          font-size: 15px !important; font-weight: 700 !important;
          border-radius: 16px !important; height: 54px !important;
          transition: all 0.4s cubic-bezier(0.22, 1, 0.36, 1) !important;
          letter-spacing: 0.08em !important;
          position: relative !important; overflow: hidden !important;
          box-shadow: 0 4px 24px rgba(124,58,237,0.3), inset 0 1px 0 rgba(255,255,255,0.1) !important;
        }
        .login-btn:hover {
          transform: translateY(-3px) !important;
          box-shadow: 0 8px 48px rgba(124,58,237,0.45), 0 0 80px rgba(139,92,246,0.2), inset 0 1px 0 rgba(255,255,255,0.15) !important;
          filter: brightness(1.1) !important;
        }
        .login-btn:active {
          transform: translateY(0) !important;
          box-shadow: 0 2px 12px rgba(124,58,237,0.2) !important;
        }
        .login-btn::before {
          content: '' !important; position: absolute !important;
          top: -50% !important; left: -50% !important;
          width: 200% !important; height: 200% !important;
          background: conic-gradient(from 0deg, transparent, rgba(255,255,255,0.1), transparent 30%) !important;
          animation: btnSpin 4s linear infinite !important;
        }
        @keyframes btnSpin { to { transform: rotate(360deg); } }

        .login-checkbox {
          accent-color: #8B5CF6 !important;
          width: 15px !important; height: 15px !important;
          cursor: pointer !important; border-radius: 4px !important;
        }

        .scan-line {
          position: absolute; top: 0; left: 0; right: 0; height: 1px;
          background: linear-gradient(90deg, transparent, rgba(139,92,246,0.4), transparent);
          transform-origin: left center;
        }
      `}</style>

      <AuroraCanvas />
      <HexGrid />
      <FloatingGlyphs />

      <div ref={cardRef} style={{
        position: 'relative', zIndex: 10,
        width: '100%', maxWidth: 460,
        padding: '56px 48px 48px',
        background: 'rgba(12,10,28,0.55)',
        border: '1px solid rgba(139,92,246,0.1)',
        borderRadius: 28,
        backdropFilter: 'blur(40px) saturate(1.5)',
        boxShadow: '0 0 60px rgba(139,92,246,0.08), 0 30px 60px rgba(0,0,0,0.4)',
        opacity: 0,
      }}>
        <div ref={scanRef} className="scan-line" style={{ transform: 'scaleX(0)' }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 40 }}>
          <div ref={shieldRef} style={{
            width: 56, height: 56, borderRadius: 18, flexShrink: 0,
            background: 'linear-gradient(135deg, #7C3AED 0%, #6366F1 50%, #8B5CF6 100%)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            opacity: 0,
            boxShadow: '0 0 30px rgba(139,92,246,0.3), inset 0 1px 0 rgba(255,255,255,0.15)',
          }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div>
            <div ref={badgeRef} style={{
              fontFamily: '"JetBrains Mono", monospace', fontSize: 10, fontWeight: 600,
              letterSpacing: '0.6em', textTransform: 'uppercase', color: '#8B5CF6',
              opacity: 0, marginBottom: 6,
            }}>
              NEXUS INTEL
            </div>
            <div style={{
              fontFamily: '"DM Sans", sans-serif', fontSize: 12, color: '#7C7F9A',
              letterSpacing: '0.04em',
            }}>
              THREAT INTELLIGENCE PLATFORM
            </div>
          </div>
        </div>

        <div ref={title1Ref} style={{ opacity: 0 }}>
          <div style={{
            fontFamily: '"Syne", sans-serif', fontSize: 38, fontWeight: 800,
            color: '#F0EEFF', lineHeight: 1.15, letterSpacing: '-0.02em',
          }}>
            黑灰产情报
          </div>
        </div>
        <div ref={title2Ref} style={{ opacity: 0 }}>
          <div style={{
            fontFamily: '"Syne", sans-serif', fontSize: 38, fontWeight: 800,
            lineHeight: 1.15, letterSpacing: '-0.02em',
            background: 'linear-gradient(135deg, #A78BFA 0%, #7C3AED 40%, #C084FC 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
          }}>
            分析平台
          </div>
        </div>

        <div ref={lineRef} style={{
          height: 2, marginTop: 24, borderRadius: 1,
          background: 'linear-gradient(90deg, #7C3AED, #8B5CF6, rgba(139,92,246,0.1), transparent)',
          transformOrigin: 'left center', transform: 'scaleX(0)', opacity: 0,
        }} />

        <div ref={subRef} style={{ opacity: 0 }}>
          <div style={{
            fontFamily: '"DM Sans", sans-serif', fontSize: 14, color: '#8B89A8',
            marginTop: 18, lineHeight: 1.7, fontWeight: 400,
          }}>
            登录以访问威胁情报分析平台
          </div>
        </div>

        <div ref={formRef} style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 36 }}>
          <div className="login-input" data-fi style={{ opacity: 0 }}>
            <Input prefix={<UserOutlined />} placeholder="用户名"
              value={username} onChange={e => setUsername(e.target.value)}
              onPressEnter={handleLogin} autoFocus aria-label="用户名" />
          </div>
          <div className="login-input" data-fi style={{ opacity: 0 }}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码"
              value={password} onChange={e => setPassword(e.target.value)}
              onPressEnter={handleLogin} aria-label="密码" />
          </div>
          <div data-fi style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', opacity: 0 }}>
            <label style={{
              display: 'flex', alignItems: 'center', gap: 9, fontSize: 13,
              color: '#8A87A8', cursor: 'pointer', userSelect: 'none',
              fontFamily: '"DM Sans", sans-serif', transition: 'color 0.3s ease',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#A78BFA'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#8A87A8'; }}
            >
              <input type="checkbox" className="login-checkbox" checked={rememberMe}
                onChange={e => setRememberMe(e.target.checked)} aria-label="记住我" />
              记住我
            </label>
            <span role="button" tabIndex={0} aria-label="忘记密码"
              style={{
                fontSize: 13, color: '#8A87A8', cursor: 'pointer',
                fontFamily: '"DM Sans", sans-serif', transition: 'color 0.3s ease',
              }}
              onMouseEnter={e => { e.currentTarget.style.color = '#A78BFA'; }}
              onMouseLeave={e => { e.currentTarget.style.color = '#8A87A8'; }}
              onClick={() => message.info('请联系系统管理员重置密码')}
              onKeyDown={e => { if (e.key === 'Enter') message.info('请联系系统管理员重置密码'); }}
            >忘记密码？</span>
          </div>
          <div data-fi style={{ opacity: 0, marginTop: 6 }}>
            <Button type="primary" block loading={loading} onClick={handleLogin} className="login-btn">
              登 录 系 统
            </Button>
          </div>
        </div>

        <div ref={footRef} style={{ opacity: 0 }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 28,
          }}>
            <div style={{
              width: 5, height: 5, borderRadius: '50%',
              background: '#34D399', boxShadow: '0 0 8px rgba(52,211,153,0.4)',
            }} />
            <span style={{
              fontSize: 10, color: '#8B89A8',
              fontFamily: '"JetBrains Mono", monospace', letterSpacing: '0.1em',
            }}>ENCRYPTED · SSL SECURE</span>
          </div>
          <div style={{
            textAlign: 'center', marginTop: 20, fontSize: 13, color: '#8B89A8',
            fontFamily: '"DM Sans", sans-serif',
          }}>
            还没有账号？{' '}
            <Link to="/register" style={{
              color: '#A78BFA', fontWeight: 600, textDecoration: 'none',
              transition: 'color 0.3s ease',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#C084FC'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#A78BFA'; }}
            >
              立即注册
            </Link>
          </div>
        </div>
      </div>
    </div>
    </LoginErrorBoundary>
  );
};

export default Login;
