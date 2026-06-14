import { useRef, useCallback } from 'react';
import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

export function useButtonMicroAnim() {
  const ref = useRef<HTMLDivElement>(null);
  const ctxRef = useRef<gsap.Context | null>(null);

  useGSAP(() => {
    if (!ref.current) return;
    ctxRef.current = gsap.context(() => {}, ref.current);
    return () => { ctxRef.current?.revert(); };
  }, { scope: ref });

  const onMouseEnter = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      scale: ANIM_CONFIG.micro.hoverScale,
      duration: ANIM_CONFIG.micro.hoverDuration,
      ease: 'power2.out',
    });
  }, []);

  const onMouseLeave = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      scale: 1,
      duration: ANIM_CONFIG.micro.hoverDuration,
      ease: 'power2.out',
    });
  }, []);

  const onMouseDown = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      scale: ANIM_CONFIG.micro.pressScale,
      duration: ANIM_CONFIG.micro.pressDuration,
      ease: 'power2.out',
    });
  }, []);

  const onMouseUp = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      scale: ANIM_CONFIG.micro.hoverScale,
      duration: ANIM_CONFIG.micro.hoverDuration,
      ease: 'back.out(2)',
    });
  }, []);

  return { ref, onMouseEnter, onMouseLeave, onMouseDown, onMouseUp };
}

export function useFocusGlowAnim(color?: string) {
  const ref = useRef<HTMLInputElement | HTMLDivElement>(null);
  const glowColor = color ?? ANIM_CONFIG.micro.glowColor;

  const onFocus = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      boxShadow: `0 0 0 ${ANIM_CONFIG.micro.glowSize}px ${glowColor}`,
      scale: 1.02,
      duration: 0.2,
      ease: 'power2.out',
    });
  }, [glowColor]);

  const onBlur = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      boxShadow: '0 0 0 0px transparent',
      scale: 1,
      duration: 0.2,
      ease: 'power2.out',
    });
  }, []);

  return { ref, onFocus, onBlur };
}

export function useCardHoverAnim(color?: string) {
  const ref = useRef<HTMLDivElement>(null);
  const cardColor = color ?? 'rgba(30, 64, 175, 0.12)';

  const onMouseEnter = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      y: -2,
      boxShadow: `0 8px 24px -4px ${cardColor}, 0 4px 8px -2px rgba(12,14,18,0.04)`,
      duration: 0.25,
      ease: 'power2.out',
    });
    const border = ref.current.querySelector('.card-gradient-border::before') as HTMLElement | null;
    if (border) {
      gsap.to(border, { opacity: 1, duration: 0.25 });
    }
  }, [cardColor]);

  const onMouseLeave = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      y: 0,
      boxShadow: 'var(--shadow-card)',
      duration: 0.25,
      ease: 'power2.out',
    });
  }, []);

  return { ref, onMouseEnter, onMouseLeave };
}

export function useHoverShiftAnim(direction: 'x' | 'y' = 'x', distance: number = -2) {
  const ref = useRef<HTMLDivElement>(null);

  const onMouseEnter = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      [direction]: distance,
      duration: 0.2,
      ease: 'power2.out',
    });
  }, [direction, distance]);

  const onMouseLeave = useCallback(() => {
    if (!ref.current) return;
    gsap.to(ref.current, {
      [direction]: 0,
      duration: 0.2,
      ease: 'power2.out',
    });
  }, [direction]);

  return { ref, onMouseEnter, onMouseLeave };
}

export function usePulseGlowAnim(color?: string, duration?: number) {
  const ref = useRef<HTMLDivElement>(null);
  const glowColor = color ?? 'rgba(30, 64, 175, 0.3)';
  const dur = duration ?? 2;
  let tween: gsap.core.Tween | null = null;

  const start = useCallback(() => {
    if (!ref.current) return;
    tween = gsap.to(ref.current, {
      boxShadow: `0 0 20px ${glowColor}`,
      duration: dur / 2,
      ease: 'sine.inOut',
      yoyo: true,
      repeat: -1,
    });
  }, [glowColor, dur]);

  const stop = useCallback(() => {
    tween?.kill();
    tween = null;
    if (ref.current) {
      gsap.to(ref.current, {
        boxShadow: '0 0 0px transparent',
        duration: 0.3,
      });
    }
  }, []);

  return { ref, start, stop };
}

export function useShakeAnim() {
  const ref = useRef<HTMLDivElement>(null);

  const shake = useCallback(() => {
    if (!ref.current) return;
    gsap.fromTo(ref.current,
      { x: 0 },
      {
        x: ANIM_CONFIG.micro.shakeAmplitude,
        duration: 0.04,
        ease: 'power2.inOut',
        repeat: ANIM_CONFIG.micro.shakeRepeats * 2 - 1,
        yoyo: true,
        onComplete: () => {
          gsap.set(ref.current!, { x: 0 });
        },
      }
    );
  }, []);

  return { ref, shake };
}
