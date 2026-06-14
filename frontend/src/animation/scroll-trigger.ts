import { useRef, useEffect } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { ANIM_CONFIG } from '../config/animation';

gsap.registerPlugin(ScrollTrigger);

interface ScrollEnterOptions {
  selector?: string;
  fromVars?: gsap.TweenVars;
  toVars?: gsap.TweenVars;
  stagger?: number;
  start?: string;
}

export function useScrollEnter(options?: ScrollEnterOptions) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;

    const targets = options?.selector
      ? ref.current.querySelectorAll(options?.selector)
      : ref.current;

    if (!targets || (targets instanceof NodeList && targets.length === 0)) return;

    const tween = gsap.fromTo(
      targets,
      {
        opacity: 0,
        y: ANIM_CONFIG.enter.y,
        ...options?.fromVars,
      },
      {
        opacity: 1,
        y: 0,
        duration: ANIM_CONFIG.enter.duration,
        stagger: options?.stagger ?? ANIM_CONFIG.stagger.default,
        ease: ANIM_CONFIG.enter.ease,
        scrollTrigger: {
          trigger: ref.current,
          start: options?.start ?? 'top 80%',
          toggleActions: 'play none none none',
        },
        ...options?.toVars,
      }
    );

    return () => {
      tween.scrollTrigger?.kill();
      tween.kill();
    };
  }, []);

  return ref;
}

export function batchScrollEnter(
  containers: Element[],
  options?: {
    selector?: string;
    fromVars?: gsap.TweenVars;
    toVars?: gsap.TweenVars;
    stagger?: number;
  }
): void {
  ScrollTrigger.batch(containers, {
    onEnter: (batch) => {
      gsap.fromTo(batch, {
        opacity: 0,
        y: ANIM_CONFIG.enter.y,
        ...options?.fromVars,
      }, {
        opacity: 1,
        y: 0,
        duration: ANIM_CONFIG.enter.duration,
        stagger: options?.stagger ?? ANIM_CONFIG.stagger.tight,
        ease: ANIM_CONFIG.enter.ease,
        ...options?.toVars,
      });
    },
    start: 'top 85%',
    batchMax: 8,
  });
}

export { ScrollTrigger };
