import React, { useRef, useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate, Routes, Route } from 'react-router-dom';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

interface AnimateRoutesProps {
  children: React.ReactNode;
}

const AnimateRoutes: React.FC<AnimateRoutesProps> = ({ children }) => {
  const location = useLocation();
  const containerRef = useRef<HTMLDivElement>(null);
  const [displayChildren, setDisplayChildren] = useState(children);
  const [transitioning, setTransitioning] = useState(false);
  const lastLocationRef = useRef(location.pathname);

  const animateOut = useCallback(() => {
    return new Promise<void>((resolve) => {
      if (!containerRef.current) { resolve(); return; }
      gsap.to(containerRef.current, {
        opacity: 0,
        y: ANIM_CONFIG.pageTransition.exitY,
        duration: ANIM_CONFIG.pageTransition.exitDuration,
        ease: ANIM_CONFIG.pageTransition.exitEase,
        onComplete: resolve,
      });
    });
  }, []);

  const animateIn = useCallback(() => {
    return new Promise<void>((resolve) => {
      if (!containerRef.current) { resolve(); return; }
      gsap.fromTo(containerRef.current,
        { opacity: 0, y: ANIM_CONFIG.pageTransition.enterY },
        {
          opacity: 1,
          y: 0,
          duration: ANIM_CONFIG.pageTransition.enterDuration,
          ease: ANIM_CONFIG.pageTransition.enterEase,
          onComplete: resolve,
        }
      );
    });
  }, []);

  useEffect(() => {
    if (location.pathname !== lastLocationRef.current) {
      lastLocationRef.current = location.pathname;

      if (transitioning) {
        gsap.killTweensOf(containerRef.current);
      }

      setTransitioning(true);
      if (containerRef.current) {
        containerRef.current.style.pointerEvents = 'none';
      }

      animateOut().then(() => {
        setDisplayChildren(children);
        requestAnimationFrame(() => {
          animateIn().then(() => {
            setTransitioning(false);
            if (containerRef.current) {
              containerRef.current.style.pointerEvents = 'auto';
            }
          });
        });
      });
    }
  }, [location.pathname]);

  return (
    <div ref={containerRef} style={{ willChange: 'opacity, transform' }}>
      {displayChildren}
    </div>
  );
};

export default AnimateRoutes;
