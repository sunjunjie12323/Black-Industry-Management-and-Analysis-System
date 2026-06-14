import React, { useRef, useEffect } from 'react';
import { Drawer } from 'antd';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

interface AnimatedDrawerProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  width?: number;
  placement?: 'left' | 'right' | 'top' | 'bottom';
}

const AnimatedDrawer: React.FC<AnimatedDrawerProps> = ({
  open, onClose, title, children,
  width = 480, placement = 'right',
}) => {
  const prevOpen = useRef(false);

  useEffect(() => {
    const drawerBody = document.querySelector('.ant-drawer-content-wrapper') as HTMLElement;
    if (!drawerBody) return;

    if (open && !prevOpen.current) {
      prevOpen.current = true;
      const fromX = placement === 'left' ? '-100%' : placement === 'right' ? '100%' : '0';
      const fromY = placement === 'top' ? '-100%' : placement === 'bottom' ? '100%' : '0';

      gsap.fromTo(drawerBody,
        { x: fromX, y: fromY, opacity: 0 },
        { x: '0%', y: '0%', opacity: 1, duration: ANIM_CONFIG.modal.duration, ease: ANIM_CONFIG.modal.ease }
      );
    } else if (!open && prevOpen.current) {
      prevOpen.current = false;
    }
  }, [open, placement]);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title}
      width={width}
      placement={placement}
      destroyOnHidden
    >
      {children}
    </Drawer>
  );
};

export default AnimatedDrawer;
