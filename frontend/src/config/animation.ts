interface FluidBackgroundConfig {
  layer1Duration: number;
  layer2Duration: number;
  layer2Paths: number;
  layer3Duration: number;
  layer3Particles: number;
  colors: { r: number; g: number; b: number; weight: number }[];
  amplitude: { min: number; max: number };
}

interface AnimationConfig {
  pageTransition: {
    enterDuration: number;
    exitDuration: number;
    enterY: number;
    exitY: number;
    enterEase: string;
    exitEase: string;
  };
  stagger: {
    default: number;
    tight: number;
    loose: number;
  };
  enter: {
    opacity: number;
    y: number;
    scale: number;
    duration: number;
    ease: string;
  };
  exit: {
    opacity: number;
    y: number;
    duration: number;
    ease: string;
  };
  micro: {
    hoverScale: number;
    pressScale: number;
    hoverDuration: number;
    pressDuration: number;
    glowColor: string;
    glowSize: number;
    shakeAmplitude: number;
    shakeRepeats: number;
  };
  modal: {
    enterScale: number;
    duration: number;
    ease: string;
  };
  statCard: {
    enterScale: number;
    duration: number;
    counterDuration: number;
    ease: string;
  };
  chart: {
    drawDuration: number;
    hoverScale: number;
    glowIntensity: number;
  };
  listRow: {
    fadeInDuration: number;
    staggerDelay: number;
  };
  fluidBg: FluidBackgroundConfig;
  search: {
    expandWidth: number;
    collapsedWidth: number;
    duration: number;
  };
  sidebar: {
    width: number;
    collapsedWidth: number;
    transitionDuration: number;
  };
  perf: {
    fpsThreshold: number;
    recoverThreshold: number;
    degradeDuration: number;
    recoverDuration: number;
  };
}

export const ANIM_CONFIG: AnimationConfig = {
  pageTransition: {
    enterDuration: 0.3,
    exitDuration: 0.25,
    enterY: 20,
    exitY: -12,
    enterEase: 'power2.out',
    exitEase: 'power2.in',
  },
  stagger: {
    default: 0.06,
    tight: 0.03,
    loose: 0.1,
  },
  enter: {
    opacity: 0,
    y: 20,
    scale: 0.95,
    duration: 0.5,
    ease: 'back.out(1.4)',
  },
  exit: {
    opacity: 0,
    y: -12,
    duration: 0.25,
    ease: 'power2.in',
  },
  micro: {
    hoverScale: 1.02,
    pressScale: 0.95,
    hoverDuration: 0.2,
    pressDuration: 0.1,
    glowColor: 'rgba(30, 64, 175, 0.15)',
    glowSize: 12,
    shakeAmplitude: 8,
    shakeRepeats: 3,
  },
  modal: {
    enterScale: 0.9,
    duration: 0.3,
    ease: 'back.out(1.4)',
  },
  statCard: {
    enterScale: 0.8,
    duration: 0.5,
    counterDuration: 1.2,
    ease: 'back.out(1.4)',
  },
  chart: {
    drawDuration: 0.6,
    hoverScale: 1.3,
    glowIntensity: 0.4,
  },
  listRow: {
    fadeInDuration: 0.2,
    staggerDelay: 0.03,
  },
  fluidBg: {
    layer1Duration: 30,
    layer2Duration: 8,
    layer2Paths: 4,
    layer3Duration: 6,
    layer3Particles: 40,
    colors: [
      { r: 30, g: 64, b: 175, weight: 0.4 },
      { r: 8, g: 145, b: 178, weight: 0.3 },
      { r: 5, g: 150, b: 105, weight: 0.2 },
      { r: 124, g: 58, b: 237, weight: 0.1 },
    ],
    amplitude: { min: 30, max: 80 },
  },
  search: {
    expandWidth: 360,
    collapsedWidth: 280,
    duration: 0.25,
  },
  sidebar: {
    width: 220,
    collapsedWidth: 64,
    transitionDuration: 0.2,
  },
  perf: {
    fpsThreshold: 24,
    recoverThreshold: 30,
    degradeDuration: 3000,
    recoverDuration: 5000,
  },
};

export const PAGE_ENTER = ANIM_CONFIG.enter;
export const PAGE_EXIT = ANIM_CONFIG.exit;
export const STAGGER_DEFAULT = ANIM_CONFIG.stagger.default;
export const MICRO = ANIM_CONFIG.micro;
export const FLUID_BG = ANIM_CONFIG.fluidBg;
