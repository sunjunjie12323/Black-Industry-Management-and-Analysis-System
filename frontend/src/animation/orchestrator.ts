import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

class GSAPOrchestrator {
  private timelines: Map<string, gsap.core.Timeline> = new Map();
  private contextRef: gsap.Context | null = null;

  createTimeline(id: string, vars?: gsap.TimelineVars): gsap.core.Timeline {
    const tl = gsap.timeline(vars);
    this.timelines.set(id, tl);
    return tl;
  }

  createPageEnterTimeline(
    container: HTMLElement,
    selector: string = '[data-animate]',
    options?: { stagger?: number; fromVars?: gsap.TweenVars; toVars?: gsap.TweenVars }
  ): gsap.core.Timeline {
    const targets = container.querySelectorAll(selector);
    if (targets.length === 0) return gsap.timeline();

    const tl = this.createTimeline('pageEnter', {
      defaults: { ease: ANIM_CONFIG.pageTransition.enterEase },
    });

    tl.fromTo(
      targets,
      {
        opacity: 0,
        y: ANIM_CONFIG.pageTransition.enterY,
        ...(options?.fromVars || {}),
      },
      {
        opacity: 1,
        y: 0,
        duration: ANIM_CONFIG.pageTransition.enterDuration,
        stagger: options?.stagger ?? ANIM_CONFIG.stagger.default,
        ...(options?.toVars || {}),
      }
    );

    return tl;
  }

  createPageExitTimeline(container: HTMLElement): gsap.core.Timeline {
    const tl = this.createTimeline('pageExit');
    tl.to(container, {
      opacity: 0,
      y: ANIM_CONFIG.pageTransition.exitY,
      duration: ANIM_CONFIG.pageTransition.exitDuration,
      ease: ANIM_CONFIG.pageTransition.exitEase,
    });
    return tl;
  }

  animateCounter(
    obj: Record<string, number>,
    key: string,
    targetValue: number,
    options?: { prefix?: string; suffix?: string; duration?: number; ease?: string; onUpdate?: (val: number) => void }
  ): gsap.core.Tween {
    return gsap.to(obj, {
      [key]: targetValue,
      duration: options?.duration ?? ANIM_CONFIG.statCard.counterDuration,
      ease: options?.ease ?? 'power2.out',
      onUpdate: () => {
        options?.onUpdate?.(obj[key]);
      },
    });
  }

  staggerEnter(
    targets: Element[] | NodeListOf<Element>,
    options?: {
      fromVars?: gsap.TweenVars;
      toVars?: gsap.TweenVars;
      stagger?: number;
    }
  ): gsap.core.Timeline {
    const tl = this.createTimeline('staggerEnter');
    tl.fromTo(targets, {
      opacity: 0,
      y: ANIM_CONFIG.enter.y,
      ...options?.fromVars,
    }, {
      opacity: 1,
      y: 0,
      duration: ANIM_CONFIG.enter.duration,
      stagger: options?.stagger ?? ANIM_CONFIG.stagger.default,
      ease: ANIM_CONFIG.enter.ease,
      ...options?.toVars,
    });
    return tl;
  }

  register(id: string, timeline: gsap.core.Timeline): void {
    this.timelines.set(id, timeline);
  }

  get(id: string): gsap.core.Timeline | undefined {
    return this.timelines.get(id);
  }

  kill(id: string): void {
    const tl = this.timelines.get(id);
    if (tl) {
      tl.kill();
      this.timelines.delete(id);
    }
  }

  cleanup(): void {
    this.timelines.forEach((tl) => tl.kill());
    this.timelines.clear();
    if (this.contextRef) {
      this.contextRef.revert();
      this.contextRef = null;
    }
  }

  setContext(ctx: gsap.Context): void {
    this.contextRef = ctx;
  }
}

export const orchestrator = new GSAPOrchestrator();
export default GSAPOrchestrator;
