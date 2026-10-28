// Lucide icons by role (tokens.json `icon.glyph.web`), 1.5px stroke, grey, never in a tinted
// circle (§2.5). Icons are imported individually so the bundle only carries the ones used.
import type { Component, JSX } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import {
  ArrowDown,
  ArrowLeft,
  ArrowLeftRight,
  ArrowRight,
  Bot,
  Camera,
  Check,
  ChevronDown,
  ChevronRight,
  CircleArrowRight,
  CircleDot,
  CircleX,
  Code,
  Columns2,
  Command,
  Copy,
  Crosshair,
  Download,
  Ellipsis,
  Eye,
  Flag,
  Folder,
  Globe,
  Hand,
  Image,
  LayoutGrid,
  ListFilter,
  Lock,
  LockOpen,
  MessageSquare,
  Minus,
  PanelBottom,
  PanelLeft,
  PanelRight,
  Pause,
  Pencil,
  Pin,
  Play,
  Plus,
  RotateCcw,
  RotateCw,
  Search,
  Shield,
  SquarePen,
  Terminal,
  Trash2,
  TriangleAlert,
  X,
} from 'lucide-solid';

const ICONS = {
  'arrow-down': ArrowDown,
  'arrow-left': ArrowLeft,
  'arrow-left-right': ArrowLeftRight,
  'arrow-right': ArrowRight,
  bot: Bot,
  camera: Camera,
  check: Check,
  'chevron-down': ChevronDown,
  'chevron-right': ChevronRight,
  'circle-arrow-right': CircleArrowRight,
  'circle-dot': CircleDot,
  'circle-x': CircleX,
  code: Code,
  'columns-2': Columns2,
  command: Command,
  copy: Copy,
  crosshair: Crosshair,
  download: Download,
  ellipsis: Ellipsis,
  eye: Eye,
  flag: Flag,
  folder: Folder,
  globe: Globe,
  hand: Hand,
  image: Image,
  'layout-grid': LayoutGrid,
  'list-filter': ListFilter,
  lock: Lock,
  'lock-open': LockOpen,
  'message-square': MessageSquare,
  minus: Minus,
  'panel-bottom': PanelBottom,
  'panel-left': PanelLeft,
  'panel-right': PanelRight,
  pause: Pause,
  pencil: Pencil,
  pin: Pin,
  play: Play,
  plus: Plus,
  'rotate-ccw': RotateCcw,
  'rotate-cw': RotateCw,
  search: Search,
  shield: Shield,
  'square-pen': SquarePen,
  terminal: Terminal,
  'trash-2': Trash2,
  'triangle-alert': TriangleAlert,
  x: X,
} as const;

export type IconName = keyof typeof ICONS;
export type IconSize = 12 | 16 | 18;

export interface IconProps {
  name: IconName;
  /** 16 in bars (default), 12 inline, 18 for the toolbar's record control. */
  size?: IconSize | undefined;
  class?: string | undefined;
  /** Accessible name; without it the icon is decorative (`aria-hidden`). */
  label?: string | undefined;
  style?: JSX.CSSProperties | undefined;
}

export const Icon: Component<IconProps> = (props) => {
  const px = () => `${props.size ?? 16}px`;
  return (
    <Dynamic
      component={ICONS[props.name]}
      size={props.size ?? 16}
      strokeWidth={1.5}
      aria-hidden={props.label ? undefined : true}
      aria-label={props.label}
      role={props.label ? 'img' : undefined}
      class={props.class ?? ''}
      style={{ width: px(), height: px(), ...props.style }}
    />
  );
};
