import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@solidjs/testing-library';
import { Menu, type MenuEntry } from './Menu';

const anchor = { left: 10, top: 10, right: 60, bottom: 30 };

function items(onRed: () => void, onReplay: () => void): MenuEntry[] {
  return [
    { label: 'Replay', kbd: 'r', onSelect: onReplay },
    { type: 'separator' },
    {
      label: 'Mark',
      children: [
        { label: 'Red', swatch: 'red', onSelect: onRed },
        { label: 'Blue', swatch: 'blue', onSelect: () => {} },
      ],
    },
  ];
}

afterEach(() => cleanup());

describe('Menu', () => {
  it('closes the whole tree when a submenu item is clicked', () => {
    const onClose = vi.fn();
    const onRed = vi.fn();
    render(() => <Menu anchor={anchor} items={items(onRed, () => {})} onClose={onClose} label="Row" />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Mark' }));
    const sub = screen.getAllByRole('menu').find((m) => m.getAttribute('data-parent'));
    expect(sub).toBeTruthy();
    fireEvent.click(screen.getByRole('menuitem', { name: 'Red' }));
    expect(onRed).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1); // the root closes, not only the submenu
  });

  it('closes the whole tree when a submenu item is chosen from the keyboard', () => {
    const onClose = vi.fn();
    const onRed = vi.fn();
    render(() => <Menu anchor={anchor} items={items(onRed, () => {})} onClose={onClose} animate={false} label="Row" />);
    const root = screen.getByRole('menu', { name: 'Row' });
    fireEvent.keyDown(root, { key: 'ArrowDown' }); // Replay → Mark
    fireEvent.keyDown(root, { key: 'ArrowRight' });
    const sub = screen.getAllByRole('menu').find((m) => m.getAttribute('data-parent'))!;
    expect(sub).toBeTruthy();
    fireEvent.keyDown(sub, { key: 'Enter' }); // first submenu item is active for keyboard-opened menus
    expect(onRed).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('ArrowLeft only closes the submenu; a top-level item closes the menu', () => {
    const onClose = vi.fn();
    const onReplay = vi.fn();
    render(() => <Menu anchor={anchor} items={items(() => {}, onReplay)} onClose={onClose} animate={false} label="Row" />);
    const root = screen.getByRole('menu', { name: 'Row' });
    fireEvent.keyDown(root, { key: 'ArrowDown' });
    fireEvent.keyDown(root, { key: 'ArrowRight' });
    const sub = screen.getAllByRole('menu').find((m) => m.getAttribute('data-parent'))!;
    fireEvent.keyDown(sub, { key: 'ArrowLeft' });
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getAllByRole('menu')).toHaveLength(1);
    fireEvent.click(screen.getByRole('menuitem', { name: /Replay/ }));
    expect(onReplay).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
