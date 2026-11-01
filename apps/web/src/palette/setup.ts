// The palette's Setup group: the handful of operator actions that are not bus commands with a
// form of their own. Labels read the current state so the action says what it will do.
import type { AppStore, Density } from '~/state/app';
import { caInstallArgs } from '~/state/caTrust';
import type { SetupAction } from './groups';

const DENSITY_NEXT: Record<Density, Density> = { dense: 'default', default: 'comfortable', comfortable: 'dense' };

function effectiveTheme(app: AppStore): 'light' | 'dark' {
  if (app.ui.theme !== 'system') return app.ui.theme;
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function setupActions(app: AppStore, close: () => void): SetupAction[] {
  const hasTool = (n: string) => app.proxy.tools.some((t) => t.name === n);
  const theme = effectiveTheme(app);
  const list: SetupAction[] = [];
  if (hasTool('ca.install'))
    list.push({
      id: 'install-ca',
      label: 'Trust the aitmproxy CA',
      hint: 'Install the root CA into your user trust store; HTTPS is not captured until then',
      icon: 'lock',
      tool: 'ca.install',
      args: caInstallArgs(app.ca),
    });
  list.push(
    {
      id: 'add-scope',
      label: 'Add host to scope',
      hint: 'Authorise a host, host:port or *.wildcard',
      icon: 'crosshair',
      run: () => {
        app.setSidebar({ kind: 'scope' });
        app.setPanel('scope');
        close();
      },
    },
    {
      id: 'open-browser',
      label: 'Open browser',
      hint: 'The embedded browser panel',
      icon: 'globe',
      run: () => {
        app.setPanel('browser');
        close();
      },
    },
    {
      id: 'intercept',
      label: app.proxy.armed ? 'Disarm intercept' : 'Arm intercept',
      hint: app.proxy.armed ? 'Let requests through again' : 'Pause every request before it reaches upstream',
      icon: 'hand',
      run: () => {
        void app.arm(!app.proxy.armed);
        close();
      },
    },
    {
      id: 'theme',
      label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
      hint: 'Toggle theme',
      icon: 'circle-dot',
      run: () => app.setTheme(theme === 'dark' ? 'light' : 'dark'),
    },
    {
      id: 'density',
      label: `Density: ${DENSITY_NEXT[app.ui.density]}`,
      hint: `Toggle density (now ${app.ui.density})`,
      icon: 'layout-grid',
      run: () => app.setDensity(DENSITY_NEXT[app.ui.density]),
    },
    {
      id: 'layout',
      label: app.ui.layout === 'horizontal' ? 'Inspector on the right' : 'Inspector below',
      hint: 'Toggle layout',
      icon: app.ui.layout === 'horizontal' ? 'panel-right' : 'panel-bottom',
      run: () => app.setLayout(app.ui.layout === 'horizontal' ? 'vertical' : 'horizontal'),
    },
  );
  return list;
}
