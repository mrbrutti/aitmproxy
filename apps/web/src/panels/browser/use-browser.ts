import { useApp } from '~/state/context';
import { browserState, type BrowserState } from './state';

/** The Browser view's shared state for the current app store. */
export const useBrowser = (): BrowserState => browserState(useApp());
