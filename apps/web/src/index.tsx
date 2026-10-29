/* @refresh reload */
import { render } from 'solid-js/web';
import './styles/tokens.css';
import './styles/base.css';
import App from './App';

const root = document.getElementById('root');
if (!root) throw new Error('#root missing');
render(() => <App />, root);
