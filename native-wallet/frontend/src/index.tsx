import { createRoot } from 'react-dom/client';
import './style.css';
import { CardStoreProvider } from './stores/CardStore';

import App from './App';

const container = document.getElementById('root');

const root = createRoot(container!);

root.render(
  <CardStoreProvider>
    <App />
  </CardStoreProvider>
);
