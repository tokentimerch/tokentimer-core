// Import logger first to override console globally
import './utils/logger.js';
// Install global error/rejection handlers before anything else
import './utils/globalErrors.js';

import React from 'react';
// Load brand CSS variables and font families globally
import './styles/brand.css';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import { BrowserRouter } from 'react-router-dom';

const RootTree = (
  <BrowserRouter>
    <App />
  </BrowserRouter>
);

ReactDOM.createRoot(document.getElementById('root')).render(
  import.meta.env?.MODE === 'production' ? (
    <React.StrictMode>{RootTree}</React.StrictMode>
  ) : (
    RootTree
  )
);
