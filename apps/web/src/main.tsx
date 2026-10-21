import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import { captureLinkToken } from './lib/link-token'
import './index.css'
import App from './App.tsx'

const initialToken = captureLinkToken(window.location, window.history)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter><App initialToken={initialToken} /></BrowserRouter>
  </StrictMode>,
)
