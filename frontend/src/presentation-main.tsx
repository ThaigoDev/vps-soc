// Entry of the standalone presentation (npm run build:presentation): one HTML file that
// works offline, opened straight from disk. Dark theme, no dashboard, no API.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import Presentation from './pages/Presentation'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MemoryRouter>
      <Presentation standalone />
    </MemoryRouter>
  </StrictMode>,
)
