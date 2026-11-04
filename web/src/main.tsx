import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiError } from '@/lib/api'
import { AuthProvider } from '@/state/auth'
import { ThemeProvider } from '@/state/theme'
import { ToastProvider } from '@/components/ui/Toast'
import App from '@/App'
import '@/index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Results stream in over the WebSocket, so aggressive polling is not
      // needed; a short stale time still covers tab switches.
      staleTime: 10_000,
      gcTime: 10 * 60_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
          return false
        }
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ToastProvider>
          <AuthProvider>
            <BrowserRouter
              future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            >
              <App />
            </BrowserRouter>
          </AuthProvider>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </StrictMode>,
)
