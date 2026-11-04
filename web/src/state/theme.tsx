import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'nety.theme'

interface ThemeContextValue {
  theme: Theme
  /** True when the theme follows the OS rather than an explicit choice. */
  isSystem: boolean
  setTheme: (t: Theme) => void
  toggle: () => void
  useSystem: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function systemTheme(): Theme {
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    return v === 'dark' || v === 'light' ? v : null
  } catch {
    return null
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [explicit, setExplicit] = useState<Theme | null>(() => stored())
  const [system, setSystem] = useState<Theme>(() => systemTheme())
  const theme = explicit ?? system

  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: light)')
    if (!mq) return
    const onChange = () => setSystem(systemTheme())
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  const setTheme = useCallback((t: Theme) => {
    setExplicit(t)
    try {
      localStorage.setItem(STORAGE_KEY, t)
    } catch {
      /* private mode: the theme simply will not persist */
    }
  }, [])

  const useSystemTheme = useCallback(() => {
    setExplicit(null)
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* ignore */
    }
  }, [])

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      isSystem: explicit === null,
      setTheme,
      toggle: () => setTheme(theme === 'dark' ? 'light' : 'dark'),
      useSystem: useSystemTheme,
    }),
    [theme, explicit, setTheme, useSystemTheme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used inside a ThemeProvider')
  return ctx
}
