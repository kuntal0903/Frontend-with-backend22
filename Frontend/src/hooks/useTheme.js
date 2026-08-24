import { useState, useEffect, useCallback } from 'react';

const STORAGE_KEY  = 'asm-theme';
const DEFAULT_THEME = 'dark';
const VALID_THEMES  = ['dark', 'light', 'blue'];

function applyTheme(theme) {
  const safe = VALID_THEMES.includes(theme) ? theme : DEFAULT_THEME;
  document.documentElement.setAttribute('data-theme', safe);
  localStorage.setItem(STORAGE_KEY, safe);
}

function getSavedTheme() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return VALID_THEMES.includes(saved) ? saved : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

export function useTheme() {
  const [theme, setThemeState] = useState(() => {
    const saved = getSavedTheme();
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', saved);
    }
    return saved;
  });

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((newTheme) => {
    if (VALID_THEMES.includes(newTheme)) {
      setThemeState(newTheme);
    }
  }, []);

  return { theme, setTheme, themes: VALID_THEMES };
}

export { applyTheme, getSavedTheme };
