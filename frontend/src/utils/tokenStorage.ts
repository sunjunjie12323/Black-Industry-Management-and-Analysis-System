const TOKEN_KEY = 'tia_token';
const USER_KEY = 'tia_user';
const TOKEN_EXPIRY_KEY = 'tia_token_expiry';
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000;

function isValidJwtFormat(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3 && parts.every(p => p.length > 0);
}

export const tokenStorage = {
  getToken(): string | null {
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) return null;
    const expiry = sessionStorage.getItem(TOKEN_EXPIRY_KEY);
    if (expiry && Date.now() > parseInt(expiry, 10)) {
      tokenStorage.clear();
      return null;
    }
    return token;
  },

  setToken(token: string): void {
    if (!isValidJwtFormat(token) && token !== 'guest') return;
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(TOKEN_EXPIRY_KEY, (Date.now() + TOKEN_EXPIRY_MS).toString());
  },

  getUser<T>(): T | null {
    const raw = sessionStorage.getItem(USER_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      sessionStorage.removeItem(USER_KEY);
      return null;
    }
  },

  setUser(user: unknown): void {
    sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  },

  clear(): void {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
    sessionStorage.removeItem(USER_KEY);
  },

  isTokenExpired(): boolean {
    const expiry = sessionStorage.getItem(TOKEN_EXPIRY_KEY);
    if (!expiry) return true;
    return Date.now() > parseInt(expiry, 10);
  },
};
