export type BloomXSameSite = "lax" | "strict" | "none";

export interface BloomXCookieConfig {
    name: string;
    domain?: string;
    path?: string;
    secure?: boolean;
    sameSite?: BloomXSameSite;
    maxAge?: number;
}

export interface BloomXOAuthConfig {
    authOrigin: string;
    sessionPath?: string;
    loginPath?: string;
    logoutPath?: string;
    allowedOrigins: string[];
    cookie: BloomXCookieConfig;
    defaultReturnPath?: string;
}

export interface BloomXLoginOptions {
    origin?: string;
    returnTo?: string;
    prompt?: string;
    extraParams?: Record<string, string>;
}

export interface BloomXLogoutOptions {
    origin?: string;
    returnTo?: string;
}

export interface BloomXSession {
    id?: string;
    email?: string;
    name?: string;
    [key: string]: unknown;
}

export interface BloomXFetchOptions {
    fetcher?: typeof fetch;
}

export interface BloomXSessionClient {
    getSession: () => Promise<BloomXSession | null>;
    login: (options?: BloomXLoginOptions) => void;
    logout: (options?: BloomXLogoutOptions) => void;
}