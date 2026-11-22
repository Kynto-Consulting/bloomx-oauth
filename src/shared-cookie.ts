import { BloomXCookieConfig, BloomXLoginOptions, BloomXLogoutOptions, BloomXOAuthConfig } from "./types";

// Controles: OWASP ASVS V3/V5, RFC 6749 s.10.15 (open redirect), RFC 6265bis (SameSite=None => Secure),
// NIST SP 800-63C, CIS 16.x, ISO/IEC 27002:2022 8.26.

function normalizeOrigin(origin: string) {
    return new URL(origin).origin;
}

export function isAllowedBloomXOrigin(config: BloomXOAuthConfig, origin: string) {
    let normalizedOrigin: string;
    try {
        normalizedOrigin = normalizeOrigin(origin);
    } catch {
        return false;
    }
    return config.allowedOrigins.some((allowedOrigin) => {
        try {
            return normalizeOrigin(allowedOrigin) === normalizedOrigin;
        } catch {
            return false;
        }
    });
}

export function assertAllowedBloomXOrigin(config: BloomXOAuthConfig, origin: string) {
    if (!isAllowedBloomXOrigin(config, origin)) {
        throw new Error(`Origin not allowed: ${origin}`);
    }
    return normalizeOrigin(origin);
}

// Sufijos publicos multi-etiqueta frecuentes: la heuristica de "ultimas 2 etiquetas" es incorrecta para ellos
// (co.uk, com.pe, ...). Para un PSL completo usar el paquete `psl`/`tldts`. Aqui se toma un conjunto conservador.
const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.mx",
    "com.ar", "com.pe", "com.co", "com.cl", "com.ve", "co.za", "co.in", "com.cn", "com.tr", "github.io", "vercel.app",
    "netlify.app", "pages.dev", "web.app", "herokuapp.com", "azurewebsites.net", "cloudfront.net"
]);

function registrableDomain(host: string) {
    const parts = host.toLowerCase().split(".").filter(Boolean);
    if (parts.length < 2) return null;
    const lastTwo = parts.slice(-2).join(".");
    if (MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo)) {
        return parts.length >= 3 ? parts.slice(-3).join(".") : null; // el host ES un sufijo publico
    }
    return lastTwo;
}

export function canShareCookieBetween(hostA: string, hostB: string) {
    const a = registrableDomain(hostA);
    const b = registrableDomain(hostB);
    return a !== null && a === b;
}

export function createBloomXCookieOptions(config: BloomXOAuthConfig, overrides?: Partial<BloomXCookieConfig>) {
    const merged = {
        httpOnly: true,
        secure: config.cookie.secure ?? true,
        sameSite: config.cookie.sameSite ?? "lax",
        path: config.cookie.path ?? "/",
        maxAge: config.cookie.maxAge ?? 60 * 60 * 24 * 30,
        domain: config.cookie.domain,
        ...overrides
    };

    // SameSite=None exige Secure (los navegadores rechazan la cookie en caso contrario): se fuerza.
    if (merged.sameSite === "none") {
        merged.secure = true;
    }
    return merged;
}

/**
 * Resuelve el returnTo SIEMPRE contra la lista blanca de origenes (RFC 6749 10.15: open redirect).
 * Antes, sin `options.origin`, un returnTo arbitrario pasaba tal cual.
 * Se admiten rutas relativas (se resuelven contra el origen indicado o contra authOrigin).
 */
function resolveReturnTo(config: BloomXOAuthConfig, options?: { origin?: string; returnTo?: string; }) {
    const baseOrigin = options?.origin
        ? assertAllowedBloomXOrigin(config, options.origin)
        : normalizeOrigin(config.authOrigin);

    if (options?.returnTo) {
        const returnUrl = new URL(options.returnTo, baseOrigin);
        if (returnUrl.protocol !== "https:" && returnUrl.protocol !== "http:") {
            throw new Error("returnTo must be an http(s) URL");
        }
        // Sin credenciales embebidas ni origenes fuera de la lista blanca (authOrigin siempre es de confianza)
        if (returnUrl.username || returnUrl.password) {
            throw new Error("returnTo must not contain credentials");
        }
        if (returnUrl.origin !== normalizeOrigin(config.authOrigin)) {
            assertAllowedBloomXOrigin(config, returnUrl.origin);
        }
        return returnUrl.toString();
    }

    return `${baseOrigin}${config.defaultReturnPath || "/"}`;
}

const RESERVED_PARAMS = new Set(["returnto", "origin", "prompt"]);

export function buildBloomXLoginUrl(config: BloomXOAuthConfig, options?: BloomXLoginOptions) {
    const url = new URL(config.loginPath || "/api/auth/login", config.authOrigin);
    const returnTo = resolveReturnTo(config, options);

    url.searchParams.set("returnTo", returnTo);
    if (options?.origin) {
        url.searchParams.set("origin", assertAllowedBloomXOrigin(config, options.origin));
    }
    if (options?.prompt) {
        url.searchParams.set("prompt", options.prompt);
    }
    for (const [key, value] of Object.entries(options?.extraParams || {})) {
        // extraParams no puede pisar los parametros de seguridad (returnTo/origin/prompt)
        if (RESERVED_PARAMS.has(key.toLowerCase())) continue;
        url.searchParams.set(key, value);
    }

    return url.toString();
}

export function buildBloomXLogoutUrl(config: BloomXOAuthConfig, options?: BloomXLogoutOptions) {
    const url = new URL(config.logoutPath || "/api/auth/logout", config.authOrigin);
    const returnTo = resolveReturnTo(config, options);

    url.searchParams.set("returnTo", returnTo);
    if (options?.origin) {
        url.searchParams.set("origin", assertAllowedBloomXOrigin(config, options.origin));
    }

    return url.toString();
}
