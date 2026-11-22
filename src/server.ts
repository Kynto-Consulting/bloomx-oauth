import { createBloomXCookieOptions } from "./shared-cookie";
import { BloomXOAuthConfig } from "./types";

// Nombres/valores de cookie: solo tokens seguros (RFC 6265 cookie-octet). Evita inyeccion de atributos y
// de cabeceras (CR/LF, ';', ','), CWE-113. CIS 16.x / NIST SI-10 / ISO 27002 8.28.
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const COOKIE_VALUE_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;
const COOKIE_DOMAIN_RE = /^\.?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
const COOKIE_PATH_RE = /^\/[\x20-\x3A\x3C-\x7E]*$/;

export function buildBloomXSetCookieHeader(config: BloomXOAuthConfig, value: string) {
    const options = createBloomXCookieOptions(config);

    if (!COOKIE_NAME_RE.test(config.cookie.name)) {
        throw new Error("Invalid cookie name");
    }
    if (!COOKIE_VALUE_RE.test(value)) {
        throw new Error("Invalid cookie value");
    }
    if (options.domain && !COOKIE_DOMAIN_RE.test(options.domain)) {
        throw new Error("Invalid cookie domain");
    }
    if (!COOKIE_PATH_RE.test(options.path)) {
        throw new Error("Invalid cookie path");
    }

    const segments = [
        `${config.cookie.name}=${value}`,
        `Path=${options.path}`,
        `Max-Age=${Math.max(0, Math.floor(Number(options.maxAge)) || 0)}`,
        `SameSite=${options.sameSite}`
    ];

    if (options.domain) {
        segments.push(`Domain=${options.domain}`);
    }
    if (options.secure) {
        segments.push("Secure");
    }
    segments.push("HttpOnly");

    return segments.join("; ");
}
