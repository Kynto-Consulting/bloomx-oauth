import { BloomXFetchOptions, BloomXOAuthConfig, BloomXSession, BloomXSessionClient } from "./types";
import { buildBloomXLoginUrl, buildBloomXLogoutUrl } from "./shared-cookie";

export function createBloomXSessionClient(config: BloomXOAuthConfig, options?: BloomXFetchOptions): BloomXSessionClient {
    const fetcher = options?.fetcher || fetch;

    return {
        async getSession(): Promise<BloomXSession | null> {
            const response = await fetcher(new URL(config.sessionPath || "/api/auth/me", config.authOrigin), {
                credentials: "include"
            });

            if (!response.ok) {
                return null;
            }

            const data = await response.json();
            // Si el endpoint responde { user: null } NO hay sesion (antes se devolvia el objeto completo, truthy)
            if (data && typeof data === "object" && "user" in data) {
                return (data.user as BloomXSession | null) || null;
            }
            return data?.session || null;
        },
        login(loginOptions) {
            if (typeof window === "undefined") {
                throw new Error("BloomX login can only be started in the browser");
            }
            window.location.assign(buildBloomXLoginUrl(config, loginOptions));
        },
        logout(logoutOptions) {
            if (typeof window === "undefined") {
                throw new Error("BloomX logout can only be started in the browser");
            }
            window.location.assign(buildBloomXLogoutUrl(config, logoutOptions));
        }
    };
}
