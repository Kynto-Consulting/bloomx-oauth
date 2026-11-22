import { useEffect, useMemo, useState } from "react";
import { createBloomXSessionClient } from "./client";
import { BloomXLoginOptions, BloomXLogoutOptions, BloomXOAuthConfig, BloomXSession } from "./types";

interface BloomXButtonProps {
    config: BloomXOAuthConfig;
    label?: string;
    className?: string;
}

interface BloomXLoginButtonProps extends BloomXButtonProps {
    loginOptions?: BloomXLoginOptions;
}

interface BloomXLogoutButtonProps extends BloomXButtonProps {
    logoutOptions?: BloomXLogoutOptions;
}

export function useBloomXSession(config: BloomXOAuthConfig) {
    const client = useMemo(() => createBloomXSessionClient(config), [config]);
    const [session, setSession] = useState<BloomXSession | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        let cancelled = false;

        client.getSession()
            .then((value) => {
                if (!cancelled) {
                    setSession(value);
                }
            })
            .finally(() => {
                if (!cancelled) {
                    setIsLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };
    }, [client]);

    return { session, isLoading, refresh: () => client.getSession().then(setSession) };
}

export function BloomXLoginButton({ config, label = "Sign in with BloomX", className, loginOptions }: BloomXLoginButtonProps) {
    const client = useMemo(() => createBloomXSessionClient(config), [config]);

    return (
        <button type="button" className={className} onClick={() => client.login(loginOptions)}>
            {label}
        </button>
    );
}

export function BloomXLogoutButton({ config, label = "Sign out", className, logoutOptions }: BloomXLogoutButtonProps) {
    const client = useMemo(() => createBloomXSessionClient(config), [config]);

    return (
        <button type="button" className={className} onClick={() => client.logout(logoutOptions)}>
            {label}
        </button>
    );
}
