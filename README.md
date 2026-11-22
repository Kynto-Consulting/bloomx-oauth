# bloomx-oauth

Paquete reusable para integrar autenticacion BloomX en dominios y subdominios autorizados usando cookie compartida cuando el dominio base lo permite, y con flujo de redireccion seguro para escenarios privados.

## Que incluye

- Utilidades para validar origins y return URLs.
- Helpers para construir opciones de cookie compartida.
- Cliente ligero para login, logout y lectura de sesion.
- Componentes React para botones de login/logout y un hook de sesion.

## Ejemplo rapido

```ts
import { buildBloomXLoginUrl, createBloomXSessionClient } from "bloomx-oauth";

const config = {
  authOrigin: "https://auth.bloomx.example.com",
  allowedOrigins: [
    "https://mail.bloomx.example.com",
    "https://admin.bloomx.example.com"
  ],
  cookie: {
    name: "next-auth.session-token",
    domain: ".bloomx.example.com",
    secure: true
  }
};

const sessionClient = createBloomXSessionClient(config);
const loginUrl = buildBloomXLoginUrl(config, {
  origin: window.location.origin,
  returnTo: window.location.href
});
```

## Nota operativa

La cookie compartida solo funciona de forma nativa entre subdominios del mismo dominio registrable. Para dominios distintos, este paquete sirve para controlar el redirect y la validacion del origen, pero el intercambio de sesion debe hacerse con un bridge del lado del servidor.