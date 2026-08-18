const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        try {
            /* =========================================
               GOOGLE LOGIN
            ========================================= */

            if (
                url.pathname === "/auth/google" &&
                request.method === "POST"
            ) {
                return await handleGoogleLogin(request, env);
            }


            /* =========================================
               LIVE NET STATUS / LIVE MONITOR
            ========================================= */

            if (
                url.pathname === "/api/status" &&
                request.method === "GET"
            ) {
                const checkedAt = new Date().toISOString();

                return new Response(
                    JSON.stringify({
                        ok: true,
                        service: "LiveNet",
                        status: "online",
                        checkedAt,

                        services: [

                            /* LiveNet itself */
                            {
                                id: "livenet",
                                name: "LiveNet",
                                platform: "LiveNet",
                                type: "system",
                                status: "online",
                                url: "https://livenet.limonvzdanii.workers.dev"
                            },

                            /* Twitch */
                            {
                                id: "twitch-bobrdobrenok",
                                name: "bobrdobrenok",
                                platform: "Twitch",
                                type: "stream",

                                /*
                                 * Twitch API intentionally isn't used.
                                 * Therefore we don't pretend to know
                                 * whether the channel is actually LIVE.
                                 */
                                status: "available",

                                apiConnected: false,

                                url: "https://www.twitch.tv/bobrdobrenok"
                            },

                            {
                                id: "twitch-hypertwitch112",
                                name: "hypertwitch112",
                                platform: "Twitch",
                                type: "stream",
                                status: "available",
                                apiConnected: false,
                                url: "https://www.twitch.tv/hypertwitch112"
                            },

                            /* Kick */
                            {
                                id: "kick-livenet1",
                                name: "LiveNet1",
                                platform: "Kick",
                                type: "stream",

                                /*
                                 * No Kick API credentials are used yet.
                                 */
                                status: "available",

                                apiConnected: false,

                                url: "https://kick.com/LiveNet1"
                            },

                            /* ЭтоЯTV */
                            {
                                id: "etoyatv",
                                name: "ЭтоЯTV",
                                platform: "ЭтоЯTV",
                                type: "stream",

                                status: "available",

                                apiConnected: false,

                                url: "https://etoyatv.top/LiveNet"
                            }
                        ]
                    }),
                    {
                        status: 200,
                        headers: {
                            "Content-Type":
                                "application/json; charset=utf-8",

                            "Cache-Control":
                                "no-store",

                            "Access-Control-Allow-Origin":
                                "*"
                        }
                    }
                );
            }


            /* =========================================
               CURRENT USER
            ========================================= */

            if (
                url.pathname === "/api/me" &&
                request.method === "GET"
            ) {
                return await handleMe(request, env);
            }


            /* =========================================
               LOGOUT
            ========================================= */

            if (
                url.pathname === "/auth/logout"
            ) {
                return new Response("OK", {
                    status: 200,

                    headers: {
                        "Set-Cookie":
                            "livenet_session=; " +
                            "Path=/; " +
                            "Max-Age=0; " +
                            "HttpOnly; " +
                            "Secure; " +
                            "SameSite=Lax",

                        "Cache-Control":
                            "no-store"
                    }
                });
            }


            /* =========================================
               STATIC WEBSITE
            ========================================= */

            return env.ASSETS.fetch(request);

        } catch (error) {

            console.error(
                "LiveNet Worker error:",
                error
            );

            return new Response(
                JSON.stringify({
                    ok: false,
                    error: "Internal server error"
                }),
                {
                    status: 500,

                    headers: {
                        "Content-Type":
                            "application/json; charset=utf-8",

                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }
    }
};


/* =========================================
   GOOGLE LOGIN
========================================= */

async function handleGoogleLogin(
    request,
    env
) {

    let body;

    try {
        body = await request.json();
    } catch {
        return json(
            {
                error: "Invalid JSON"
            },
            400
        );
    }


    const credential =
        body.credential;

    const csrf =
        body.csrf;


    if (
        !credential ||
        !csrf
    ) {
        return json(
            {
                error: "Missing credentials"
            },
            400
        );
    }


    /* =========================================
       CSRF COOKIE
    ========================================= */

    const cookieHeader =
        request.headers.get("Cookie") || "";


    const csrfCookie =
        getCookie(
            cookieHeader,
            "livenet_csrf"
        );


    if (
        !csrfCookie ||
        csrfCookie !== csrf
    ) {
        return json(
            {
                error: "Invalid CSRF token"
            },
            403
        );
    }


    /* =========================================
       GOOGLE TOKEN
    ========================================= */

    const payload =
        await verifyGoogleToken(
            credential,
            env.GOOGLE_CLIENT_ID
        );


    if (!payload) {
        return json(
            {
                error: "Invalid Google token"
            },
            401
        );
    }


    /*
     * Google `sub` используется как
     * постоянный идентификатор пользователя.
     */

    const sessionPayload = {
        sub:
            payload.sub || "",

        name:
            payload.name || "",

        email:
            payload.email || "",

        picture:
            payload.picture || "",

        exp:
            Math.floor(
                Date.now() / 1000
            ) + 3600
    };


    const session =
        b64urlEncode(
            JSON.stringify(
                sessionPayload
            )
        );


    return new Response(
        JSON.stringify({
            success: true,
            user: sessionPayload
        }),
        {
            status: 200,

            headers: {
                "Content-Type":
                    "application/json; charset=utf-8",

                "Cache-Control":
                    "no-store",

                "Set-Cookie":
                    `livenet_session=${session}; ` +
                    "Path=/; " +
                    "Max-Age=3600; " +
                    "HttpOnly; " +
                    "Secure; " +
                    "SameSite=Lax"
            }
        }
    );
}


/* =========================================
   /api/me
========================================= */

async function handleMe(
    request,
    env
) {

    const cookies =
        request.headers.get("Cookie") || "";


    const session =
        getCookie(
            cookies,
            "livenet_session"
        );


    if (!session) {
        return json({
            authenticated: false
        });
    }


    try {

        const user =
            JSON.parse(
                b64urlDecode(session)
            );


        if (
            !user.sub ||
            !user.exp ||
            user.exp <
                Math.floor(
                    Date.now() / 1000
                )
        ) {
            return json({
                authenticated: false
            });
        }


        return json({
            authenticated: true,
            user
        });

    } catch {

        return json({
            authenticated: false
        });
    }
}


/* =========================================
   GOOGLE JWT VERIFICATION
========================================= */

async function verifyGoogleToken(
    token,
    clientId
) {

    if (
        !token ||
        !clientId
    ) {
        return null;
    }


    const parts =
        token.split(".");


    if (
        parts.length !== 3
    ) {
        return null;
    }


    let header;
    let payload;


    try {

        header =
            JSON.parse(
                b64urlDecode(
                    parts[0]
                )
            );


        payload =
            JSON.parse(
                b64urlDecode(
                    parts[1]
                )
            );

    } catch {

        return null;
    }


    const signature =
        b64urlToBytes(
            parts[2]
        );


    /* =========================================
       ISSUER
    ========================================= */

    if (
        payload.iss !==
            "https://accounts.google.com" &&
        payload.iss !==
            "accounts.google.com"
    ) {
        return null;
    }


    /* =========================================
       AUDIENCE
    ========================================= */

    if (
        payload.aud !== clientId
    ) {
        return null;
    }


    /* =========================================
       EXPIRATION
    ========================================= */

    if (
        !payload.exp ||
        payload.exp <
            Math.floor(
                Date.now() / 1000
            )
    ) {
        return null;
    }


    /* =========================================
       GOOGLE JWKS
    ========================================= */

    let keysResponse;

    try {

        keysResponse =
            await fetch(
                GOOGLE_JWKS_URL
            );

    } catch {

        return null;
    }


    if (
        !keysResponse.ok
    ) {
        return null;
    }


    let keys;

    try {

        keys =
            await keysResponse.json();

    } catch {

        return null;
    }


    if (
        !keys ||
        !Array.isArray(keys.keys)
    ) {
        return null;
    }


    const jwk =
        keys.keys.find(
            key =>
                key.kid ===
                header.kid
        );


    if (!jwk) {
        return null;
    }


    let cryptoKey;

    try {

        cryptoKey =
            await crypto.subtle.importKey(
                "jwk",

                jwk,

                {
                    name:
                        "RSASSA-PKCS1-v1_5",

                    hash:
                        "SHA-256"
                },

                false,

                [
                    "verify"
                ]
            );

    } catch {

        return null;
    }


    const data =
        new TextEncoder().encode(
            `${parts[0]}.${parts[1]}`
        );


    let valid;

    try {

        valid =
            await crypto.subtle.verify(
                "RSASSA-PKCS1-v1_5",

                cryptoKey,

                signature,

                data
            );

    } catch {

        return null;
    }


    if (!valid) {
        return null;
    }


    return payload;
}


/* =========================================
   JSON HELPER
========================================= */

function json(
    data,
    status = 200
) {

    return new Response(
        JSON.stringify(data),
        {
            status,

            headers: {
                "Content-Type":
                    "application/json; charset=utf-8",

                "Cache-Control":
                    "no-store"
            }
        }
    );
}


/* =========================================
   COOKIE HELPER
========================================= */

function getCookie(
    header,
    name
) {

    const cookies =
        header.split(";");


    for (
        const cookie of cookies
    ) {

        const [
            key,
            ...value
        ] =
            cookie
                .trim()
                .split("=");


        if (
            key === name
        ) {

            return value.join("=");
        }
    }


    return null;
}


/* =========================================
   BASE64URL ENCODE
========================================= */

function b64urlEncode(
    text
) {

    const bytes =
        new TextEncoder().encode(
            text
        );


    let binary = "";


    for (
        const byte of bytes
    ) {

        binary +=
            String.fromCharCode(
                byte
            );
    }


    return btoa(binary)
        .replace(
            /\+/g,
            "-"
        )
        .replace(
            /\//g,
            "_"
        )
        .replace(
            /=/g,
            ""
        );
}


/* =========================================
   BASE64URL DECODE
========================================= */

function b64urlDecode(
    value
) {

    value =
        value
            .replace(
                /-/g,
                "+"
            )
            .replace(
                /_/g,
                "/"
            );


    while (
        value.length % 4
    ) {

        value += "=";
    }


    const binary =
        atob(value);


    const bytes =
        Uint8Array.from(
            binary,
            c =>
                c.charCodeAt(0)
        );


    return new TextDecoder()
        .decode(bytes);
}


/* =========================================
   BASE64URL → BYTES
========================================= */

function b64urlToBytes(
    value
) {

    value =
        value
            .replace(
                /-/g,
                "+"
            )
            .replace(
                /_/g,
                "/"
            );


    while (
        value.length % 4
    ) {

        value += "=";
    }


    const binary =
        atob(value);


    return Uint8Array.from(
        binary,
        c =>
            c.charCodeAt(0)
    );
}
