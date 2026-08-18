const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        try {

            // =========================================
            // Google login
            // =========================================

            if (
                url.pathname === "/auth/google" &&
                request.method === "POST"
            ) {
                return await handleGoogleLogin(request, env);
            }


            // =========================================
            // Current logged-in user
            // =========================================

            if (
                url.pathname === "/api/me" &&
                request.method === "GET"
            ) {
                return await handleMe(request, env);
            }


            // =========================================
            // LiveNet Channel Center
            // =========================================

            if (
                url.pathname === "/api/status" &&
                request.method === "GET"
            ) {

                return new Response(
                    JSON.stringify({
                        ok: true,

                        service: "LiveNet",

                        status: "online",

                        checkedAt:
                            new Date().toISOString(),

                        services: [

                            {
                                id: "livenet",
                                name: "LiveNet",
                                type: "system",
                                status: "online"
                            },

                            {
                                id: "twitch",
                                name: "Twitch",
                                type: "stream",
                                status: "available"
                            },

                            {
                                id: "kick",
                                name: "Kick",
                                type: "stream",
                                status: "available"
                            },

                            {
                                id: "etoyatv",
                                name: "ЭтоЯTV",
                                type: "stream",
                                status: "available"
                            }

                        ]
                    }),

                    {
                        status: 200,

                        headers: {
                            "Content-Type":
                                "application/json; charset=utf-8",

                            "Cache-Control":
                                "no-store"
                        }
                    }
                );
            }


            // =========================================
            // Logout
            // =========================================

            if (
                url.pathname === "/auth/logout"
            ) {

                return new Response(
                    "OK",
                    {
                        status: 200,

                        headers: {
                            "Set-Cookie":
                                "livenet_session=; " +
                                "Path=/; " +
                                "Max-Age=0; " +
                                "HttpOnly; " +
                                "Secure; " +
                                "SameSite=Lax"
                        }
                    }
                );
            }


            // =========================================
            // Static website
            // =========================================

            return env.ASSETS.fetch(request);


        } catch (error) {

            console.error(
                "LiveNet Worker error:",
                error
            );

            return new Response(
                JSON.stringify({
                    error: "Internal server error"
                }),

                {
                    status: 500,

                    headers: {
                        "Content-Type":
                            "application/json"
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

    const body =
        await request.json();

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
                error:
                    "Missing credentials"
            },
            400
        );
    }


    const cookieHeader =
        request.headers.get("Cookie") ||
        "";


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
                error:
                    "Invalid CSRF token"
            },
            403
        );
    }


    const payload =
        await verifyGoogleToken(
            credential,
            env.GOOGLE_CLIENT_ID
        );


    if (!payload) {

        return json(
            {
                error:
                    "Invalid Google token"
            },
            401
        );
    }


    /*
     * Используем sub как постоянный Google ID.
     * Email не используется как уникальный ID.
     */

    const sessionPayload = {

        sub:
            payload.sub,

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
                    "application/json",

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
        request.headers.get("Cookie") ||
        "";


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
                b64urlDecode(
                    session
                )
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

    const parts =
        token.split(".");


    if (
        parts.length !== 3
    ) {
        return null;
    }


    const header =
        JSON.parse(
            b64urlDecode(
                parts[0]
            )
        );


    const payload =
        JSON.parse(
            b64urlDecode(
                parts[1]
            )
        );


    const signature =
        b64urlToBytes(
            parts[2]
        );


    if (
        payload.iss !==
            "https://accounts.google.com" &&

        payload.iss !==
            "accounts.google.com"
    ) {

        return null;
    }


    if (
        payload.aud !== clientId
    ) {

        return null;
    }


    if (
        !payload.exp ||
        payload.exp <
            Math.floor(
                Date.now() / 1000
            )
    ) {

        return null;
    }


    const keysResponse =
        await fetch(
            GOOGLE_JWKS_URL
        );


    if (
        !keysResponse.ok
    ) {

        return null;
    }


    const keys =
        await keysResponse.json();


    const jwk =
        keys.keys.find(
            key =>
                key.kid ===
                header.kid
        );


    if (!jwk) {

        return null;
    }


    const cryptoKey =
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

            ["verify"]
        );


    const data =
        new TextEncoder().encode(
            `${parts[0]}.${parts[1]}`
        );


    const valid =
        await crypto.subtle.verify(

            "RSASSA-PKCS1-v1_5",

            cryptoKey,

            signature,

            data
        );


    if (!valid) {

        return null;
    }


    return payload;
}


/* =========================================
   HELPERS
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
                    "application/json"
            }
        }
    );
}


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


function b64urlEncode(
    text
) {

    const bytes =
        new TextEncoder()
            .encode(text);


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
