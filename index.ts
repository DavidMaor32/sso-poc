import express from 'express';
import { AuthClient, Payload } from './AuthClient';
import { config } from 'dotenv';
config()

const PORT = process.env.PORT;

const html = (payload: Payload, token: string) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sso poc</title>
</head>
<body>
    <h1>Hello ${payload.name}</h1>
    <pre><code class="language-json">
        ${JSON.stringify({ token, payload }, null, 2)}
    </code></pre>
</body>
</html>
`

async function main() {
    const auth = new AuthClient({
        jwtSecret: process.env.JWT_SECRET!,
        issuerURL: process.env.ISSUER_URL!,
        clientID: process.env.CLIENT_ID!,
        clientSecret: process.env.CLIENT_SECRET!,
        cbURL: process.env.CB_URL!,
    });

    await auth.start();
    const app = express();

    app.get('/login', (req, res) => res.redirect(auth.getAuthorizationUrl()));

    app.get(
        '/callback',
        async (req, res) => {
            try {
                const payload =
                    await auth.callback(req.query);

                console.log(
                    '\nLOGIN SUCCESS:\n'
                );

                console.log(payload);

                const token = auth.sign(payload);

                console.log('\nAPP JWT:\n' );

                console.log(token);

                res.contentType('html').send(html(payload, token));
            } catch (e) {
                console.error(e);

                res.status(500).json({
                    success: false,
                    error: (e as Error).message
                });
            }
        }
    );

    app.listen(PORT, () => {
        console.log(
            `\nOpen browser:\n`
        );

        console.log(
            `http://localhost:${PORT}/login`
        );
    });
}

main().catch(console.error);