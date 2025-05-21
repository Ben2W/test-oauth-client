import express from "express";
import qs from "qs";
import dotenv from "dotenv";
import shortid from "shortid";
import open from "open";
import { z } from "zod";
import crypto from "crypto";

dotenv.config();

// Define schema for environment variables
const envSchema = z.object({
  FAPI_URL: z.string().url(),
  CLIENT_ID: z.string().min(1),
  CLIENT_SECRET: z.string().min(1),
  PORT: z.string().optional(),
});

// Validate environment variables
try {
  envSchema.parse({
    FAPI_URL: process.env.FAPI_URL,
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    PORT: process.env.PORT,
  });
} catch (error) {
  console.error("Environment validation failed:", error.errors);
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const state = shortid.generate();
const app = express();
const tokens = {}; // in memory store because thats how the real pros do it

// Middleware to log every request
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Generate code verifier and challenge
function generateCodeVerifier() {
  return crypto
    .randomBytes(32)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateCodeChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Store code verifier
const codeVerifier = generateCodeVerifier();
const codeChallenge = generateCodeChallenge(codeVerifier);

// Modify your authorization params to include PKCE
const params = {
  response_type: "code",
  client_id: process.env.CLIENT_ID,
  redirect_uri: `http://localhost:${PORT}/callback`,
  scope: "email profile",
  state,
  code_challenge: codeChallenge,
  code_challenge_method: "S256",
};

// Log out the initial authorization url to get the flow started
console.log("Opening initial authorization url in browser...");
open(`http://localhost:${PORT}/`);

app.get("/", (req, res) => {
  const loginUrl = `${process.env.FAPI_URL}/oauth/authorize?${qs.stringify(
    params
  )}`;
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Clerk OAuth 2.0 Demo</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; text-align: center; }
          .container { max-width: 800px; margin: 0 auto; }
          h1 { color: #333; }
          p { color: #666; line-height: 1.6; }
          .url-container { 
            text-align: left;
            word-break: break-all;
            background: #f4f4f4;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
          }
          .url-label {
            font-weight: bold;
            display: block;
            margin-bottom: 10px;
          }
          .login-button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 12px 20px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin-top: 20px;
          }
          .login-button:hover { background-color: #45a049; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Welcome to Clerk as OAuth 2.0 IDP Demo</h1>
          <p>
            This application simulates a client that uses Clerk as an OAuth 2.0 Identity Provider.
            It demonstrates the OAuth 2.0 authorization code flow, token refresh, and accessing user information.
          </p>
          <div class="url-container">
            <span class="url-label">OAuth 2.0 Authorization URL:</span>
            ${loginUrl}
          </div>
          <a href="${loginUrl}" class="login-button">Log in with ${process.env.FAPI_URL}</a>
        </div>
      </body>
    </html>
  `);
});

// Common HTML template function
const generateHtml = (title, heading, data, showButtons = true) => {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow: auto; max-height: 400px; }
          .button-container { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
          button { 
            background-color: #4CAF50; 
            color: white; 
            padding: 10px 15px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
          }
          button:hover { background-color: #45a049; }
          .revoke-button {
            background-color: #dc3545;
          }
          .revoke-button:hover {
            background-color: #c82333;
          }
          .introspect-button {
            background-color: #17a2b8;
          }
          .introspect-button:hover {
            background-color: #138496;
          }
        </style>
      </head>
      <body>
        <h2>${heading}</h2>
        ${
          showButtons
            ? `
        <div class="button-container">
          <button onclick="window.location.href='/refresh'">Refresh Token</button>
          <button onclick="window.location.href='/userinfo'">User Info</button>
          <button onclick="window.location.href='/tokeninfo'">Token Info</button>
          <button class="revoke-button" onclick="window.location.href='/revoke/access'">Revoke Access Token</button>
          <button class="revoke-button" onclick="window.location.href='/revoke/refresh'">Revoke Refresh Token</button>
          <button class="introspect-button" onclick="window.location.href='/introspect/access'">Introspect Access Token</button>
          <button class="introspect-button" onclick="window.location.href='/introspect/refresh'">Introspect Refresh Token</button>
        </div>
        `
            : ""
        }
        <pre>${JSON.stringify(data, null, 2)}</pre>
      </body>
    </html>
  `;
};

// hit this endpoint to exchange the code for an access token
app.get("/callback", async (req, res) => {
  const { code, state: callbackState } = qs.parse(req.query);
  console.log("Callback state:", callbackState);

  if (callbackState !== state) {
    return res.status(400).send("State param mismatch");
  }

  console.log("Code:", code);
  const response = await fetch(`${process.env.FAPI_URL}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: qs.stringify({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      code,
      code_verifier: codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: `http://localhost:${PORT}/callback`,
    }),
  });

  console.log("OAuth token response status:", response.status);

  if (response.status !== 200) {
    const errorData = await response.json();
    console.log("OAuth token error:", errorData);
    return res.send(
      generateHtml("OAuth Error", "OAuth Token Error", errorData, false)
    );
  }

  const tokenData = await response.json();
  console.log("OAuth token success:", tokenData);

  tokens.accessToken = tokenData.access_token;
  tokens.refreshToken = tokenData.refresh_token;
  tokens.idToken = tokenData.id_token;

  res.send(generateHtml("OAuth Response", "OAuth Token Response", tokenData));
});

// hit this endpoint to refresh the access token
app.get("/refresh", async (_, res) => {
  if (!tokens.refreshToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Refresh Token Available",
        { error: "No refresh token available. Please authorize first." },
        false
      )
    );
  }

  const response = await fetch(`${process.env.FAPI_URL}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: qs.stringify({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      refresh_token: tokens.refreshToken,
      grant_type: "refresh_token",
      redirect_uri: `http://localhost:${PORT}/callback`,
    }),
  })
    .then((res) => res.json())
    .catch((error) => error.data);

  tokens.accessToken = response.access_token;
  tokens.refreshToken = response.refresh_token;

  res.send(generateHtml("Token Refreshed", "Token Refreshed", response));
});

// get user info given an access token
app.get("/userinfo", async (_, res) => {
  if (!tokens.accessToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Access Token Available",
        { error: "No access token available. Please authorize first." },
        false
      )
    );
  }

  const response = await fetch(`${process.env.FAPI_URL}/oauth/userinfo`, {
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
    },
  })
    .then((res) => res.json())
    .catch((error) => error.data);

  res.send(generateHtml("User Info", "User Information", response));
});

// Introspect a token
async function introspectToken(token) {
  const basicAuth = Buffer.from(
    `${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`
  ).toString("base64");

  return await fetch(`${process.env.FAPI_URL}/oauth/token_info`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: qs.stringify({
      token,
    }),
  })
    .then((res) => res.json())
    .catch((error) => error.data);
}

// Introspect access token
app.get("/introspect/access", async (_, res) => {
  if (!tokens.accessToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Access Token Available",
        { error: "No access token available. Please authorize first." },
        false
      )
    );
  }

  const response = await introspectToken(tokens.accessToken);
  res.send(
    generateHtml("Token Introspection", "Access Token Introspection", response)
  );
});

// Introspect refresh token
app.get("/introspect/refresh", async (_, res) => {
  if (!tokens.refreshToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Refresh Token Available",
        { error: "No refresh token available. Please authorize first." },
        false
      )
    );
  }

  const response = await introspectToken(tokens.refreshToken);
  res.send(
    generateHtml("Token Introspection", "Refresh Token Introspection", response)
  );
});

// Revoke a specific token
async function revokeToken(token, tokenTypeHint) {
  const basicAuth = Buffer.from(
    `${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`
  ).toString("base64");

  const body = {
    token,
    token_type_hint: tokenTypeHint,
  };

  return {
    requestBody: body,
    response: await fetch(`${process.env.FAPI_URL}/oauth/token/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      },
      body: qs.stringify(body),
    })
      .then((res) => res.json())
      .catch((error) => error.data),
  };
}

// Revoke access token
app.get("/revoke/access", async (_, res) => {
  if (!tokens.accessToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Access Token Available",
        { error: "No access token available. Please authorize first." },
        false
      )
    );
  }

  const result = await revokeToken(tokens.accessToken, "access_token");

  const response = {
    revocation: result,
  };

  res.send(generateHtml("Token Revoked", "Access Token Revoked", response));
});

// Revoke refresh token
app.get("/revoke/refresh", async (_, res) => {
  if (!tokens.refreshToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Refresh Token Available",
        { error: "No refresh token available. Please authorize first." },
        false
      )
    );
  }

  // Revoke the token
  const result = await revokeToken(tokens.refreshToken, "refresh_token");

  const response = {
    revocation: result,
  };

  res.send(generateHtml("Token Revoked", "Refresh Token Revoked", response));
});

// start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
