import express from "express";
import qs from "qs";
import dotenv from "dotenv";
import shortid from "shortid";
import open from "open";
import { z } from "zod";

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

// Log out the initial authorization url to get the flow started
const params = {
  response_type: "code",
  client_id: process.env.CLIENT_ID,
  redirect_uri: `http://localhost:${PORT}/callback`,
  scope: "email profile",
  state,
};

console.log("Opening initial authorization url in browser...");
open(`${process.env.FAPI_URL}/oauth/authorize?${qs.stringify(params)}`);

app.get("/", (req, res) => {
  res.redirect(
    `${process.env.FAPI_URL}/oauth/authorize?${qs.stringify(params)}`
  );
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
          .button-container { margin-top: 20px; display: flex; gap: 10px; }
          button { 
            background-color: #4CAF50; 
            color: white; 
            padding: 10px 15px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
          }
          button:hover { background-color: #45a049; }
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

  if (callbackState !== state) {
    return res.status(400).send("State param mismatch");
  }

  const response = await fetch(`${process.env.FAPI_URL}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: qs.stringify({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: `http://localhost:${PORT}/callback`,
    }),
  })
    .then((res) => res.json())
    .catch((error) => error.data);

  tokens.accessToken = response.access_token;
  tokens.refreshToken = response.refresh_token;
  tokens.idToken = response.id_token;

  res.send(generateHtml("OAuth Response", "OAuth Token Response", response));
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

// get refresh token info
app.get("/tokeninfo", async (_, res) => {
  if (!tokens.refreshToken || !tokens.accessToken) {
    return res.send(
      generateHtml(
        "Error",
        "Error: No Tokens Available",
        { error: "No tokens available. Please authorize first." },
        false
      )
    );
  }

  const response = await fetch(`${process.env.FAPI_URL}/oauth/token_info`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: qs.stringify({
      token: tokens.refreshToken,
    }),
  })
    .then((res) => res.json())
    .catch((error) => error.data);

  res.send(generateHtml("Token Info", "Refresh Token Information", response));
});

// start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
