const WorkOS = require("@workos-inc/node").WorkOS;
const jwt = require("jsonwebtoken");

const workos = new WorkOS(process.env.WORKOS_API_KEY);

exports.handler = async (event, context) => {
  const { code, error } = event.queryStringParameters || {};

  // WorkOS returned an error
  if (error) {
    console.error("WorkOS auth error:", error);
    return {
      statusCode: 302,
      headers: {
        Location: `${process.env.URL}?error=auth_failed`,
      },
      body: "",
    };
  }

  // No code returned
  if (!code) {
    return {
      statusCode: 302,
      headers: {
        Location: `${process.env.URL}?error=missing_code`,
      },
      body: "",
    };
  }

  try {
    // Exchange code for user profile
    const { user } = await workos.userManagement.authenticateWithCode({
      clientId: process.env.WORKOS_CLIENT_ID,
      code,
    });

    // Check against allowlist
    const allowedEmails = (process.env.ALLOWED_EMAILS || "")
      .split(",")
      .map(e => e.trim().toLowerCase());

    if (!allowedEmails.includes(user.email.toLowerCase())) {
      console.warn(`Unauthorized login attempt: ${user.email}`);
      return {
        statusCode: 302,
        headers: {
          Location: `${process.env.URL}?error=unauthorized`,
        },
        body: "",
      };
    }

    // Create short-lived signed JWT
    const token = jwt.sign(
      {
        user_id: user.id,
        email: user.email,
        first_name: user.firstName || "",
        last_name: user.lastName || "",
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "60s",   // 60 seconds — just long enough to redirect
        issuer: "abivian.com",
      }
    );

    // Redirect to Streamlit with token
    const streamlitUrl = `${process.env.STREAMLIT_APP_URL}?token=${token}`;

    return {
      statusCode: 302,
      headers: {
        Location: streamlitUrl,
      },
      body: "",
    };

  } catch (err) {
    console.error("Callback error:", err.message);
    return {
      statusCode: 302,
      headers: {
        Location: `${process.env.URL}?error=auth_failed`,
      },
      body: "",
    };
  }
};
