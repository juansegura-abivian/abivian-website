const WorkOS = require("@workos-inc/node").WorkOS;

const workos = new WorkOS(process.env.WORKOS_API_KEY);

exports.handler = async (event, context) => {
  try {
    const redirectUri = `${process.env.URL}/.netlify/functions/auth-callback`;

    const authorizationUrl = workos.userManagement.getAuthorizationUrl({
      clientId: process.env.WORKOS_CLIENT_ID,
      redirectUri,
      provider: "GoogleOAuth",
    });

    return {
      statusCode: 302,
      headers: {
        Location: authorizationUrl,
      },
      body: "",
    };
  } catch (error) {
    console.error("Login error:", error);
    return {
      statusCode: 302,
      headers: {
        Location: `${process.env.URL}?error=login_failed`,
      },
      body: "",
    };
  }
};
