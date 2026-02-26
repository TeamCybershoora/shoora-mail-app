import { ApiError, UnauthorizedError } from '../utils/errors.js';

const USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

function asFormBody(data) {
  return new URLSearchParams(data).toString();
}

export class GoogleOAuthService {
  constructor({ config }) {
    this.config = config;
  }

  isConfigured() {
    return Boolean(
      this.config.clientId &&
      this.config.clientSecret &&
      this.config.redirectUri,
    );
  }

  buildAuthorizationUrl({ state, codeChallenge, loginHint }) {
    this._assertConfigured();

    const url = new URL(this.config.authBaseUrl);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');
    url.searchParams.set('scope', this.config.oauthScopes.join(' '));

    if (state) {
      url.searchParams.set('state', state);
    }
    if (codeChallenge) {
      url.searchParams.set('code_challenge', codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }
    if (loginHint) {
      url.searchParams.set('login_hint', loginHint);
    }

    return url.toString();
  }

  async exchangeCode({ code, codeVerifier, redirectUri }) {
    this._assertConfigured();

    const body = {
      code,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      redirect_uri: redirectUri || this.config.redirectUri,
      grant_type: 'authorization_code',
    };

    if (codeVerifier) {
      body.code_verifier = codeVerifier;
    }

    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: asFormBody(body),
    });

    const json = await response.json();
    if (!response.ok) {
      throw new UnauthorizedError(
        json?.error_description || json?.error || 'Google OAuth code exchange failed',
      );
    }

    return {
      accessToken: json.access_token,
      refreshToken: json.refresh_token,
      expiresInSec: Number(json.expires_in || 3600),
      scope: String(json.scope || ''),
      tokenType: String(json.token_type || 'Bearer'),
      idToken: json.id_token || null,
    };
  }

  async refreshAccessToken({ refreshToken }) {
    this._assertConfigured();

    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: asFormBody({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }),
    });

    const json = await response.json();
    if (!response.ok) {
      throw new UnauthorizedError(
        json?.error_description || json?.error || 'Google token refresh failed',
      );
    }

    return {
      accessToken: json.access_token,
      refreshToken: refreshToken,
      expiresInSec: Number(json.expires_in || 3600),
      scope: String(json.scope || ''),
      tokenType: String(json.token_type || 'Bearer'),
      idToken: json.id_token || null,
    };
  }

  async fetchUserProfile(accessToken) {
    this._assertConfigured();

    const response = await fetch(USERINFO_URL, {
      headers: {
        authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new ApiError(401, 'Failed to fetch Google user profile', {
        code: 'GOOGLE_PROFILE_FETCH_FAILED',
      });
    }

    const profile = await response.json();
    return {
      id: profile.sub,
      email: String(profile.email || '').toLowerCase(),
      emailVerified: Boolean(profile.email_verified),
      name: profile.name || profile.email || '',
      picture: profile.picture || null,
    };
  }

  _assertConfigured() {
    if (this.isConfigured()) {
      return;
    }
    throw new ApiError(503, 'Google OAuth is not configured on this server', {
      code: 'GOOGLE_OAUTH_NOT_CONFIGURED',
    });
  }
}
