import { createApiClient } from "./api";
import { API_URL } from "./config";
import { clearToken, getToken } from "./token-store";

/** The application's API client: bearer token from the token store; a 401 ends the session. */
export const api = createApiClient({
  baseUrl: API_URL,
  getToken: () => getToken(),
  onUnauthorized: () => clearToken(),
});
