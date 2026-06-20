/**
 * api.js
 * -------
 * Tiny fetch wrapper shared by every page. Because the frontend is served
 * by the same Flask app (same origin), the browser automatically attaches
 * the session cookie on every request below - no token handling needed.
 */

const API = {
  async _request(method, path, body) {
    const opts = {
      method,
      credentials: "same-origin",
      headers: {},
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }

    let res;
    try {
      res = await fetch(path, opts);
    } catch (err) {
      throw new Error("Could not reach the server. Is the Flask app running?");
    }

    const isJson = (res.headers.get("content-type") || "").includes("application/json");
    const data = isJson ? await res.json().catch(() => ({})) : await res.text();

    if (!res.ok) {
      const message = isJson && data && data.error ? data.error : `Request failed (${res.status})`;
      const error = new Error(message);
      error.status = res.status;
      error.data = data;
      throw error;
    }
    return data;
  },

  get(path) {
    return this._request("GET", path);
  },
  post(path, body) {
    return this._request("POST", path, body || {});
  },
  put(path, body) {
    return this._request("PUT", path, body || {});
  },
  del(path) {
    return this._request("DELETE", path);
  },
};
