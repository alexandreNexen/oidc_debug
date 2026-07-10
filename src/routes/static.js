import path from "node:path";
import { readFile } from "node:fs/promises";

// MIME types for assets emitted by the Vite build. Everything served under
// /static/assets/* falls into this table; unknown extensions fall back to
// application/octet-stream so we never guess a wrong content type.
const VITE_MIME_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
  [".mjs", "application/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".gif", "image/gif"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
  [".ttf", "font/ttf"],
  [".txt", "text/plain; charset=utf-8"]
]);

function mimeTypeFor(filePath) {
  return VITE_MIME_TYPES.get(path.extname(filePath).toLowerCase()) || "application/octet-stream";
}

export function createStaticRouter({ viteAssetsDir, sharedStaticFiles, send, sendJson }) {
  async function serveSharedStatic(res, asset) {
    // Read as Buffer so binary assets (favicon.ico) survive byte-for-byte.
    // Passing a string encoding here (previously "utf8") corrupted .ico
    // bytes on the wire. Text assets like favicon.svg are equally safe as
    // Buffers because `res.end(buffer)` writes the raw bytes without any
    // decode/encode roundtrip.
    const content = await readFile(asset.filePath);
    send(res, 200, content, asset.contentType);
  }

  async function serveViteAsset(res, relativePath) {
    // Defense-in-depth against path traversal:
    //   1) reject non-portable characters and any ".." segment
    //   2) reject empty / absolute-looking paths
    //   3) confirm the resolved path is still inside viteAssetsDir
    if (!relativePath || relativePath.length > 256) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }
    if (relativePath.startsWith("/") || relativePath.includes("..") || !/^[A-Za-z0-9._/-]+$/.test(relativePath)) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }

    const resolved = path.resolve(viteAssetsDir, relativePath);
    const assetsPrefix = viteAssetsDir + path.sep;
    if (!resolved.startsWith(assetsPrefix)) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }

    try {
      const content = await readFile(resolved);
      send(res, 200, content, mimeTypeFor(resolved));
    } catch {
      sendJson(res, 404, { error: "Vite asset not found." });
    }
  }

  async function handleStaticRoute(req, res, url) {
    // Shared static files (favicons). Behavior preserved from the pre-refactor
    // dispatcher: no explicit method gate (POST/PUT etc. would still serve the
    // file body). Extending to 405 here would be a behavior change and is out
    // of scope for a structural refactor.
    if (sharedStaticFiles.has(url.pathname)) {
      await serveSharedStatic(res, sharedStaticFiles.get(url.pathname));
      return true;
    }

    // Vite SPA build assets (/static/assets/*). GET/HEAD only — matches the
    // pre-refactor behavior.
    if (url.pathname.startsWith("/static/assets/")) {
      if (req.method !== "GET" && req.method !== "HEAD") {
        sendJson(res, 405, { error: "Method not allowed." });
        return true;
      }
      await serveViteAsset(res, url.pathname.slice("/static/assets/".length));
      return true;
    }

    return false;
  }

  return { handleStaticRoute, serveSharedStatic, serveViteAsset };
}
