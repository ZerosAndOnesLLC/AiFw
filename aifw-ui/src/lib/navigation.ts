/**
 * Full-document navigation for auth boundaries.
 *
 * Login, logout, and expired-session handling deliberately do NOT use the
 * Next.js router: crossing an auth boundary must reset every piece of
 * client state (WebSocket context, cached resource hooks, in-memory
 * feedback) so nothing from the previous identity survives. A hard reload
 * is the simplest guarantee of that. Everything else in the app should use
 * `useRouter().push()` / `<Link>` as the Next lint rules expect.
 *
 * The destination is resolved against the current origin so it always
 * targets this appliance, never a relative path that could be re-based.
 */
export function hardNavigate(path: string): void {
  if (typeof window === "undefined") return;
  window.location.assign(new URL(path, window.location.origin).href);
}
