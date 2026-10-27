// Authenticate before resolving/starting a paid container. No token in URLs/logs.
export async function route(request, env, resolve) {
  const supplied = request.headers.get("Authorization") || "";
  const expected = env.MANAGEMENT_TOKEN;
  if (!expected || expected.length < 32 || !supplied.startsWith("Bearer ")) return new Response(null, { status: 401 });
  const digest = async (value) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  const left = await digest(supplied.slice(7)), right = await digest(expected);
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  if (difference !== 0) return new Response(null, { status: 401 });
  const url = new URL(request.url), match = /^\/nodes\/([A-Za-z0-9_-]{1,64})$/.exec(url.pathname);
  if (!match || url.search) return new Response(null, { status: 404 });
  if (!["GET", "PUT", "DELETE"].includes(request.method)) return new Response(null, { status: 405 });
  const member = resolve(env.MEMBERS, match[1]);
  try {
    if (request.method === "DELETE") { await member.stop(); return new Response(null, { status: 204 }); }
    const response = await member.fetch("http://container/readyz");
    await response.body?.cancel();
    return new Response(null, { status: response.ok ? 204 : 503, headers: { "Cache-Control": "no-store" } });
  } catch { return new Response(null, { status: 503 }); }
}
