export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": "https://sovapal.com",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    const reply = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json", ...cors },
      });

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (request.method !== "POST") return reply({ valid: false, error: "Method not allowed" }, 405);
    if (!env.BOT_TOKEN || !env.LOGIN_SECRET) return reply({ valid: false, error: "Server not configured" }, 500);

    try {
      const { init_data: initData = "" } = await request.json();
      if (!initData) return reply({ valid: false, error: "Missing init_data" });

      const params = new URLSearchParams(initData);
      const hash = params.get("hash");
      const authDate = Number(params.get("auth_date") || 0);
      if (!hash || !authDate) return reply({ valid: false, error: "Missing hash or auth_date" });

      const now = Math.floor(Date.now() / 1000);
      if (now - authDate > 3600 || authDate - now > 60) return reply({ valid: false, error: "Session expired" });

      params.delete("hash");
      const dataCheckString = Array.from(params.entries())
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => `${k}=${v}`)
        .join("\n");

      const enc = new TextEncoder();
      const hmac = async (keyBytes, msg) => {
        const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
      };
      const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

      const secretKey = await hmac(enc.encode("WebAppData"), env.BOT_TOKEN);
      const calculated = hex(await hmac(secretKey, dataCheckString));

      if (calculated.length !== hash.length) return reply({ valid: false, error: "Invalid signature" });
      let diff = 0;
      for (let i = 0; i < hash.length; i++) diff |= calculated.charCodeAt(i) ^ hash.charCodeAt(i);
      if (diff !== 0) return reply({ valid: false, error: "Invalid signature" });

      const user = JSON.parse(params.get("user") || "{}");
      const telegramId = String(user.id || "");
      if (!telegramId) return reply({ valid: false, error: "No user" });

      const password = hex(await hmac(enc.encode(env.LOGIN_SECRET), "pw:" + telegramId));

      return reply({
        valid: true,
        telegram_id: telegramId,
        first_name: user.first_name || "",
        start_param: params.get("start_param") || "",
        password,
      });
    } catch (e) {
      return reply({ valid: false, error: "Server error" }, 400);
    }
  },
};
