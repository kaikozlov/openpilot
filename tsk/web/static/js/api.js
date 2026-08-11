export async function fetchJson(url, options = {}, timeoutMs = 4000) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      cache: "no-store",
      ...options,
      signal: controller.signal,
    });
    const result = await response.json();
    return { response, result };
  } finally {
    window.clearTimeout(timer);
  }
}

export function postJson(url, payload = {}, timeoutMs = 15000) {
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }, timeoutMs);
}
