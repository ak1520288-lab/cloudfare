const apiBase = import.meta.env.VITE_API_BASE_URL || "";

export async function apiRequest(
  path,
  { method = "GET", body, csrfToken, signal } = {},
) {
  const headers = new Headers();
  if (body !== undefined) headers.set("Content-Type", "application/json");
  if (csrfToken) headers.set("X-CSRF-Token", csrfToken);

  let response;
  try {
    response = await fetch(`${apiBase}/api${path}`, {
      method,
      credentials: "include",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error(
      "Cannot reach the backend. Check that the API and its services are running.",
      { cause: error },
    );
  }

  if (response.status === 204) return null;

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `Backend request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}
