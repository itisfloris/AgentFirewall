export function redactRpcEndpoint(
  value: string | undefined
): string {
  const raw = value?.trim();

  if (!raw) {
    return "unconfigured-rpc";
  }

  try {
    const parsed = new URL(raw);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return `${parsed.protocol}//${parsed.hostname || "configured-host"}`;
    }

    const port = parsed.port
      ? `:${parsed.port}`
      : "";

    return `${parsed.protocol}//${parsed.hostname}${port}`;
  } catch {
    return "configured-rpc";
  }
}

function redactUrlLikeText(
  message: string
): string {
  return message.replace(
    /https?:\/\/[^\s"'<>)}\]]+/gi,
    candidate => redactRpcEndpoint(candidate)
  );
}

export function sanitizeRpcError(
  error: unknown,
  secretValues: readonly (string | undefined)[] = []
): string {
  let message =
    error instanceof Error
      ? error.message
      : String(error);

  for (const secret of secretValues) {
    const value = secret?.trim();

    if (!value) {
      continue;
    }

    message = message.split(value).join(
      redactRpcEndpoint(value)
    );

    try {
      const parsed = new URL(value);
      const pathParts = parsed.pathname
        .split("/")
        .filter(part => part.length >= 4);

      const sensitiveParts = [
        parsed.username,
        parsed.password,
        parsed.pathname.length > 1
          ? parsed.pathname.slice(1)
          : "",
        ...pathParts,
        ...Array.from(parsed.searchParams.values())
      ].filter(part => part.length >= 4);

      for (const part of sensitiveParts) {
        message = message.split(part).join("[REDACTED]");
      }
    } catch {}
  }

  return redactUrlLikeText(message);
}
