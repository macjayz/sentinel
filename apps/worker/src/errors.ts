import { normalizeErrorMessage, SentinelEvent } from "@sentinel/shared";

export type ErrorFingerprint = {
  key: string;
  errorType: string;
  message: string;
  affectedEndpoint: string;
};

export function fingerprintError(event: SentinelEvent): ErrorFingerprint | null {
  if (!event.error) return null;

  const affectedEndpoint = `${event.request.method} ${event.request.route ?? event.request.path}`;
  const normalizedMessage = normalizeErrorMessage(event.error.message);

  return {
    key: `${event.projectId}:${event.error.type}:${affectedEndpoint}:${normalizedMessage}`,
    errorType: event.error.type,
    message: event.error.message,
    affectedEndpoint
  };
}
