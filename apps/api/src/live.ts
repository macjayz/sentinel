import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "node:http";
import { withSpan } from "@sentinel/shared";

export type LiveAuthenticator = (token: string | undefined, projectId: string | undefined) => Promise<boolean>;

export function attachLiveServer(server: Server, authenticate?: LiveAuthenticator) {
  const wss = new WebSocketServer({
    server,
    path: "/live",
    verifyClient: (info, done) => {
      if (!authenticate) {
        done(true);
        return;
      }

      const url = new URL(info.req.url ?? "/live", "http://localhost");
      const token = url.searchParams.get("token") ?? undefined;
      const projectId = url.searchParams.get("projectId") ?? undefined;

      authenticate(token, projectId)
        .then((allowed) => done(allowed, allowed ? undefined : 401))
        .catch(() => done(false, 401));
    }
  });
  const clients = new Map<WebSocket, string | null>();

  wss.on("connection", (socket, request) => {
    const url = new URL(request.url ?? "/live", "http://localhost");
    clients.set(socket, url.searchParams.get("projectId"));
    socket.on("close", () => clients.delete(socket));
  });

  return {
    connectionCount() {
      return clients.size;
    },
    publish(channel: string, payload: unknown) {
      return this.publishToProject(channel, payload);
    },
    publishToProject(channel: string, payload: unknown, projectId?: string) {
      void withSpan(
        "sentinel.websocket.publish",
        {
          "sentinel.websocket.channel": channel,
          "sentinel.websocket.clients": clients.size
        },
        async () => {
          const message = JSON.stringify({ channel, payload });
          for (const [client, clientProjectId] of clients) {
            if (projectId && clientProjectId !== projectId) continue;
            if (client.readyState === WebSocket.OPEN) client.send(message);
          }
        }
      );
    },
    close() {
      wss.close();
    }
  };
}
