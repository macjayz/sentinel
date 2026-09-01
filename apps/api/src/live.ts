import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "node:http";
import { withSpan } from "@sentinel/shared";

export function attachLiveServer(server: Server) {
  const wss = new WebSocketServer({ server, path: "/live" });
  const clients = new Set<WebSocket>();

  wss.on("connection", (socket) => {
    clients.add(socket);
    socket.on("close", () => clients.delete(socket));
  });

  return {
    connectionCount() {
      return clients.size;
    },
    publish(channel: string, payload: unknown) {
      void withSpan(
        "sentinel.websocket.publish",
        {
          "sentinel.websocket.channel": channel,
          "sentinel.websocket.clients": clients.size
        },
        async () => {
          const message = JSON.stringify({ channel, payload });
          for (const client of clients) {
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
