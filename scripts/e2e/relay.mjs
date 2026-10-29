import { WebSocketServer, WebSocket } from 'ws';
import { verifyEvent } from 'nostr-tools/pure';
import { once } from 'node:events';

export async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, maxPayload: 524288 });
  await once(server, 'listening');
  const events = new Map();
  const subscriptions = new Map();
  let requests = 0;
  let rejecting = false;
  const send = (socket, value) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
  };
  const matches = (event, filter) => (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter.authors || filter.authors.includes(event.pubkey))
    && (!filter.since || event.created_at >= filter.since)
    && (!filter['#p'] || event.tags.some(tag => tag[0] === 'p' && filter['#p'].includes(tag[1])));
  const deliver = event => {
    for (const [socket, filters] of subscriptions) {
      for (const [id, queries] of filters) {
        if (queries.some(filter => matches(event, filter))) send(socket, ['EVENT', id, event]);
      }
    }
  };
  server.on('connection', socket => {
    subscriptions.set(socket, new Map());
    socket.on('error', () => {});
    socket.on('close', () => subscriptions.delete(socket));
    socket.on('message', bytes => {
      const [kind, id, ...rest] = JSON.parse(bytes);
      if (kind === 'EVENT') {
        const event = id;
        const accepted = !rejecting && verifyEvent(event);
        if (accepted) {
          events.set(event.id, event);
          deliver(event);
        }
        send(socket, ['OK', event.id, accepted, accepted ? '' : 'blocked: test rejection']);
      } else if (kind === 'REQ') {
        requests++;
        subscriptions.get(socket).set(id, rest);
        for (const event of events.values()) {
          if (rest.some(filter => matches(event, filter))) send(socket, ['EVENT', id, event]);
        }
        send(socket, ['EOSE', id]);
      } else if (kind === 'CLOSE') {
        subscriptions.get(socket).delete(id);
      }
    });
  });
  return {
    url: 'ws://127.0.0.1:' + server.address().port + '/',
    events,
    get requests() { return requests; },
    reject(value) { rejecting = value; },
    replay() { for (const event of events.values()) { deliver(event); deliver(event); } },
    disconnect() { for (const socket of server.clients) socket.terminate(); },
    async close() {
      for (const socket of server.clients) socket.terminate();
      await new Promise(resolve => server.close(resolve));
    },
  };
}
