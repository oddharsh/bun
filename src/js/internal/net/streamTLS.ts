// The stream-level TLS engine (upgradeDuplexToTLS) over an existing stream. A
// handle-backed net.Socket is read natively (like under node's TLSWrap) and
// hands over only what it had already buffered; any other Duplex is driven
// from its events (node's JSStreamSocket). Same split as
// https://github.com/nodejs/node/blob/v26.3.0/lib/internal/tls/wrap.js#L566-L579.
const upgradeDuplexToTLS = $newRustFunction("runtime/socket/socket.rs", "jsUpgradeDuplexToTLS", 2);

function upgradeStreamToTLS(owner: { destroyed: boolean }, connection, options) {
  const { Socket } = require("node:net");
  const transport = connection instanceof Socket ? connection._handle : undefined;
  options.transport = transport;
  const [handle, events] = upgradeDuplexToTLS(connection, options);
  if (transport) {
    // What it already buffered waits for feedBuffered rather than flow() to
    // nobody; an EOF already taken off the wire is stream state now (a later
    // one arrives natively).
    connection.pause();
    const ended = connection._readableState?.ended;
    process.nextTick(feedBuffered, owner, connection, events[0], ended ? events[1] : undefined);
  } else {
    connection.on("data", events[0]);
    connection.on("end", events[1]);
    connection.on("close", events[3]);
  }
  // Ciphertext out goes through `connection`'s Writable either way.
  connection.on("drain", events[2]);
  return [handle, events];
}

function feedBuffered(owner, connection, feed, end) {
  if (owner.destroyed || connection.destroyed) return;
  let chunk;
  while ((chunk = connection.read()) !== null) feed(chunk);
  end?.();
}

export default { upgradeStreamToTLS };
