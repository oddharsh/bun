// The stream-level TLS engine (upgradeDuplexToTLS) over an existing stream:
// generic Duplexes, named pipes, TLS over TLS, Http2SecureServer's injected
// connections. A handle-backed net.Socket is read natively (nothing reaches
// its own listeners, as under node's TLSWrap) and only what it had already
// buffered is handed over here, a tick later like node's initRead; any other
// Duplex is read from its `data` events like node's JSStreamSocket — the same
// split as https://github.com/nodejs/node/blob/v26.3.0/lib/internal/tls/wrap.js#L566-L579.
// Returns [nativeTLSHandle, events] (events[0..3]: the engine's
// data/end/drain/close intake, for later removal).
const upgradeDuplexToTLS = $newRustFunction("runtime/socket/socket.rs", "jsUpgradeDuplexToTLS", 2);

function upgradeStreamToTLS(owner: { destroyed: boolean }, connection, options) {
  const { Socket } = require("node:net");
  const transport = connection instanceof Socket ? connection._handle : undefined;
  options.transport = transport;
  const [handle, events] = upgradeDuplexToTLS(connection, options);
  if (transport) process.nextTick(feedBuffered, owner, connection, events[0]);
  else connection.on("data", events[0]);
  connection.on("end", events[1]);
  connection.on("drain", events[2]);
  connection.on("close", events[3]);
  return [handle, events];
}

function feedBuffered(owner, connection, feed) {
  if (owner.destroyed || connection.destroyed) return;
  let chunk;
  while ((chunk = connection.read()) !== null) feed(chunk);
}

export default { upgradeStreamToTLS };
