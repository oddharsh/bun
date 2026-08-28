export default {
  kArmHandshakeTimeout: Symbol("kArmHandshakeTimeout"),
  // Internal handshake-settled signal: server-side sockets emit no user
  // 'secureConnect' (node parity), so internal deferrals park on this instead.
  kSecureConnectDone: Symbol("kSecureConnectDone"),
  kVerifyError: Symbol("kVerifyError"),
  // The stream-level TLS engine's feeder while it runs over this net.Socket:
  // node:net's data handlers hand each chunk to it instead of push()ing it.
  // See internal/net/tlsFeeder.
  kTLSUpgradeSink: Symbol("kTLSUpgradeSink"),
};
