# Development-candidate limitations

Watchpost Agent currently supports Linux amd64/arm64 host monitoring and
systemd service installation. macOS and Windows are not supported monitoring
platforms. The local website defaults to loopback and is not intended for
public exposure.

The durable queue is bounded to 256 batches or 8 MiB. Full queues explicitly
drop new collections and report the loss. Upgrade, rotation, unpair, reset and
uninstall are distinct, but no public release or external security assessment
has been completed.

Keyboard focus, reduced motion, responsive layout and forced-colour fallbacks
are implemented. They have not received an external screen-reader or
assistive-technology audit.
