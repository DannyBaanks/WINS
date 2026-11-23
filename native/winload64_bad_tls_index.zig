//! Negative control: every image gets TLS slot 0, so images overwrite each other's
//! implicit-TLS block. The Wine-oracle diff must catch it.
pub const winload64_bug = @import("winload64.zig").Bug.shared_tls_index;
pub const main = @import("winload64.zig").main;
