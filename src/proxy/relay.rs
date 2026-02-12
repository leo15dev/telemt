//! Bidirectional Relay
    
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;
    use tracing::{debug, trace, warn};
    use crate::error::Result;
    use crate::stats::Stats;
    use crate::stream::BufferPool;
    
    // Activity timeout for iOS compatibility (30 minutes)
    const ACTIVITY_TIMEOUT_SECS: u64 = 1800;
    
    /// Relay data bidirectionally between client and server.
    ///
    /// Uses a single-task select!-based loop instead of spawning two tasks.
    /// This eliminates:
    /// - 2× task spawn overhead per connection
    /// - Zombie task problem (old code used select! on JoinHandles but
    ///   never aborted the losing task — it would run for up to 30 min)
    /// - Extra Arc<AtomicU64> allocations for cross-task byte counters
    ///
    /// The flush()-per-write was also removed: TCP_NODELAY is set on all
    /// sockets (socket.rs), so data is pushed immediately without Nagle
    /// buffering. Explicit flush() on every small read was causing a
    /// syscall storm and defeating CryptoWriter's internal coalescing.
    pub async fn relay_bidirectional<CR, CW, SR, SW>(
        mut client_reader: CR,
        mut client_writer: CW,
        mut server_reader: SR,
        mut server_writer: SW,
        user: &str,
        stats: Arc<Stats>,
        buffer_pool: Arc<BufferPool>,
    ) -> Result<()>
    where
        CR: AsyncRead + Unpin + Send + 'static,
        CW: AsyncWrite + Unpin + Send + 'static,
        SR: AsyncRead + Unpin + Send + 'static,
        SW: AsyncWrite + Unpin + Send + 'static,
    {
        // Get buffers from pool — one per direction
        let mut c2s_buf = buffer_pool.get();
        let cap = c2s_buf.capacity();
        c2s_buf.resize(cap, 0);
    
        let mut s2c_buf = buffer_pool.get();
        let cap = s2c_buf.capacity();
        s2c_buf.resize(cap, 0);
    
        let activity_timeout = Duration::from_secs(ACTIVITY_TIMEOUT_SECS);
    
        let mut c2s_total: u64 = 0;
        let mut s2c_total: u64 = 0;
        let mut c2s_msgs: u64 = 0;
        let mut s2c_msgs: u64 = 0;
    
        // For periodic rate logging
        let mut c2s_prev: u64 = 0;
        let mut s2c_prev: u64 = 0;
        let mut last_log = Instant::now();
    
        let user_owned = user.to_string();
    
        loop {
            tokio::select! {
                biased;
    
                // Client -> Server direction
                result = tokio::time::timeout(activity_timeout, client_reader.read(&mut c2s_buf)) => {
                    match result {
                        Err(_) => {
                            // Activity timeout
                            warn!(
                                user = %user_owned,
                                c2s_bytes = c2s_total,
                                s2c_bytes = s2c_total,
                                "Activity timeout (C->S)"
                            );
                            break;
                        }
                        Ok(Ok(0)) => {
                            // Client closed
                            debug!(
                                user = %user_owned,
                                c2s_bytes = c2s_total,
                                s2c_bytes = s2c_total,
                                "Client closed connection"
                            );
                            break;
                        }
                        Ok(Ok(n)) => {
                            c2s_total += n as u64;
                            c2s_msgs += 1;
    
                            stats.add_user_octets_from(&user_owned, n as u64);
                            stats.increment_user_msgs_from(&user_owned);
    
                            trace!(user = %user_owned, bytes = n, "C->S");
    
                            // Write without flush — TCP_NODELAY handles push
                            if let Err(e) = server_writer.write_all(&c2s_buf[..n]).await {
                                debug!(user = %user_owned, error = %e, "Write to server failed");
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            debug!(user = %user_owned, error = %e, "Client read error");
                            break;
                        }
                    }
                }
    
                // Server -> Client direction
                result = tokio::time::timeout(activity_timeout, server_reader.read(&mut s2c_buf)) => {
                    match result {
                        Err(_) => {
                            warn!(
                                user = %user_owned,
                                c2s_bytes = c2s_total,
                                s2c_bytes = s2c_total,
                                "Activity timeout (S->C)"
                            );
                            break;
                        }
                        Ok(Ok(0)) => {
                            debug!(
                                user = %user_owned,
                                c2s_bytes = c2s_total,
                                s2c_bytes = s2c_total,
                                "Server closed connection"
                            );
                            break;
                        }
                        Ok(Ok(n)) => {
                            s2c_total += n as u64;
                            s2c_msgs += 1;
    
                            stats.add_user_octets_to(&user_owned, n as u64);
                            stats.increment_user_msgs_to(&user_owned);
    
                            trace!(user = %user_owned, bytes = n, "S->C");
    
                            if let Err(e) = client_writer.write_all(&s2c_buf[..n]).await {
                                debug!(user = %user_owned, error = %e, "Write to client failed");
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            debug!(user = %user_owned, error = %e, "Server read error");
                            break;
                        }
                    }
                }
            }
    
            // Periodic rate logging (every 10s)
            let elapsed = last_log.elapsed();
            if elapsed > Duration::from_secs(10) {
                let secs = elapsed.as_secs_f64();
                let c2s_delta = c2s_total - c2s_prev;
                let s2c_delta = s2c_total - s2c_prev;
    
                debug!(
                    user = %user_owned,
                    c2s_kbps = (c2s_delta as f64 / secs / 1024.0) as u64,
                    s2c_kbps = (s2c_delta as f64 / secs / 1024.0) as u64,
                    c2s_total = c2s_total,
                    s2c_total = s2c_total,
                    "Relay active"
                );
    
                c2s_prev = c2s_total;
                s2c_prev = s2c_total;
                last_log = Instant::now();
            }
        }
    
        // Clean shutdown of both directions
        let _ = server_writer.shutdown().await;
        let _ = client_writer.shutdown().await;
    
        debug!(
            user = %user_owned,
            c2s_bytes = c2s_total,
            s2c_bytes = s2c_total,
            c2s_msgs = c2s_msgs,
            s2c_msgs = s2c_msgs,
            "Relay finished"
        );
    
        Ok(())
    }
    