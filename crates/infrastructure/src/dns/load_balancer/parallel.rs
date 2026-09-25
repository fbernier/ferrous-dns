use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;

/// Races every server, taking the first successful answer.
pub(super) async fn query(ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
    match ctx.servers {
        [] => Err(DomainError::TransportNoHealthyServers),
        [only] => query_server(ctx, only).await,
        [s0, s1] => {
            // Both futures stay on the stack (no FuturesUnordered allocation). An
            // error from whichever settles first (e.g. a rejected off-path forgery)
            // falls back to the other instead of failing the attempt.
            let race = async {
                let f0 = query_server(ctx, s0);
                let f1 = query_server(ctx, s1);
                tokio::pin!(f0, f1);

                // Re-polling a completed future panics, so remember which settled.
                let (first_idx, first) = tokio::select! {
                    r = &mut f0 => (0u8, r),
                    r = &mut f1 => (1u8, r),
                };
                match first {
                    Ok(r) => Ok(r),
                    Err(_) if first_idx == 0 => (&mut f1).await,
                    Err(_) => (&mut f0).await,
                }
            };

            timeout(Duration::from_millis(ctx.timeout_ms), race)
                .await
                .unwrap_or_else(|_| {
                    Err(DomainError::TransportTimeout {
                        server: "parallel(2 servers)".to_string(),
                    })
                })
        }
        servers => {
            let mut futs: FuturesUnordered<_> = servers
                .iter()
                .map(|protocol| query_server(ctx, protocol))
                .collect();

            let first_success = async {
                while let Some(result) = futs.next().await {
                    if result.is_ok() {
                        return result;
                    }
                }
                Err(DomainError::TransportAllServersUnreachable)
            };

            timeout(Duration::from_millis(ctx.timeout_ms), first_success)
                .await
                .unwrap_or_else(|_| {
                    Err(DomainError::TransportTimeout {
                        server: format!("parallel({} servers)", servers.len()),
                    })
                })
        }
    }
}
