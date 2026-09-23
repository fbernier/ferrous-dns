use dashmap::DashMap;
use ferrous_dns_domain::{AuthConfig, DomainError};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};
use tracing::warn;

/// Above this many tracked clients, expired windows are pruned on the next failure.
const PRUNE_THRESHOLD: usize = 1024;

/// Failed attempts seen from one client since its window opened.
struct FailureWindow {
    opened_at: Instant,
    failures: u32,
}

/// Per-client lockout shared by every credential check — password, app
/// password and second factor. After `max_failures` wrong attempts inside
/// `window`, the client is refused without its credential being checked until
/// the window closes; a successful login clears the count.
///
/// Callers key it by the TCP peer address, never by a forwarded header: a
/// client-supplied `X-Forwarded-For` would reset the count on every attempt.
/// IPv6 clients share one window per /64, the smallest block a single host is
/// normally handed, so rotating addresses inside it gains nothing.
pub struct LoginRateLimiter {
    max_failures: u32,
    window: Duration,
    windows: DashMap<IpAddr, FailureWindow>,
}

impl LoginRateLimiter {
    /// `max_failures = 0` disables the limiter.
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            windows: DashMap::new(),
        }
    }

    /// Builds the limiter from `login_rate_limit_attempts` and
    /// `login_rate_limit_window_secs`.
    pub fn from_config(config: &AuthConfig) -> Self {
        Self::new(
            config.login_rate_limit_attempts,
            Duration::from_secs(config.login_rate_limit_window_secs),
        )
    }

    /// Refuses a client that used up its attempts in the current window.
    pub fn check(&self, client: IpAddr) -> Result<(), DomainError> {
        self.check_at(client, Instant::now())
    }

    /// Counts one wrong credential from `client`.
    pub fn record_failure(&self, client: IpAddr) {
        self.record_failure_at(client, Instant::now());
    }

    /// Clears the count after a successful login.
    pub fn reset(&self, client: IpAddr) {
        self.windows.remove(&window_key(client));
    }

    fn check_at(&self, client: IpAddr, now: Instant) -> Result<(), DomainError> {
        if self.max_failures == 0 {
            return Ok(());
        }
        let Some(window) = self.windows.get(&window_key(client)) else {
            return Ok(());
        };
        let is_open = now.duration_since(window.opened_at) < self.window;
        if is_open && window.failures >= self.max_failures {
            return Err(DomainError::RateLimited);
        }
        Ok(())
    }

    fn record_failure_at(&self, client: IpAddr, now: Instant) {
        if self.max_failures == 0 {
            return;
        }
        if self.windows.len() > PRUNE_THRESHOLD {
            self.windows
                .retain(|_, window| now.duration_since(window.opened_at) < self.window);
        }

        let key = window_key(client);
        let mut window = self.windows.entry(key).or_insert(FailureWindow {
            opened_at: now,
            failures: 0,
        });
        if now.duration_since(window.opened_at) >= self.window {
            *window = FailureWindow {
                opened_at: now,
                failures: 0,
            };
        }
        window.failures = window.failures.saturating_add(1);
        if window.failures == self.max_failures {
            warn!(client = %key, "Login locked out after too many failed attempts");
        }
    }
}

/// IPv4 (including IPv4-mapped IPv6 from a dual-stack socket) keys by address,
/// IPv6 by its /64.
fn window_key(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(prefix))
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const WINDOW: Duration = Duration::from_secs(900);

    fn fail(limiter: &LoginRateLimiter, client: IpAddr, times: u32, now: Instant) {
        for _ in 0..times {
            limiter.record_failure_at(client, now);
        }
    }

    #[test]
    fn allows_until_max_failures_reached() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();

        fail(&limiter, CLIENT, 2, now);
        assert!(limiter.check_at(CLIENT, now).is_ok());

        fail(&limiter, CLIENT, 1, now);
        assert!(matches!(
            limiter.check_at(CLIENT, now),
            Err(DomainError::RateLimited)
        ));
    }

    #[test]
    fn lockout_ends_when_window_closes() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        fail(&limiter, CLIENT, 3, now);

        assert!(limiter
            .check_at(CLIENT, now + WINDOW - Duration::from_secs(1))
            .is_err());
        assert!(limiter.check_at(CLIENT, now + WINDOW).is_ok());
    }

    #[test]
    fn failure_after_window_closes_starts_a_new_count() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        fail(&limiter, CLIENT, 2, now);

        let later = now + WINDOW;
        fail(&limiter, CLIENT, 2, later);
        assert!(limiter.check_at(CLIENT, later).is_ok());
    }

    #[test]
    fn reset_clears_failures() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        fail(&limiter, CLIENT, 3, now);

        limiter.reset(CLIENT);
        assert!(limiter.check_at(CLIENT, now).is_ok());
    }

    #[test]
    fn zero_max_failures_disables_limiter() {
        let limiter = LoginRateLimiter::new(0, WINDOW);
        let now = Instant::now();
        fail(&limiter, CLIENT, 100, now);

        assert!(limiter.check_at(CLIENT, now).is_ok());
    }

    #[test]
    fn clients_have_independent_windows() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        fail(&limiter, CLIENT, 3, now);

        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert!(limiter.check_at(other, now).is_ok());
    }

    #[test]
    fn ipv6_addresses_in_same_64_share_a_window() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        for host in 1..=3u16 {
            let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host));
            limiter.record_failure_at(client, now);
        }

        let same_64 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xffff, 0, 0, 9));
        let other_64 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        assert!(limiter.check_at(same_64, now).is_err());
        assert!(limiter.check_at(other_64, now).is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_shares_window_with_ipv4() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped());
        fail(&limiter, mapped, 3, now);

        assert!(limiter.check_at(CLIENT, now).is_err());
    }

    #[test]
    fn expired_windows_are_pruned_once_threshold_exceeded() {
        let limiter = LoginRateLimiter::new(3, WINDOW);
        let now = Instant::now();
        for host in 0..=PRUNE_THRESHOLD as u32 {
            limiter.record_failure_at(IpAddr::V4(Ipv4Addr::from(host)), now);
        }

        limiter.record_failure_at(CLIENT, now + WINDOW);
        assert_eq!(limiter.windows.len(), 1);
    }
}
