//! Root-port reset rules shared with Linux's xhci_port_state_to_neutral()
//! and hub_port_wait_reset()/hub_port_reset() in drivers/usb/{host,core}.

const CONNECTED: u32 = 1;
const ENABLED: u32 = 1 << 1;
const RESET: u32 = 1 << 4;
const RESET_CHANGE: u32 = 1 << 21;
const CONNECT_CHANGE: u32 = 1 << 17;
const RO: u32 = (1 << 0) | (1 << 3) | (0xf << 10) | (1 << 30);
const RWS: u32 = (0xf << 5) | (1 << 9) | (0x3 << 14) | (0x7 << 25);

pub(super) fn neutral(state: u32) -> u32 {
    state & (RO | RWS)
}

pub(super) fn delay(ns: u64, mut now: impl FnMut() -> u64) -> bool {
    let start = now();
    for _ in 0..50_000_000 {
        if now().wrapping_sub(start) >= ns {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Linux's hub_port_debounce(): require 100 ms of stable connection, checking
/// every 25 ms, with a 1500 ms total limit. A connection-change restarts the wait.
pub(super) fn debounce(
    mut read: impl FnMut() -> u32,
    mut write: impl FnMut(u32),
    mut now: impl FnMut() -> u64,
) -> bool {
    let mut connected = false;
    let mut stable_ms = 0;
    for attempt in 0..=60 {
        let state = read();
        let connection = state & CONNECTED != 0;
        if state & CONNECT_CHANGE == 0 && connection == connected {
            if connection {
                stable_ms += 25;
                if stable_ms >= 100 {
                    return true;
                }
            }
        } else {
            stable_ms = 0;
            connected = connection;
        }
        if state & CONNECT_CHANGE != 0 {
            write(neutral(state) | CONNECT_CHANGE);
        }
        if attempt == 60 || !delay(25_000_000, &mut now) {
            return false;
        }
    }
    false
}

/// Bounded polling equivalent of Linux's reset completion and recovery waits.
/// Never write PED back: it disables an enabled port, and PED|PR is undefined.
/// Return the post-reset status so the caller uses the negotiated speed.
pub(super) fn reset(
    mut read: impl FnMut() -> u32,
    mut write: impl FnMut(u32),
    mut now: impl FnMut() -> u64,
) -> Option<u32> {
    write(neutral(read()) | RESET);
    let start = now();
    // Linux starts root-port reset polling after HUB_ROOT_RESET_TIME (60 ms).
    if !delay(60_000_000, &mut now) {
        return None;
    }
    for _ in 0..50_000_000 {
        let state = read();
        if state & (CONNECTED | ENABLED | RESET) == CONNECTED | ENABLED {
            write(neutral(state) | RESET_CHANGE);
            // Linux allows 50 ms recovery (USB's 10 ms minimum plus margin).
            if !delay(50_000_000, &mut now) {
                return None;
            }
            let state = read();
            return (state & (CONNECTED | ENABLED | RESET) == CONNECTED | ENABLED)
                .then_some(state);
        }
        // Do not fail immediately on CCS=0: some controllers reconnect after reset.
        if now().wrapping_sub(start) >= 800_000_000 {
            break;
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn power_on_preserves_settings_without_disabling_or_resetting_port() {
        let settings = (1 << 9) | (3 << 14) | (5 << 25) | (3 << 5);
        let status = CONNECTED | ENABLED | RESET_CHANGE | (1 << 16) | (1 << 31);
        assert_eq!(neutral(settings | status) | (1 << 9), settings | CONNECTED);
    }

    #[test]
    fn debounce_restarts_on_connection_change_and_disconnect() {
        let clock = Cell::new(0u64);
        let mut states = [CONNECTED | CONNECT_CHANGE, CONNECTED, CONNECTED,
                          0, CONNECTED | CONNECT_CHANGE,
                          CONNECTED, CONNECTED, CONNECTED, CONNECTED].into_iter();
        let mut writes = alloc::vec::Vec::new();
        assert!(debounce(|| states.next().unwrap(), |v| writes.push(v), || {
            let t = clock.get();
            clock.set(t + 25_000_000);
            t
        }));
        assert_eq!(writes, [CONNECTED | CONNECT_CHANGE; 2]);
        assert!(clock.get() >= 200_000_000);
    }

    #[test]
    fn bouncing_connection_never_becomes_ready() {
        assert!(!debounce(|| CONNECTED | CONNECT_CHANGE, |_| {}, {
            let mut t = 0;
            move || { t += 25_000_000; t }
        }));
    }

    #[test]
    fn enabled_port_reset_does_not_disable_port_or_acknowledge_other_changes() {
        let clock = Cell::new(0);
        let mut reads = [u32::MAX, CONNECTED | ENABLED | RESET, 0,
                         CONNECTED | ENABLED | RESET_CHANGE | (2 << 10),
                         CONNECTED | ENABLED | (2 << 10)].into_iter();
        let mut writes = alloc::vec::Vec::new();
        let result = reset(|| reads.next().expect("unexpected read"), |v| writes.push(v), || {
            let t = clock.get();
            clock.set(t + 10_000_000);
            t
        });
        assert_eq!(result, Some(CONNECTED | ENABLED | (2 << 10)));
        assert_eq!(writes, [RO | RWS | RESET,
                           CONNECTED | (2 << 10) | RESET_CHANGE]);
        assert!(clock.get() >= 50_000_000);
    }

    #[test]
    fn stuck_reset_or_disabled_or_disconnected_port_times_out() {
        for state in [CONNECTED | ENABLED | RESET, CONNECTED, 0] {
            let clock = Cell::new(0);
            let mut writes = 0;
            assert_eq!(reset(|| state, |_| writes += 1, || {
                let t = clock.get();
                clock.set(t + 100_000_000);
                t
            }), None);
            assert_eq!(writes, 1);
        }
    }

    #[test]
    fn disconnect_during_recovery_is_not_addressed() {
        let mut reads = [CONNECTED, CONNECTED | ENABLED, 0].into_iter();
        let clock = Cell::new(0);
        assert_eq!(reset(|| reads.next().unwrap(), |_| {}, || {
            let t = clock.get();
            clock.set(t + 50_000_000);
            t
        }), None);
    }
}
