//! Logical time and challenge deadlines.

/// Logical clock instant used by Beacon core.
///
/// Backends map this to wall clock, block height, or another totally ordered
/// timeline. The mock backend typically advances an in-memory counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(pub u64);

impl Instant {
    /// Create an instant from a raw tick / height / timestamp unit.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Borrow the raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Deadline after which a challenge window (or dispute) may close.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Deadline(pub Instant);

impl Deadline {
    /// Create a deadline at the given instant.
    #[must_use]
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }

    /// Create a deadline from a raw logical time value.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(Instant::new(value))
    }

    /// Returns `true` if `now` is at or past this deadline.
    #[must_use]
    pub const fn is_reached(self, now: Instant) -> bool {
        now.0 >= self.0 .0
    }

    /// The instant at which this deadline fires.
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_ordering() {
        let d = Deadline::from_raw(10);
        assert!(!d.is_reached(Instant::new(9)));
        assert!(d.is_reached(Instant::new(10)));
        assert!(d.is_reached(Instant::new(11)));
    }
}
