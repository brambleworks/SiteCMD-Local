//! Timestamp and calendar representations for persisted and wire data.

mod date;
mod format;
mod parse;

pub use date::CalendarDate;
pub use format::{format_offset, format_wall_time};
pub use parse::{parse_offset, OffsetTimestamp, TimestampError};

use std::fmt;
use std::ops::{Add, Sub};

pub use jiff::SignedDuration;
use jiff::{tz::Offset, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const NANOS_PER_SECOND: i32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_CYCLE: i64 = 146_097 * SECONDS_PER_DAY;
const MIN_YEAR: i32 = -262_143;
const MAX_YEAR: i32 = 262_142;
const MIN_SECOND: i64 = -8_334_601_228_800;
const MAX_SECOND: i64 = 8_210_266_876_799;

/// Stores leap seconds and extended years found in existing records.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTimestamp {
    seconds: i64,
    nanos: i32,
}

impl UtcTimestamp {
    pub fn from_timestamp(seconds: i64, nanos: u32) -> Option<Self> {
        let limit = if seconds.rem_euclid(60) == 59 {
            2 * NANOS_PER_SECOND
        } else {
            NANOS_PER_SECOND
        };
        ((MIN_SECOND..=MAX_SECOND).contains(&seconds) && nanos < limit as u32).then_some(Self {
            seconds,
            nanos: nanos as i32,
        })
    }

    pub fn from_timestamp_millis(millis: i64) -> Option<Self> {
        Self::from_timestamp(
            millis.div_euclid(1000),
            (millis.rem_euclid(1000) * 1_000_000) as u32,
        )
    }

    pub fn parse_from_rfc3339(text: &str) -> Result<Self, TimestampError> {
        parse_offset(text).map(|parsed| parsed.timestamp)
    }

    pub fn parse_wall_time(text: &str, separator: char) -> Result<Self, TimestampError> {
        parse::parse_wall(text, separator)
    }

    pub fn timestamp(self) -> i64 {
        self.seconds
    }

    pub fn timestamp_millis(self) -> i64 {
        self.seconds * 1000 + i64::from(self.nanos / 1_000_000)
    }

    pub fn timestamp_nanos_opt(self) -> Option<i64> {
        (i128::from(self.seconds) * i128::from(NANOS_PER_SECOND) + i128::from(self.nanos))
            .try_into()
            .ok()
    }

    pub fn date(self) -> CalendarDate {
        CalendarDate::from_timestamp(self)
    }

    fn civil_in(self, offset: Offset) -> (jiff::civil::DateTime, i64) {
        let nanos = self.nanos % NANOS_PER_SECOND;
        let (timestamp, years) = match Timestamp::new(self.seconds, nanos) {
            Ok(timestamp) => (timestamp, 0),
            Err(_) => {
                // Gregorian dates and weekdays repeat every 400 years.
                let cycles = self.seconds.div_euclid(SECONDS_PER_CYCLE);
                let Ok(timestamp) =
                    Timestamp::new(self.seconds.rem_euclid(SECONDS_PER_CYCLE), nanos)
                else {
                    unreachable!("Gregorian cycle fits in a timestamp");
                };
                (timestamp, cycles * 400)
            }
        };
        (offset.to_datetime(timestamp), years)
    }

    pub fn duration_since(self, earlier: Self) -> SignedDuration {
        let later_clock = self.seconds.rem_euclid(SECONDS_PER_DAY);
        let earlier_clock = earlier.seconds.rem_euclid(SECONDS_PER_DAY);
        let crossed_leap =
            i64::from(later_clock > earlier_clock && earlier.nanos >= NANOS_PER_SECOND)
                - i64::from(later_clock < earlier_clock && self.nanos >= NANOS_PER_SECOND);
        SignedDuration::new(
            self.seconds - earlier.seconds + crossed_leap,
            self.nanos - earlier.nanos,
        )
    }
}

impl std::str::FromStr for UtcTimestamp {
    type Err = TimestampError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse::parse_serialized(text)
    }
}

impl From<Timestamp> for UtcTimestamp {
    fn from(timestamp: Timestamp) -> Self {
        let nanos = timestamp.as_nanosecond();
        Self {
            seconds: nanos.div_euclid(i128::from(NANOS_PER_SECOND)) as i64,
            nanos: nanos.rem_euclid(i128::from(NANOS_PER_SECOND)) as i32,
        }
    }
}

impl Add<SignedDuration> for UtcTimestamp {
    type Output = Self;

    fn add(self, duration: SignedDuration) -> Self {
        let mut seconds = self.seconds;
        let mut nanos = i64::from(self.nanos) + i64::from(duration.subsec_nanos());
        let second = i64::from(NANOS_PER_SECOND);
        if self.nanos >= NANOS_PER_SECOND {
            if duration.as_secs() == 0 && nanos < 2 * second {
                return Self {
                    seconds,
                    nanos: nanos as i32,
                };
            }
            if duration.as_secs() < 0 {
                seconds += 1;
            }
            nanos -= second;
        }
        seconds
            .checked_add(duration.as_secs())
            .and_then(|value| value.checked_add(nanos.div_euclid(second)))
            .and_then(|value| Self::from_timestamp(value, nanos.rem_euclid(second) as u32))
            .expect("timestamp arithmetic is in range")
    }
}

impl Sub<SignedDuration> for UtcTimestamp {
    type Output = Self;

    fn sub(self, duration: SignedDuration) -> Self {
        self + -duration
    }
}

impl Sub for UtcTimestamp {
    type Output = SignedDuration;

    fn sub(self, earlier: Self) -> SignedDuration {
        self.duration_since(earlier)
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.rfc3339(Offset::UTC, true))
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = UtcTimestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RFC 3339 formatted date and time string")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
                parse::parse_serialized(text).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

pub fn days(days: i64) -> SignedDuration {
    SignedDuration::from_hours(days.checked_mul(24).expect("day count is in range"))
}

pub fn whole_days(duration: SignedDuration) -> i64 {
    duration.as_secs() / SECONDS_PER_DAY
}
