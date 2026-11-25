use std::{
    fmt,
    ops::{Add, Sub},
};

use jiff::{tz::Offset, SignedDuration};

use super::{
    format::write_date,
    parse::{parse_date, CivilDay},
    TimestampError, UtcTimestamp, SECONDS_PER_DAY,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CalendarDate(UtcTimestamp);

impl CalendarDate {
    pub(super) fn from_timestamp(timestamp: UtcTimestamp) -> Self {
        Self(UtcTimestamp {
            seconds: timestamp.seconds.div_euclid(SECONDS_PER_DAY) * SECONDS_PER_DAY,
            nanos: 0,
        })
    }

    pub fn new(year: i32, month: i8, day: i8) -> Result<Self, TimestampError> {
        CivilDay::new(year, month, day)?.midnight().map(Self)
    }

    pub fn parse(mut input: &str) -> Result<Self, TimestampError> {
        let date = parse_date(&mut input, false)?;
        if !input.is_empty() {
            return Err(TimestampError::Trailing);
        }
        date.resolve()?.midnight().map(Self)
    }

    pub fn midnight(self) -> UtcTimestamp {
        self.0
    }

    pub fn checked_sub_days(self, days: u64) -> Option<Self> {
        self.checked_add_days(-i64::try_from(days).ok()?)
    }

    fn checked_add_days(self, days: i64) -> Option<Self> {
        let seconds = days.checked_mul(SECONDS_PER_DAY)?;
        UtcTimestamp::from_timestamp(self.0.seconds.checked_add(seconds)?, 0).map(Self)
    }
}

impl fmt::Display for CalendarDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (civil, years) = self.0.civil_in(Offset::UTC);
        write_date(formatter, civil.date(), years)
    }
}

impl fmt::Debug for CalendarDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Add<i64> for CalendarDate {
    type Output = Self;

    fn add(self, days: i64) -> Self {
        self.checked_add_days(days)
            .expect("date arithmetic is in range")
    }
}

impl Sub<i64> for CalendarDate {
    type Output = Self;

    fn sub(self, days: i64) -> Self {
        days.checked_neg()
            .and_then(|days| self.checked_add_days(days))
            .expect("date arithmetic is in range")
    }
}

impl Sub for CalendarDate {
    type Output = SignedDuration;

    fn sub(self, earlier: Self) -> SignedDuration {
        self.0 - earlier.0
    }
}
