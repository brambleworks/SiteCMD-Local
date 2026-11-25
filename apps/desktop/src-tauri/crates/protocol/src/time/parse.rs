use std::fmt;

use jiff::{
    civil::{Date, Time},
    tz::Offset,
};

use super::{UtcTimestamp, MAX_YEAR, MIN_YEAR, NANOS_PER_SECOND, SECONDS_PER_CYCLE};

#[derive(Debug, Clone, Copy)]
pub enum TimestampError {
    Range,
    Impossible,
    Invalid,
    Short,
    Trailing,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Range => "input is out of range",
            Self::Impossible => "no possible date and time matching input",
            Self::Invalid => "input contains invalid characters",
            Self::Short => "premature end of input",
            Self::Trailing => "trailing input",
        })
    }
}

impl std::error::Error for TimestampError {}

pub struct OffsetTimestamp {
    pub(super) timestamp: UtcTimestamp,
    offset: Offset,
}

impl OffsetTimestamp {
    pub fn to_rfc3339(&self) -> String {
        self.timestamp.rfc3339(self.offset, false)
    }

    pub fn iso_date(&self) -> String {
        self.timestamp.iso_date_in(self.offset)
    }

    pub fn report_datetime(&self) -> String {
        self.timestamp.report_datetime_in(self.offset)
    }
}

pub fn parse_offset(text: &str) -> Result<OffsetTimestamp, TimestampError> {
    if text.len() < 19 {
        return Err(TimestampError::Short);
    }
    let mut input = text;
    let year = number(&mut input, 4, 4)?;
    consume(&mut input, '-')?;
    let month = number(&mut input, 2, 2)?;
    consume(&mut input, '-')?;
    let day = number(&mut input, 2, 2)?;
    let suffix = (|| {
        consume_datetime_separator(&mut input)?;
        let clock = parse_clock(&mut input, true, true, false)?;
        Ok::<_, TimestampError>((clock, parse_zone(input, true)?))
    })();
    // Strict parsing reports an invalid calendar date before a suffix error.
    let date = CivilDay::new(year, month as i8, day as i8)?;
    let (clock, offset) = suffix?;
    Ok(OffsetTimestamp {
        timestamp: date.timestamp(clock, offset)?,
        offset,
    })
}

pub(super) fn parse_serialized(text: &str) -> Result<UtcTimestamp, TimestampError> {
    let mut input = text;
    let date = parse_date(&mut input, true)?;
    consume_datetime_separator(&mut input)?;
    let clock = parse_clock(&mut input, false, true, true)?;
    let offset = parse_zone(input.trim_start(), false)?;
    date.resolve()?.timestamp(clock, offset)
}

fn parse_zone(mut input: &str, strict: bool) -> Result<Offset, TimestampError> {
    let (sign, hours, minutes) = if !strict
        && input
            .get(..3)
            .is_some_and(|s| s.eq_ignore_ascii_case("UTC"))
    {
        input = &input[3..];
        (1, 0, 0)
    } else if let Some(rest) = input.strip_prefix(['z', 'Z']) {
        input = rest;
        (1, 0, 0)
    } else {
        let sign = match input.chars().next().ok_or(TimestampError::Short)? {
            '+' => 1,
            '-' | '\u{2212}' => -1,
            _ => return Err(TimestampError::Invalid),
        };
        input = &input[input.chars().next().expect("sign is present").len_utf8()..];
        let hours = number(&mut input, 2, 2)?;
        if strict {
            consume(&mut input, ':')?;
        } else {
            input = input.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
        }
        let minutes = number(&mut input, 2, 2)?;
        if minutes > 59 {
            return Err(TimestampError::Range);
        }
        (sign, hours, minutes)
    };
    if !strict {
        input = input.trim_start();
    }
    if !input.is_empty() {
        return Err(TimestampError::Trailing);
    }
    if hours > 23 {
        return Err(TimestampError::Range);
    }
    Offset::from_seconds(sign * (hours * 3600 + minutes * 60)).map_err(|_| TimestampError::Range)
}

fn consume_datetime_separator(input: &mut &str) -> Result<(), TimestampError> {
    *input = input
        .strip_prefix(['T', 't', ' '])
        .ok_or(if input.is_empty() {
            TimestampError::Short
        } else {
            TimestampError::Invalid
        })?;
    Ok(())
}

pub(super) struct CivilDay {
    pub(super) date: Date,
    pub(super) cycles: i64,
}

impl CivilDay {
    pub(super) fn new(year: i32, month: i8, day: i8) -> Result<Self, TimestampError> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return Err(TimestampError::Range);
        }
        // Keep room for offset conversion around the first and last day of the cycle.
        let representative = if (-9998..=9998).contains(&year) {
            year
        } else {
            2000 + (year - 2000).rem_euclid(400)
        };
        let date =
            Date::new(representative as i16, month, day).map_err(|_| TimestampError::Range)?;
        let cycles = i64::from((year - representative) / 400);
        Ok(Self { date, cycles })
    }

    pub(super) fn midnight(self) -> Result<UtcTimestamp, TimestampError> {
        self.timestamp(
            Clock {
                time: Time::MIN,
                leap: false,
            },
            Offset::UTC,
        )
    }

    fn timestamp(self, clock: Clock, offset: Offset) -> Result<UtcTimestamp, TimestampError> {
        let timestamp = offset
            .to_timestamp(self.date.to_datetime(clock.time))
            .map_err(|_| TimestampError::Range)?;
        let normalized = UtcTimestamp::from(timestamp);
        UtcTimestamp::from_timestamp(
            normalized.seconds + self.cycles * SECONDS_PER_CYCLE,
            (normalized.nanos + i32::from(clock.leap) * NANOS_PER_SECOND) as u32,
        )
        .ok_or(TimestampError::Impossible)
    }
}

pub(super) struct DateFields {
    year: i32,
    month: i8,
    day: i8,
}

impl DateFields {
    pub(super) fn resolve(self) -> Result<CivilDay, TimestampError> {
        CivilDay::new(self.year, self.month, self.day)
    }
}

pub(super) fn parse_date(input: &mut &str, relaxed: bool) -> Result<DateFields, TimestampError> {
    *input = input.trim_start();
    let year = match input.chars().next() {
        Some(sign @ ('+' | '-')) => {
            *input = &input[1..];
            let digits = digits(input, 1, usize::MAX)?;
            let value = digits.parse::<i64>().map_err(|_| TimestampError::Range)?;
            let signed = if sign == '-' { -value } else { value };
            i32::try_from(signed).map_err(|_| TimestampError::Range)?
        }
        _ => number(input, 1, 4)?,
    };
    if relaxed {
        *input = input.trim_start();
    }
    consume(input, '-')?;
    *input = input.trim_start();
    let month = number(input, 1, 2)?;
    if !(1..=12).contains(&month) {
        return Err(TimestampError::Range);
    }
    if relaxed {
        *input = input.trim_start();
    }
    consume(input, '-')?;
    *input = input.trim_start();
    let day = number(input, 1, 2)?;
    if !(1..=31).contains(&day) {
        return Err(TimestampError::Range);
    }
    Ok(DateFields {
        year,
        month: month as i8,
        day: day as i8,
    })
}

struct Clock {
    time: Time,
    leap: bool,
}

pub(super) fn parse_wall(mut input: &str, separator: char) -> Result<UtcTimestamp, TimestampError> {
    let date = parse_date(&mut input, false)?;
    if separator == ' ' {
        input = input.trim_start();
    } else {
        consume(&mut input, separator)?;
    }
    let clock = parse_clock(&mut input, false, false, false)?;
    if !input.is_empty() {
        return Err(TimestampError::Trailing);
    }
    date.resolve()?.timestamp(clock, Offset::UTC)
}

fn parse_clock(
    input: &mut &str,
    strict: bool,
    fractions: bool,
    relaxed: bool,
) -> Result<Clock, TimestampError> {
    let hour = clock_field(input, strict, 23)?;
    if relaxed {
        *input = input.trim_start();
    }
    consume(input, ':')?;
    let minute = clock_field(input, strict, 59)?;
    if relaxed {
        *input = input.trim_start();
    }
    consume(input, ':')?;
    let second = clock_field(input, strict, 60)?;
    let leap = second == 60;
    let nanos = if fractions {
        if let Some(rest) = input.strip_prefix('.') {
            *input = rest;
            let start = input.len();
            let nanos = number(input, 1, 9)?;
            let count = start - input.len();
            *input = input.trim_start_matches(|c: char| c.is_ascii_digit());
            nanos * 10_i32.pow((9 - count) as u32)
        } else {
            0
        }
    } else {
        0
    };
    let time = Time::new(
        hour as i8,
        minute as i8,
        (second - i32::from(leap)) as i8,
        nanos,
    )
    .map_err(|_| TimestampError::Range)?;
    Ok(Clock { time, leap })
}

fn clock_field(input: &mut &str, strict: bool, max: i32) -> Result<i32, TimestampError> {
    if !strict {
        *input = input.trim_start();
    }
    let value = number(input, if strict { 2 } else { 1 }, 2)?;
    if !strict && value > max {
        return Err(TimestampError::Range);
    }
    Ok(value)
}

fn number(input: &mut &str, min: usize, max: usize) -> Result<i32, TimestampError> {
    digits(input, min, max)?
        .parse()
        .map_err(|_| TimestampError::Range)
}

fn digits<'a>(input: &mut &'a str, min: usize, max: usize) -> Result<&'a str, TimestampError> {
    let count = input
        .bytes()
        .take(max)
        .take_while(u8::is_ascii_digit)
        .count();
    if count < min {
        return Err(if input.len() < min {
            TimestampError::Short
        } else {
            TimestampError::Invalid
        });
    }
    let (value, remaining) = input.split_at(count);
    *input = remaining;
    Ok(value)
}

fn consume(input: &mut &str, expected: char) -> Result<(), TimestampError> {
    *input = input.strip_prefix(expected).ok_or(if input.is_empty() {
        TimestampError::Short
    } else {
        TimestampError::Invalid
    })?;
    Ok(())
}

impl std::ops::Add<jiff::SignedDuration> for OffsetTimestamp {
    type Output = Self;

    fn add(self, duration: jiff::SignedDuration) -> Self {
        Self {
            timestamp: self.timestamp + duration,
            offset: self.offset,
        }
    }
}
