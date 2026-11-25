use std::fmt::{self, Write};

use jiff::{
    civil::{Date, DateTime},
    tz::Offset,
};

use super::{UtcTimestamp, NANOS_PER_SECOND};

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

impl UtcTimestamp {
    pub fn iso_date(self) -> String {
        self.iso_date_in(Offset::UTC)
    }

    pub(super) fn iso_date_in(self, offset: Offset) -> String {
        let (civil, years) = self.civil_in(offset);
        let mut text = String::with_capacity(10);
        write_date(&mut text, civil.date(), years).expect("writing to a string succeeds");
        text
    }

    pub fn iso_datetime(self) -> String {
        self.iso_datetime_in(Offset::UTC)
    }

    fn iso_datetime_in(self, offset: Offset) -> String {
        let (civil, years) = self.civil_in(offset);
        let mut text = String::with_capacity(35);
        let leap = self.nanos >= NANOS_PER_SECOND;
        write_datetime(&mut text, civil, years, 'T', leap).expect("writing to a string succeeds");
        text
    }

    pub fn report_date(self) -> String {
        let (civil, years) = self.civil_in(Offset::UTC);
        report_date(civil.date(), years)
    }

    pub fn report_datetime(self) -> String {
        self.report_datetime_in(Offset::UTC)
    }

    pub(super) fn report_datetime_in(self, offset: Offset) -> String {
        let (civil, years) = self.civil_in(offset);
        let mut text = report_date(civil.date(), years);
        let hour = (civil.hour() + 11) % 12 + 1;
        let minute = civil.minute();
        let meridiem = if civil.hour() < 12 { "AM" } else { "PM" };
        write!(text, " at {hour:2}:{minute:02} {meridiem}").expect("writing to a string succeeds");
        text
    }

    pub fn wall_minute(self) -> String {
        let (civil, years) = self.civil_in(Offset::UTC);
        let mut text = String::with_capacity(16);
        write_date(&mut text, civil.date(), years).expect("writing to a string succeeds");
        let (hour, minute) = (civil.hour(), civil.minute());
        write!(text, " {hour:02}:{minute:02}").expect("writing to a string succeeds");
        text
    }

    pub fn to_rfc3339(self) -> String {
        self.rfc3339(Offset::UTC, false)
    }

    pub(super) fn rfc3339(self, offset: Offset, use_z: bool) -> String {
        let mut output = self.iso_datetime_in(offset);
        let nanos = self.nanos % NANOS_PER_SECOND;
        if nanos != 0 {
            let (value, width) = if nanos % 1_000_000 == 0 {
                (nanos / 1_000_000, 3)
            } else if nanos % 1000 == 0 {
                (nanos / 1000, 6)
            } else {
                (nanos, 9)
            };
            write!(output, ".{value:0width$}").expect("writing to a string succeeds");
        }
        if use_z && offset == Offset::UTC {
            output.push('Z');
        } else {
            let sign = if offset.is_negative() { '-' } else { '+' };
            let rounded_minutes = (offset.seconds().unsigned_abs() + 30) / 60;
            let (hours, minutes) = (rounded_minutes / 60, rounded_minutes % 60);
            write!(output, "{sign}{hours:02}:{minutes:02}").expect("writing to a string succeeds");
        }
        output
    }
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.rfc3339(Offset::UTC, true))
    }
}

fn write_year(output: &mut impl Write, year: i64) -> fmt::Result {
    if (0..=9999).contains(&year) {
        write!(output, "{year:04}")
    } else {
        write!(output, "{year:+05}")
    }
}

pub(super) fn write_date(output: &mut impl Write, date: Date, years: i64) -> fmt::Result {
    write_year(output, i64::from(date.year()) + years)?;
    let (month, day) = (date.month(), date.day());
    write!(output, "-{month:02}-{day:02}")
}

fn write_datetime(
    output: &mut impl Write,
    civil: DateTime,
    years: i64,
    separator: char,
    leap: bool,
) -> fmt::Result {
    write_date(output, civil.date(), years)?;
    let (hour, minute) = (civil.hour(), civil.minute());
    let second = civil.second() + i8::from(leap);
    write!(output, "{separator}{hour:02}:{minute:02}:{second:02}")
}

fn report_date(date: Date, years: i64) -> String {
    let month = MONTHS[usize::from(date.month() as u8 - 1)];
    let day = date.day();
    let mut text = format!("{month} {day:02}, ");
    write_year(&mut text, i64::from(date.year()) + years).expect("writing to a string succeeds");
    text
}

pub fn format_wall_time(civil: DateTime) -> String {
    let mut text = String::with_capacity(19);
    write_datetime(&mut text, civil, 0, ' ', false).expect("writing to a string succeeds");
    text
}

pub fn format_offset(offset: Offset) -> String {
    let seconds = offset.seconds().unsigned_abs();
    let sign = if offset.is_negative() { '-' } else { '+' };
    let hours = seconds / 3600;
    let minutes = seconds / 60 % 60;
    let seconds = seconds % 60;
    if seconds == 0 {
        format!("{sign}{hours:02}:{minutes:02}")
    } else {
        format!("{sign}{hours:02}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_rounds_offsets_to_minutes_without_rounding_wall_time() {
        // RFC 3339 emitted offset seconds instead of rounding the offset.
        let timestamp = UtcTimestamp::default();
        for (offset, expected) in [
            (3_661, "1970-01-01T01:01:01+01:01"),
            (3_690, "1970-01-01T01:01:30+01:02"),
            (-3_690, "1969-12-31T22:58:30-01:02"),
            (3_590, "1970-01-01T00:59:50+01:00"),
            (-1, "1969-12-31T23:59:59-00:00"),
        ] {
            assert_eq!(
                timestamp.rfc3339(Offset::from_seconds(offset).unwrap(), false),
                expected
            );
        }
    }
}
