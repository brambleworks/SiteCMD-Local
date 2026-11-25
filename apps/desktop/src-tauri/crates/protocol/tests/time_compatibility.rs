use jiff::{tz::Offset, SignedDuration};
use sitecmd_protocol::time::{
    format_offset, format_wall_time, parse_offset, CalendarDate, UtcTimestamp,
};

#[test]
fn explicit_and_serialized_timestamps_keep_their_fraction_widths() {
    // Jiff's default display trims significant groups of fractional zeros.
    for (input, expected) in [
        ("2026-08-05T00:00:00.0Z", "2026-08-05T00:00:00"),
        ("2026-08-05T00:00:00.1Z", "2026-08-05T00:00:00.100"),
        ("2026-08-05T00:00:00.1234Z", "2026-08-05T00:00:00.123400"),
        (
            "2026-08-05T00:00:00.1234567Z",
            "2026-08-05T00:00:00.123456700",
        ),
        (
            "2026-08-05T00:00:00.123456789987Z",
            "2026-08-05T00:00:00.123456789",
        ),
    ] {
        let stamp = UtcTimestamp::parse_from_rfc3339(input).unwrap();
        assert_eq!(stamp.to_rfc3339(), format!("{expected}+00:00"));
        assert_eq!(
            serde_json::to_string(&stamp).unwrap(),
            format!("\"{expected}Z\"")
        );
    }
}

#[test]
fn offset_reports_and_epoch_milliseconds_keep_their_spelling() {
    // Offset normalization changes report times and truncation changes pre-epoch values.
    let local = parse_offset("2026-08-05t02:15:00.1-04:00").unwrap();
    assert_eq!(local.report_datetime(), "August 05, 2026 at  2:15 AM");
    assert_eq!(
        (local + SignedDuration::from_secs(15)).to_rfc3339(),
        "2026-08-05T02:15:15.100-04:00"
    );
    let last_four_digit_year = parse_offset("9999-12-31T23:59:59-23:59").unwrap();
    assert_eq!(
        last_four_digit_year.to_rfc3339(),
        "9999-12-31T23:59:59-23:59"
    );
    assert_eq!(last_four_digit_year.iso_date(), "9999-12-31");
    let before_epoch = UtcTimestamp::parse_from_rfc3339("1969-12-31T23:59:59.999999999Z").unwrap();
    assert_eq!(before_epoch.timestamp(), -1);
    assert_eq!(before_epoch.timestamp_millis(), -1);
    assert_eq!(before_epoch.timestamp_nanos_opt(), Some(-1));
    assert_eq!(format_offset(Offset::UTC), "+00:00");
    assert_eq!(
        format_offset(Offset::from_seconds(-18000).unwrap()),
        "-05:00"
    );
    assert_eq!(
        format_offset(Offset::from_seconds(3661).unwrap()),
        "+01:01:01"
    );
}

#[test]
fn stored_leap_seconds_and_extended_years_round_trip() {
    // Jiff normalizes leap seconds and its calendar excludes persisted extended years.
    for (input, expected, millis) in [
        (
            "2017-01-01T00:59:60.3+01:00",
            "2016-12-31T23:59:60.300Z",
            1_483_228_800_300,
        ),
        (
            "+10400-02-29T00:01:01Z",
            "+10400-02-29T00:01:01Z",
            266_030_179_261_000,
        ),
        (
            "-262143-01-01T00:00:00Z",
            "-262143-01-01T00:00:00Z",
            -8_334_601_228_800_000,
        ),
        (
            "+262142-12-31T23:59:59Z",
            "+262142-12-31T23:59:59Z",
            8_210_266_876_799_000,
        ),
        (
            "2026 - 8 - 5t2 : 1 : 0 UTC",
            "2026-08-05T02:01:00Z",
            1_785_895_260_000,
        ),
        (
            "2026-08-05T02:01:00+0000",
            "2026-08-05T02:01:00Z",
            1_785_895_260_000,
        ),
        (
            "2026-08-05T02:01:00Z ",
            "2026-08-05T02:01:00Z",
            1_785_895_260_000,
        ),
    ] {
        let stamp: UtcTimestamp = serde_json::from_str(&format!("\"{input}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&stamp).unwrap(),
            format!("\"{expected}\"")
        );
        assert_eq!(stamp.timestamp_millis(), millis, "{input}");
        assert_eq!(
            stamp.date().to_string(),
            expected.split_once('T').unwrap().0
        );
        assert_eq!(
            UtcTimestamp::from_timestamp_millis(millis)
                .unwrap()
                .timestamp_millis(),
            millis,
            "{input}"
        );
    }
    assert_eq!(
        CalendarDate::parse("+10400-02-29").unwrap().to_string(),
        "+10400-02-29"
    );
    assert!(CalendarDate::parse("+10200-02-29").is_err());
    assert_eq!(
        UtcTimestamp::from_timestamp_millis(1_483_228_800_300)
            .unwrap()
            .to_rfc3339(),
        "2017-01-01T00:00:00.300+00:00"
    );
    assert!(UtcTimestamp::parse_from_rfc3339("2026-08-05T02:01Z").is_err());
    assert!(UtcTimestamp::parse_from_rfc3339("2026-08-05T02:01:00+0000").is_err());
    assert!(UtcTimestamp::parse_from_rfc3339("2026-08-05T02:01:00+24:00").is_err());
}

#[test]
fn arithmetic_preserves_the_leap_second_and_its_boundaries() {
    // Normalizing the extra second early changes arithmetic across midnight.
    let parse = |text| UtcTimestamp::parse_from_rfc3339(text).unwrap();
    let stamp = parse("2016-12-31T23:59:60.5Z");
    for (millis, expected) in [
        (1000, "2017-01-01T00:00:00.500+00:00"),
        (300, "2016-12-31T23:59:60.800+00:00"),
        (600, "2017-01-01T00:00:00.100+00:00"),
    ] {
        assert_eq!(
            (stamp + SignedDuration::from_millis(millis)).to_rfc3339(),
            expected
        );
    }
    for (millis, expected) in [
        (1000, "2016-12-31T23:59:59.500+00:00"),
        (600, "2016-12-31T23:59:59.900+00:00"),
    ] {
        assert_eq!(
            (stamp - SignedDuration::from_millis(millis)).to_rfc3339(),
            expected
        );
    }
    for (duration, seconds, nanos) in [
        (stamp - parse("2016-12-31T23:59:59Z"), 1, 500_000_000),
        (parse("2017-01-01T00:00:00Z") - stamp, 0, -500_000_000),
        (stamp - parse("2017-01-01T00:00:01Z"), 0, -500_000_000),
    ] {
        assert_eq!(
            (duration.as_secs(), duration.subsec_nanos()),
            (seconds, nanos)
        );
    }
}

#[test]
fn named_formats_and_debug_keep_the_legacy_timestamp_text() {
    // Generic formatting lost leap seconds or signed years in some directives.
    let stamp: UtcTimestamp = "+10400-02-29T23:59:60.5Z".parse().unwrap();
    assert_eq!(stamp.iso_date(), "+10400-02-29");
    assert_eq!(stamp.iso_datetime(), "+10400-02-29T23:59:60");
    assert_eq!(stamp.wall_minute(), "+10400-02-29 23:59");
    assert_eq!(stamp.report_date(), "February 29, +10400");
    assert_eq!(stamp.report_datetime(), "February 29, +10400 at 11:59 PM");
    assert_eq!(format!("{stamp:?}"), "+10400-02-29T23:59:60.500Z");
    assert_eq!(format!("{:?}", stamp.date()), "+10400-02-29");
    let local = jiff::civil::date(2026, 11, 19).at(1, 2, 3, 456_789_000);
    assert_eq!(format_wall_time(local), "2026-11-19 01:02:03");
}

#[test]
fn calendar_arithmetic_uses_whole_day_counts() {
    // Adding a partial signed duration silently discarded the partial day.
    let leap_day = CalendarDate::new(2024, 2, 29).unwrap();
    assert_eq!((leap_day + 1).to_string(), "2024-03-01");
    assert_eq!((leap_day - 1).to_string(), "2024-02-28");
    assert_eq!((leap_day + (-1)).to_string(), "2024-02-28");
}
