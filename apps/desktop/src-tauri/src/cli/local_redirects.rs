//! Redirect tracking for loopback HTTP fetches.

use url::Url;

pub(crate) const REDIRECT_HOP_LIMIT: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WalkEnd {
    Loop,
    HopLimit { url: String },
    Invalid,
}

pub(crate) struct RedirectWalk {
    current: Url,
    visited: Vec<Url>,
}

impl RedirectWalk {
    pub(crate) fn new(start: &Url) -> Self {
        Self {
            current: start.clone(),
            visited: vec![start.clone()],
        }
    }

    /// One 3xx answer: its Location header, if it has a readable one.
    pub(crate) fn follow(&mut self, location: Option<&str>) -> Result<String, WalkEnd> {
        let location = location.ok_or(WalkEnd::Invalid)?;
        let next = self
            .current
            .join(location.trim())
            .map_err(|_| WalkEnd::Invalid)?;
        if self.visited.contains(&next) {
            return Err(WalkEnd::Loop);
        }
        let url = next.to_string();
        if self.visited.len() >= REDIRECT_HOP_LIMIT {
            return Err(WalkEnd::HopLimit { url });
        }
        self.visited.push(next.clone());
        self.current = next;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::{RedirectWalk, WalkEnd};
    use url::Url;

    #[test]
    fn a_location_seen_before_ends_the_walk_as_a_loop() {
        // A local redirect walk that follows a loop or never stops.
        let mut walk = RedirectWalk::new(&Url::parse("http://localhost:3000/start").unwrap());
        assert_eq!(
            walk.follow(Some("/next")),
            Ok("http://localhost:3000/next".into())
        );
        assert_eq!(walk.follow(Some("/start")), Err(WalkEnd::Loop));
    }

    #[test]
    fn the_tenth_hop_ends_the_walk_with_its_url() {
        // A local redirect walk that follows a loop or never stops.
        let mut walk = RedirectWalk::new(&Url::parse("http://localhost:3000/start").unwrap());
        for hop in 1..10 {
            assert_eq!(
                walk.follow(Some(&format!("/hop/{hop}"))),
                Ok(format!("http://localhost:3000/hop/{hop}"))
            );
        }
        assert_eq!(walk.follow(Some("/start")), Err(WalkEnd::Loop));
        assert_eq!(
            walk.follow(Some("/hop/10")),
            Err(WalkEnd::HopLimit {
                url: "http://localhost:3000/hop/10".into()
            })
        );
    }

    #[test]
    fn a_missing_or_unjoinable_location_is_invalid() {
        // A local redirect walk that follows a loop or never stops.
        let mut walk = RedirectWalk::new(&Url::parse("http://localhost:3000/start").unwrap());
        assert_eq!(walk.follow(None), Err(WalkEnd::Invalid));
        assert_eq!(walk.follow(Some("http://[::1")), Err(WalkEnd::Invalid));
    }

    #[test]
    fn a_relative_location_resolves_against_the_current_url() {
        // A relative redirect can use the starting URL after the current URL changes.
        let mut walk = RedirectWalk::new(&Url::parse("http://localhost:3000/a/b").unwrap());
        assert_eq!(
            walk.follow(Some("http://127.0.0.1:4000/c/d")),
            Ok("http://127.0.0.1:4000/c/d".into())
        );
        assert_eq!(
            walk.follow(Some("next")),
            Ok("http://127.0.0.1:4000/c/next".into())
        );
        assert_eq!(
            walk.follow(Some("/next")),
            Ok("http://127.0.0.1:4000/next".into())
        );
        assert_eq!(
            walk.follow(Some("//localhost:5000/x")),
            Ok("http://localhost:5000/x".into())
        );
    }
}
