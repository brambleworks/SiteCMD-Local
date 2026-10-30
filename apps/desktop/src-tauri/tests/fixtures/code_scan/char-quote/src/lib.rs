pub fn start() {
    let _ = std::env::var("RUNTIME_URL");
}

pub fn is_quote(c: char) -> bool {
    c == '"'
}

#[cfg(test)]
mod tests {
    #[test]
    fn quote() {
        assert!(super::is_quote('"'));
    }

    #[test]
    fn reads_fixture() {
        let _ = std::env::var("TEST_ONLY_FIXTURE");
    }

    const KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8q7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8q7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8q7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8q7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8q7BFUVsdXrJ3kqXo9mZz0Yt8PpL2nW4cR6vT1aE5sD9fG3hJ7kL0mN2bV4cX6zA8
-----END RSA PRIVATE KEY-----"; // gitleaks:allow
}
