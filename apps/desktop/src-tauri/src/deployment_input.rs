//! Parse local deployment flags before constructing any connected wire value.
use crate::connected_ci::{DeploymentFacts, PublishOrdering};

#[derive(Default)]
pub struct DeploymentInput {
    pub provider_deployment_id: String,
    pub commit_sha: String,
    pub git_ref: Option<String>,
    pub target: Option<String>,
    pub previous_sha: Option<String>,
    pub provider_created_at: Option<String>,
    pub published: bool,
    pub ordering: Option<PublishOrderingInput>,
}
#[derive(Default)]
pub struct PublishOrderingInput {
    pub authority_id: String,
    pub epoch: u64,
    pub publish_sequence: Option<u64>,
    pub predecessor_deployment_id: Option<String>,
}
/// Include the CLI flag in a type error without echoing its untrusted value.
pub fn parse_flag<T: std::str::FromStr<Err = String>>(
    flag: &str,
    value: &str,
) -> Result<T, String> {
    if value.is_empty() {
        if matches!(
            flag,
            "--deployment-id" | "--commit" | "--ordering-authority"
        ) {
            return Err(format!("{flag} is required and cannot be empty"));
        }
        return Err(format!(
            "{flag} was given with an empty value; omit it instead"
        ));
    }
    if flag == "--ref" && value.encode_utf16().count() > 256 {
        return Err("--ref must be at most 256 characters".into());
    }
    if matches!(flag, "--commit" | "--previous-sha")
        && (7..=64).contains(&value.len())
        && value.bytes().all(|c| c.is_ascii_hexdigit())
        && value.bytes().any(|c| c.is_ascii_uppercase())
    {
        return Err(format!(
            "{flag} must be lowercase; the service matches deployment SHAs exactly"
        ));
    }
    value.parse().map_err(|error| match flag {
        "--commit" | "--previous-sha" => format!("{flag} must be a commit SHA of 7 to 64 lowercase hex digits"),
        "--ref" => "--ref must be a Git ref of at most 256 characters without empty, dot, .lock, or Git-reserved components".into(),
        "--deployed-at" => "--deployed-at must be an RFC 3339 timestamp with uppercase T, an explicit offset or Z, and at most 9 fractional digits".into(),
        "--ordering-authority" => format!("{flag} must be 1 to 256 ASCII characters starting with a letter, digit, or underscore, using only letters, digits, and _ . : @ / + -"),
        "--deployment-id" | "--predecessor-deployment-id" | "--target" => format!("{flag} must be 1 to 128 ASCII characters starting with a letter, digit, or underscore, using only letters, digits, and _ . : @ / + -"),
        _ => format!("{flag}: {error}"),
    })
}
impl DeploymentInput {
    pub fn finish(self) -> Result<DeploymentFacts, String> {
        let ordering = self
            .ordering
            .map(|o| -> Result<_, String> {
                Ok(PublishOrdering {
                    kind: "publish_sequence".parse().expect("fixed ordering code"),
                    authority_id: parse_flag("--ordering-authority", &o.authority_id)?,
                    epoch: o.epoch,
                    publish_sequence: o.publish_sequence,
                    predecessor_deployment_id: o
                        .predecessor_deployment_id
                        .as_deref()
                        .map(|v| parse_flag("--predecessor-deployment-id", v))
                        .transpose()?,
                })
            })
            .transpose()?;
        let facts = DeploymentFacts {
            provider_deployment_id: parse_flag("--deployment-id", &self.provider_deployment_id)?,
            commit_sha: parse_flag("--commit", &self.commit_sha)?,
            git_ref: self
                .git_ref
                .as_deref()
                .map(|v| parse_flag("--ref", v))
                .transpose()?,
            target: self
                .target
                .as_deref()
                .map(|v| parse_flag("--target", v))
                .transpose()?,
            previous_sha: self
                .previous_sha
                .as_deref()
                .map(|v| parse_flag("--previous-sha", v))
                .transpose()?,
            provider_created_at: self
                .provider_created_at
                .as_deref()
                .map(|v| parse_flag("--deployed-at", v))
                .transpose()?,
            published: self.published,
            ordering,
        };
        facts.validate()?;
        Ok(facts)
    }
}
