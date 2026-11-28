export function readReleaseEnvironments(prefix, expected, gh) {
  return Object.fromEntries(
    Object.keys(expected?.requiredReviewers ?? {}).map((name) => {
      const endpoint = `${prefix}/environments/${encodeURIComponent(name)}`;
      const environment = gh(endpoint);
      return [
        name,
        {
          ...environment,
          deploymentPolicies: environment.deployment_branch_policy?.custom_branch_policies
            ? gh(`${endpoint}/deployment-branch-policies`)
            : null,
        },
      ];
    }),
  );
}

export function releaseEnvironmentFailures(expected, environments) {
  if (!expected) return [];
  const failures = [];
  for (const [name, requiredReviewers] of Object.entries(expected.requiredReviewers)) {
    const environment = environments?.[name];
    if (!environment) {
      failures.push(`environment "${name}" is missing.`);
      continue;
    }
    const reviewers = (environment.protection_rules ?? [])
      .filter(({ type }) => type === "required_reviewers")
      .flatMap(({ reviewers }) =>
        reviewers.map(({ type, reviewer }) => `${type}:${reviewer.login ?? reviewer.slug}`),
      )
      .sort();
    if (JSON.stringify(reviewers) !== JSON.stringify([...requiredReviewers].sort())) {
      failures.push(`environment "${name}" reviewers must be [${requiredReviewers.join(", ")}].`);
    }
    if (environment.can_admins_bypass !== expected.canAdminsBypass) {
      failures.push(`environment "${name}" can_admins_bypass must be ${expected.canAdminsBypass}.`);
    }
    const policy = environment.deployment_branch_policy;
    const deployment = environment.deploymentPolicies;
    const [tag] = deployment?.branch_policies ?? [];
    if (
      policy?.protected_branches !== false ||
      policy.custom_branch_policies !== true ||
      deployment?.total_count !== 1 ||
      deployment.branch_policies?.length !== 1 ||
      tag?.type !== "tag" ||
      tag.name !== expected.deploymentTagPattern
    ) {
      failures.push(
        `environment "${name}" deployment tag policies must allow only ${expected.deploymentTagPattern} tags.`,
      );
    }
  }
  return failures;
}
