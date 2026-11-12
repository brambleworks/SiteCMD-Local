// GitHub's push protection refuses any commit holding a Stripe live key, with or
// without a gitleaks:allow marker, so tests build key-shaped values from parts.
const STRIPE_LIVE_KEY = /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}/;
const TEXT = /\.(?:rs|[cm]?[jt]sx?|json|html?|md|toml|ya?ml|txt)$/;

export function stripeKeyLiteralFailures(read, exists, listFiles) {
  const failures = [];
  for (const dir of [".github", "apps", "docs", "packaging", "tools"]) {
    if (!exists(dir)) continue;
    for (const file of listFiles(dir, (name) => TEXT.test(name)))
      read(file)
        .split("\n")
        .forEach((line, index) => {
          if (STRIPE_LIVE_KEY.test(line))
            failures.push(
              `${file}:${index + 1} - holds a Stripe live key literal, which GitHub's push protection refuses; build it from parts with concat! or format!.`,
            );
        });
  }
  return failures;
}
