// Git documents repository-local variables in `git rev-parse --local-env-vars`
// and requires hooks to clear them before entering another repository:
// https://git-scm.com/docs/githooks#_description
// https://git-scm.com/docs/git#_environment_variables
const REPOSITORY_GIT_ENV = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CONFIG",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_COUNT",
  "GIT_OBJECT_DIRECTORY",
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_GRAFT_FILE",
  "GIT_INDEX_FILE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_REPLACE_REF_BASE",
  "GIT_PREFIX",
  "GIT_SHALLOW_FILE",
  "GIT_COMMON_DIR",
  "GIT_NAMESPACE",
  "GIT_CEILING_DIRECTORIES",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

/** Keep the caller's environment, without inherited repository selection. */
export function gitEnv() {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) =>
        !REPOSITORY_GIT_ENV.includes(name) && !/^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name),
    ),
  );
}
