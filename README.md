# Remove Empty Namespaces

A lightweight Python application that scans Kubernetes namespaces, marks empty ones, and deletes them if they stay empty. Run it in whichever context fits your workflow:

- as a Kubernetes CronJob (manifests available in `kustomize/`)
- as a standalone command-line job (e.g., from your laptop or CI runner)

## How It Works

1. Discover all namespaced API resources that allow `list`.
2. Filter namespaces, API resources, and concrete objects via regex-based allow/deny lists.
3. Optionally apply a "double check" label so a namespace must remain empty for two consecutive runs.
4. Delete or skip namespaces based on the configured rules and `dryRun` flag.

## Running the App

### As a Kubernetes CronJob

1. Adjust `kustomize/settings.yaml` to match your environment (namespaces, resource filters, age thresholds, etc.).
2. (Optional) Edit `kustomize/base/cronjob.yaml` to tune schedule, image, or pod resources.
3. Apply the manifests:

   ```shell
   kubectl apply -k kustomize/
   ```

   This creates the `remove-empty-ns` namespace, a ConfigMap with your settings, and a CronJob that uses the published container image.

4. Update the ConfigMap (`kustomize/settings.yaml`) and re-apply to roll out new rules. The next CronJob run picks them up automatically.

### From the Command Line

1. Install the required tools and dependencies with [mise](https://mise.jdx.dev):

   ```shell
   mise install
   mise run venv
   ```

2. Provide a settings file (you can reuse `kustomize/settings.yaml` or craft your own).
3. Run the app:

   ```shell
   poetry run -- python ./src/app.py -c kustomize/settings.yaml
   ```

   - The app uses in-cluster credentials when running inside Kubernetes; otherwise it falls back to your local `~/.kube/config`.
   - Use `-v`/`-vv` for more verbose logging.
   - Use `-q` to suppress all logging output.

## Configuration

Configuration is plain YAML. See `kustomize/settings.yaml` for a complete working example. Key options:

- `namespacesConsidered` / `namespacesIgnored`: regex lists for target namespaces. `namespacesIgnored` always runs first; if `namespacesConsidered` is empty, every namespace that survived the ignore step is eligible.
- `ageGreaterThan`: minimum namespace age (seconds) before it is even inspected.
- `doubleCheck.enabled` and `doubleCheck.label`: add/remove the specified label to ensure a namespace is still empty on the next run before deleting it.
- `resourcesConsidered` / `resourcesIgnored`: regex triplets (`apiGroup`, `kind`, `name`) to force consideration or exclusion of specific objects. Objects are checked against `resourcesIgnored` first, then `resourcesConsidered`; ignored matches never count as present even if also listed as considered.
- `apiResourcesConsidered` / `apiResourcesIgnored`: regex pairs (`apiGroup`, `kind`) to whitelist/blacklist entire API kinds before listing objects. `apiResourcesIgnored` trims the universe first, then `apiResourcesConsidered` optionally whitelists the remainder.
- `dryRun`: when `true`, nothing is deleted; the app only logs what it would do.

Tuning these lists lets you focus on particular workloads (for example, only clean up preview environments) while ignoring shared infra components.

## Development

1. Install toolchain with `mise install`.
2. Create the virtual environment: `mise run venv`.
3. Install git hooks: `pre-commit install`.
4. Explore helper commands via `mise tasks`.
5. Run unit tests (outdated but kept for reference) with `mise run test`.
