# Release Core

1. After merging the release PR, wait for the authoritative `CI` push run
   on `main` to succeed for the exact commit to be tagged. A manual CI run
   cannot satisfy the release gate. Tag a reviewed commit that contains
   the current Release workflow. GitHub executes the workflow at the tag.
2. Push `vX.Y.Z-beta.1` at that commit and wait for the entire **Release**
   workflow to pass. Verify the prerelease images, chart and agent
   artifact in Actions. Prerelease tags do not create a public GitHub Release.
3. Push `vX.Y.Z` at the same commit. The workflow verifies branch ancestry
   and exact-SHA push CI before building artifacts. It builds, scans and
   signs the images, verifies the Helm and agent packages, publishes the
   chart, then creates the GitHub Release with the agent archive and
   checksum. Replace the placeholder notes and rerun **Notify Discord on
   release** with that tag after editing.

## Verify a published release

For each component, download the `release-image-security-<component>-attempt-N`
artifact from its successful job attempt and extract it into
`release-image-security-<component>`. Compare the live tags with those
digests and verify the signatures against the specific Release workflow tag.

```bash
set -e
tag=vX.Y.Z
for component in api dashboard worker k8s-controller; do
  image="ghcr.io/tokentimerch/tokentimer-core-$component"
  digest="$(docker buildx imagetools inspect "$image:${tag#v}" --format '{{.Manifest.Digest}}')"
  test "$digest" = "$(cat "release-image-security-$component/release-image.digest")"
  cosign verify --certificate-identity "https://github.com/tokentimerch/tokentimer-core/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image@$digest"
done
```

Pull the chart with `helm pull oci://ghcr.io/tokentimerch/charts/tokentimer --version X.Y.Z`.
Compare its OCI digest with the publication log and check the chart's image
tags. Download the agent `.tgz` and `.sha256` together and run
`sha256sum -c ./*.sha256` in their download directory before extraction.

## Recover a failed run

Open the **Release** run and inspect the first failed job and any retained
artifact evidence. For a provenance error, check the original tag
commit, its ancestry on `main` and the exact push CI result. Wait for that
CI run or rerun it if needed, then rerun the failed release jobs on the
original tag. Publication stages recheck the tag and reuse only identical
versioned images and chart bytes. After a transient failure, compare what
already published against the retained digests and rerun the failed jobs.
If their input artifacts expired, rerun the full workflow only after that
check. A digest conflict requires qualifying a new version.

If GitHub Release creation failed, use `gh release view vX.Y.Z --json
isDraft,assets` to check the current state. If the release is absent, rerun
the failed job. If there is a draft, the job stops for operator review. Verify
or finish attaching the approved assets before publishing the draft.
For a published release with the correct assets, edit the notes. Recover a
missing or incorrect immutable asset with a new version. Deleting a
published release cannot free its tag for reuse.

## Publish development images

Dispatch **Publish Images** from `main`. Set `source_ref` to a fully qualified
branch or tag ref to build another source. The workflow pins the resolved
commit and emits a SHA tag and a `debug-ref-*` tag. It accepts an optional
`staging-*` or `debug-*` tag. A failed-job rerun reuses the validated commit.
Running the entire workflow again resolves `source_ref` again. The release
workflow owns versioned images. Each release tag has its own concurrency
group, and Helm publication shares a lock for Artifact Hub metadata.
Manual runs share a separate lock for staging aliases. If GitHub replaces a
pending request, rerun it after the active publisher finishes.
