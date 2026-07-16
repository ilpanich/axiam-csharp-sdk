# Code Signing Policy

Free code signing for the **Axiam.Sdk** open-source project is provided by
[SignPath.io](https://about.signpath.io/), with a free code signing certificate
issued by the [SignPath Foundation](https://signpath.org/).

This document describes the policy under which the project's release artifacts are
built, signed and distributed. It exists to give consumers of the packages a clear,
auditable understanding of what is signed, who can authorize a signing operation, and
how the integrity of the build pipeline is maintained.

## Project

- **Project name:** Axiam.Sdk (C#)
- **Description:** Official C# client SDK for [AXIAM](https://github.com/ilpanich/axiam)
  — Access eXtended Identity and Authorization Management.
- **Source repository:** <https://github.com/ilpanich/axiam-csharp-sdk>
- **License:** [Apache-2.0](LICENSE)
- **Distributed packages (NuGet):**
  - [`Axiam.Sdk`](https://www.nuget.org/packages/Axiam.Sdk) — core client SDK
  - [`Axiam.Sdk.AspNetCore`](https://www.nuget.org/packages/Axiam.Sdk.AspNetCore) —
    ASP.NET Core middleware

## Signed artifacts

The following artifacts produced by the release pipeline are code signed:

- NuGet packages (`.nupkg`) for `Axiam.Sdk` and `Axiam.Sdk.AspNetCore`
- Symbol packages (`.snupkg`) accompanying the above

Signing is applied to release artifacts only. Continuous-integration builds of pull
requests and feature branches are **not** signed.

## Source code and contributions

- The authoritative source of truth is the `main` branch of the repository above.
- Changes reach `main` exclusively through pull requests.
- Every pull request is built and validated by the project's CI
  ([`.github/workflows/sdk-ci-csharp.yml`](.github/workflows/sdk-ci-csharp.yml)),
  which runs the build, test suite, coverage and security gates before a change can be
  merged.
- Contributions are reviewed by the project maintainer(s) prior to merge.

## Build and signing pipeline

1. Release artifacts are built from a clean checkout of a tagged commit on `main`
   using GitHub Actions.
2. The build is deterministic (`<Deterministic>true</Deterministic>`) and uses
   [SourceLink](https://github.com/dotnet/sourcelink) so the published packages are
   reproducible and debuggable against the exact source commit.
3. The unsigned build artifacts are submitted to [SignPath.io](https://signpath.io/)
   for signing via SignPath's GitHub Actions integration.
4. SignPath signs the artifacts with the certificate issued by the SignPath Foundation
   under the configured signing policy.
5. Signed artifacts are published to [NuGet.org](https://www.nuget.org/).

No signing key material is ever exposed to the build environment or to project
maintainers: the private key is held exclusively by SignPath and is never present on
CI runners or developer machines.

## Signing authorization

- Only the project owner/maintainer(s) with the appropriate SignPath role may approve
  and release a signing request.
- Signing is triggered by the release pipeline against tagged commits on `main` only.
- SignPath enforces the origin of the artifacts (repository, branch and workflow), so
  only artifacts produced by the project's own trusted GitHub Actions pipeline can be
  submitted for signing.

## Privacy and integrity

- The project does not collect any information from users of its packages.
- Consumers can verify the authenticity of a release by checking that the NuGet package
  is signed with the SignPath Foundation certificate issued to this project.

## Contact

Questions about this policy or the project's release process can be raised via the
[issue tracker](https://github.com/ilpanich/axiam-csharp-sdk/issues) of the repository.
