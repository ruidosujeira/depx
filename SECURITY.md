# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability in depx. Use GitHub's private vulnerability reporting for `ruidosujeira/depx` when available. If that channel is unavailable, contact the repository maintainer privately through the contact method listed on the maintainer's GitHub profile and include “depx security” in the subject.

Include the affected depx version or commit, reproduction steps, impact, and any suggested mitigation. Avoid including secrets or unrelated personal data.

The maintainer will acknowledge a complete report as soon as practical, investigate it, and coordinate disclosure and a fix. Please allow time for users to update before publishing technical details.

## Scope

Security reports may include unsafe parsing behavior, command execution, credential exposure, dependency confusion in generated recommendations, denial of service from adversarial project data, or incorrect vulnerability gating that can produce a false clean CI result.

Operational OSV outages are reported as errors after bounded retries; depx does not treat a failed advisory request as a clean audit.
