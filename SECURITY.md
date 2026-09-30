# Security Policy

## Reporting a Vulnerability

AgentSec-Bench is a security research and evaluation framework. If you discover a
vulnerability in the framework's own code (as opposed to a scenario, which is
*designed* to model an attack and is not itself a vulnerability), please report it
privately rather than opening a public issue.

Email: oteyikelvin@gmail.com

Please include:

- A description of the issue and its potential impact
- Steps to reproduce
- The version/commit hash you tested against (`git rev-parse HEAD`)

We'll acknowledge reports as quickly as we can and work with you on a fix and
disclosure timeline before any public details are published.

## Scope

In scope: vulnerabilities in AgentSec-Bench's own core code (`agentsec_bench/core/`),
tooling, or CI/release process that could affect users running the benchmark.

Out of scope: the scenarios themselves. Each scenario intentionally models an
attack or misuse pattern against a *mock* agent/tool/environment for evaluation
purposes - that is the framework working as intended, not a vulnerability.

## Supported Versions

As a research benchmark under active development, only the latest tagged release
receives security fixes. There is no long-term support policy for older versions.
