# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |
| < 1.0   | No        |

## Security Architecture

### Privilege Requirements

MinervaDB PostgreSQL Profiler requires `CAP_BPF + CAP_PERFMON` (kernel 5.8+) or `CAP_SYS_ADMIN` (older).

**Production recommendation**: Grant only `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_PTRACE`:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+eip /usr/local/bin/minervadb-profiler
```

### eBPF Safety

All eBPF programs:
- Pass the Linux kernel eBPF verifier (proves memory safety)
- Do NOT modify kernel data structures (read-only observation)
- Use BTF CO-RE to avoid hardcoded memory offsets
- Are compiled with `-O2` optimization

### Data Sensitivity

The profiler captures full SQL query text. Enable redaction:

```yaml
security:
  redact_literals: true        # replace literals with $1, $2
  redact_query_text: false     # set true for fingerprints only
```

**Do not expose /metrics publicly without authentication.**

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

| Channel | Details |
|---------|---------|
| Email   | [security@minervadb.com](mailto:security@minervadb.com) |
| GitHub  | [Private security advisory](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/security/advisories/new) |

### Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 2 business days |
| Initial assessment | Within 5 business days |
| Patch availability | Within 30 days (critical: 7 days) |
| Public disclosure | 90 days after patch release |

## Known Limitations

1. Full SQL statements including bind parameters are captured — use `redact_literals: true`
2. No authentication on `/metrics` — use a reverse proxy with TLS + auth in production
3. BPF maps accessible to any process with `CAP_BPF` — use isolated namespaces in multi-tenant deployments

_Policy reviewed annually. Last updated: 2026-06-12_
