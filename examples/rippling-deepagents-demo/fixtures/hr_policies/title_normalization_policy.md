# Job Title Normalization Policy

- Job titles should follow the format `<Level Prefix> <Role>` (e.g. "Senior
  Software Engineer", "Engineering Manager").
- Title changes are a `bounded_write` action performed by `update_job_title`
  and do not by themselves grant new application access or change payroll.
- Any title change that would also change an employee's Supergroup (and
  therefore downstream app access or approval chains) must first pass a
  fresh permission check via `check_permission`.
