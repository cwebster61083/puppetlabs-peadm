# @summary Perform preflight checks for a PE cluster before install or upgrade
#
# Validates that the target infrastructure meets requirements before running
# peadm::install or peadm::upgrade. Checks include Bolt version support,
# PE version support, architecture validity, node connectivity, OS platform
# consistency, hostname/certname alignment, and pxp-agent connectivity from
# compilers to the primary on port 8142.
#
# @param primary_host
#   The hostname and certname of the primary Puppet server
# @param replica_host
#   The hostname and certname of the replica Puppet server
# @param compiler_hosts
#   The hostnames and certnames of any compiler nodes
# @param primary_postgresql_host
#   The hostname and certname of the primary PE-PostgreSQL server (XL only)
# @param replica_postgresql_host
#   The hostname and certname of the replica PE-PostgreSQL server (XL only)
# @param version
#   The target PE version to install or upgrade to. When provided, the version
#   is validated against the set of supported PE versions.
# @param token_file
#   Path to a PE RBAC token file. When compiler_hosts are provided, the token
#   is validated against the primary to confirm API access.
# @param pe_admin_password
#   Password for the PE admin RBAC user. When provided alongside compiler_hosts,
#   a token will be generated at runtime via peadm::rbac_token instead of
#   requiring a pre-existing token_file.
# @param token_lifetime
#   Lifetime for the generated RBAC token. Format <integer>[smhdy]. Defaults to 1h.
# @param permit_unsafe_versions
#   When true, suppresses the error raised for PE versions not in the known
#   supported list.
plan peadm::preflight (
  # Standard
  Peadm::SingleTargetSpec           $primary_host,
  Optional[Peadm::SingleTargetSpec] $replica_host            = undef,

  # Large
  Optional[TargetSpec]              $compiler_hosts          = undef,

  # Extra Large
  Optional[Peadm::SingleTargetSpec] $primary_postgresql_host = undef,
  Optional[Peadm::SingleTargetSpec] $replica_postgresql_host = undef,

  # Common
  Optional[Peadm::Pe_version]       $version                 = undef,
  Optional[String]                  $token_file              = undef,
  Optional[String[1]]               $pe_admin_password       = undef,  # lint:ignore:140chars Bolt cannot auto-wrap CLI strings as Sensitive
  String                            $token_lifetime          = '1h',
  Boolean                           $permit_unsafe_versions  = false,
  Optional[String]                  $html_report_file        = undef,
) {
  peadm::log_plan_parameters({
    'primary_host'            => $primary_host,
    'replica_host'            => $replica_host,
    'compiler_hosts'          => $compiler_hosts,
    'primary_postgresql_host' => $primary_postgresql_host,
    'replica_postgresql_host' => $replica_postgresql_host,
    'version'                 => $version,
  })

  out::message('# Validating Bolt version')
  peadm::assert_supported_bolt_version()

  out::message('# Validating architecture')
  $arch = peadm::assert_supported_architecture(
    $primary_host,
    $replica_host,
    $primary_postgresql_host,
    $replica_postgresql_host,
    $compiler_hosts,
  )

  if $version {
    out::message("# Validating PE version ${version}")
    peadm::assert_supported_pe_version($version, $permit_unsafe_versions)
  }

  # Convert inputs into targets
  $primary_target            = peadm::get_targets($primary_host, 1)
  $replica_target            = peadm::get_targets($replica_host, 1)
  $primary_postgresql_target = peadm::get_targets($primary_postgresql_host, 1)
  $replica_postgresql_target = peadm::get_targets($replica_postgresql_host, 1)
  $compiler_targets          = peadm::get_targets($compiler_hosts)

  $all_targets = peadm::flatten_compact([
      $primary_target,
      $primary_postgresql_target,
      $replica_target,
      $replica_postgresql_target,
      $compiler_targets,
  ])

  # Validate RBAC token when compilers are present (required for upgrade)
  if $compiler_targets and $compiler_targets.size > 0 {
    if $pe_admin_password and $token_file =~ Undef {
      out::message('# Generating RBAC token via peadm::rbac_token')
      run_task('peadm::rbac_token', $primary_target,
        password       => $pe_admin_password,
        token_lifetime => $token_lifetime,
      )
    }
    out::message('# Validating RBAC token')
    run_task('peadm::validate_rbac_token', $primary_target, token_file => $token_file)
  }

  out::message('# Checking connectivity and gathering platform information')
  $precheck_results = run_task('peadm::precheck', $all_targets)
  $platform = $precheck_results.first['platform']

  # Check for hostname/certname mismatches — warns but does not fail
  $hostname_mismatches = $precheck_results.filter |$result| {
    $result.target.peadm::certname() != $result['hostname']
  }

  if $hostname_mismatches.size > 0 {
    $mismatch_details = $hostname_mismatches.map |$result| {
      "  target '${$result.target.peadm::certname()}' reports hostname '${$result['hostname']}'"
    }.join("\n")
    out::message("WARNING: Hostname/certname mismatches detected. Certificate names will be set to target names; ensure target names are correct and resolvable.\n${mismatch_details}")
  }

  # Fail if nodes report different OS platforms — PE requires a homogeneous cluster
  $platform_mismatches = $precheck_results.filter |$result| {
    $result['platform'] != $platform
  }

  if $platform_mismatches.size > 0 {
    $mismatch_names = $platform_mismatches.map |$result| { $result.target.peadm::certname() }
    fail_plan("Platform mismatch: all targets must run the same OS. Mismatched targets: ${$mismatch_names.join(', ')}")
  }

  # Check pxp-agent connectivity from compilers to primary on port 8142 (orchestrator/PXP broker)
  if $compiler_targets and $compiler_targets.size > 0 {
    out::message('# Checking pxp-agent connectivity from compilers to primary (port 8142)')
    $primary_certname = $primary_target[0].peadm::certname()
    $pxp_results = run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${primary_certname}/8142'",
      $compiler_targets,
      '_catch_errors' => true,
    )
    $pxp_failures = $pxp_results.error_set.targets
    if $pxp_failures.size > 0 {
      $failed_names = $pxp_failures.map |$t| { $t.peadm::certname() }
      fail_plan("PXP-agent connectivity check failed: compilers cannot reach ${primary_certname}:8142 (orchestrator/PXP broker). Failed: ${failed_names.join(', ')}")
    }
  }

  # Check that PE master rules are current (relevant for existing installations)
  out::message('# Checking PE master rules')
  $rules_check = run_task('peadm::check_pe_master_rules', $primary_target).first.value
  if ! $rules_check['updated'] {
    out::message('WARNING: PE master rules are not current. Run the peadm::convert plan before proceeding with an upgrade.')
  }

  # ── Firewall checks ────────────────────────────────────────────────────────
  # Key PE ports that all infrastructure nodes must reach on the primary:
  #   8140 - Puppet Server (catalog requests, file serving)
  #   8081 - PuppetDB
  # PostgreSQL port 5432: all PE server nodes must reach both psql nodes (XL only)
  out::message('# Checking firewall rules (PE ports on primary)')
  $primary_fqdn = $primary_target[0].peadm::certname()

  $firewall_infra_targets = peadm::flatten_compact([$replica_target, $compiler_targets])
  $fw_port_results = {}
  $psql_targets      = peadm::flatten_compact([$primary_postgresql_target, $replica_postgresql_target])
  $pe_server_targets = peadm::flatten_compact([$primary_target, $replica_target])

  $fw_8140_failures = [] + ($firewall_infra_targets.size > 0 ? {
    true => run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${primary_fqdn}/8140'",
      $firewall_infra_targets,
      '_catch_errors' => true,
    ).error_set.targets.map |$t| { "${$t.peadm::certname()} -> ${primary_fqdn}:8140" },
    default => [],
  })

  $fw_8081_failures = [] + ($firewall_infra_targets.size > 0 ? {
    true => run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${primary_fqdn}/8081'",
      $firewall_infra_targets,
      '_catch_errors' => true,
    ).error_set.targets.map |$t| { "${$t.peadm::certname()} -> ${primary_fqdn}:8081" },
    default => [],
  })

  # Check all PE server nodes (primary + replica) can reach both psql nodes on 5432
  $fw_5432_failures_primary_psql = [] + ($primary_postgresql_target.size > 0 ? {
    true => run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${$primary_postgresql_target[0].peadm::certname()}/5432'",
      $pe_server_targets,
      '_catch_errors' => true,
    ).error_set.targets.map |$t| { "${$t.peadm::certname()} -> ${$primary_postgresql_target[0].peadm::certname()}:5432" },
    default => [],
  })

  $fw_5432_failures_replica_psql = [] + ($replica_postgresql_target.size > 0 ? {
    true => run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${$replica_postgresql_target[0].peadm::certname()}/5432'",
      $pe_server_targets,
      '_catch_errors' => true,
    ).error_set.targets.map |$t| { "${$t.peadm::certname()} -> ${$replica_postgresql_target[0].peadm::certname()}:5432" },
    default => [],
  })

  $fw_5432_failures = $fw_5432_failures_primary_psql + $fw_5432_failures_replica_psql

  $all_fw_failures = $fw_8140_failures + $fw_8081_failures + $fw_5432_failures
  if $all_fw_failures.size > 0 {
    fail_plan("Firewall check failed. Blocked connections:\n  ${$all_fw_failures.join("\n  ")}")
  }

  # ── Disk space check ───────────────────────────────────────────────────────
  # PE primary needs at least 100 GB; compilers/replicas at least 50 GB.
  # We warn (not fail) so operators can make an informed decision.
  out::message('# Checking disk space')
  $disk_min_gb_primary  = 100
  $disk_min_gb_infra    = 50

  $disk_results = run_command(
    "df -BG --output=avail /opt 2>/dev/null | tail -1 | tr -dc '0-9' || df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9'",
    $all_targets,
    '_catch_errors' => true,
  )

  $disk_warnings = $disk_results.ok_set.results.filter |$r| {
    $raw = $r['stdout'].strip
    $raw =~ /^\d+$/ and Integer($raw, 10) < (($r.target in $primary_target) ? { true => $disk_min_gb_primary, default => $disk_min_gb_infra })
  }.map |$r| {
    $avail_gb = Integer($r['stdout'].strip, 10)
    $min = ($r.target in $primary_target) ? { true => $disk_min_gb_primary, default => $disk_min_gb_infra }
    "${$r.target.peadm::certname()}: ${avail_gb} GB available (minimum ${min} GB)"
  }

  if $disk_warnings.size > 0 {
    out::message("WARNING: Insufficient disk space on:\n  ${$disk_warnings.join("\n  ")}")
  }

  # ── Memory pressure check ─────────────────────────────────────────────────
  # PE primary needs at least 8 GB available; other infra nodes at least 4 GB.
  out::message('# Checking memory pressure')
  $mem_min_mb_primary = 8192
  $mem_min_mb_infra   = 4096

  $mem_results = run_command(
    "awk '/^MemAvailable/ {print int($2/1024)}' /proc/meminfo",
    $all_targets,
    '_catch_errors' => true,
  )

  $mem_warnings = $mem_results.ok_set.results.filter |$r| {
    $avail_mb = Integer($r['stdout'].strip, 10)
    $min = ($r.target in $primary_target) ? { true => $mem_min_mb_primary, default => $mem_min_mb_infra }
    $avail_mb < $min
  }.map |$r| {
    $avail_mb = Integer($r['stdout'].strip, 10)
    $min = ($r.target in $primary_target) ? { true => $mem_min_mb_primary, default => $mem_min_mb_infra }
    "${$r.target.peadm::certname()}: ${avail_mb} MB available (minimum ${min} MB)"
  }

  if $mem_warnings.size > 0 {
    out::message("WARNING: Low available memory on:\n  ${$mem_warnings.join("\n  ")}")
  }

  # ── Service health check ──────────────────────────────────────────────────
  # Run puppet infra status on the primary to check all PE service states.
  out::message('# Checking PE service health')
  $svc_status_result = run_command(
    '/opt/puppetlabs/bin/puppet infra status 2>&1',
    $primary_target,
    '_catch_errors' => true,
  )
  $svc_failures = $svc_status_result.ok_set.results.reduce([]) |$memo, $r| {
    $bad_lines = $r['stdout'].split("\n").filter |$line| {
      $line =~ /[✗]|\bfailed\b|\bstopped\b|\bError\b/
    }
    $bad_lines.size > 0 ? {
      true    => $memo + $bad_lines.map |$l| { "${$r.target.peadm::certname()}: ${$l.strip}" },
      default => $memo,
    }
  }

  # Check pxp-agent service on compilers specifically
  $pxp_svc_warnings = $compiler_targets.size > 0 ? {
    true => run_command(
      'systemctl is-active pxp-agent 2>/dev/null || echo "inactive"',
      $compiler_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $r['stdout'].strip != 'active'
    }.map |$r| {
      "${$r.target.peadm::certname()}: pxp-agent is ${$r['stdout'].strip}"
    },
    default => [],
  }

  $all_svc_issues = $svc_failures + $pxp_svc_warnings

  if $all_svc_issues.size > 0 {
    out::message("WARNING: Service health issues detected:\n  ${$all_svc_issues.join("\n  ")}")
  }

  # ── Log error check ───────────────────────────────────────────────────────
  # Scan the last 500 lines of key PE logs for ERROR/FATAL entries.
  out::message('# Checking PE service logs for recent errors')

  $log_warnings = run_command(
    'for log in puppetserver/puppetserver puppetdb/puppetdb console-services/console-services orchestration-services/orchestration-services; do logfile=/var/log/puppetlabs/$log.log; errs=$(tail -500 "$logfile" 2>/dev/null | grep -E "ERROR|FATAL"); [ -z "$errs" ] && continue; count=$(echo "$errs" | wc -l | tr -d " "); last_ts=$(echo "$errs" | tail -1 | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}" | head -1); if [ -n "$last_ts" ] && epoch=$(date -d "$last_ts" +%s 2>/dev/null) && [ -n "$epoch" ]; then delta=$(( $(date +%s) - epoch )); if [ $delta -lt 60 ]; then ago="${delta}s ago"; elif [ $delta -lt 3600 ]; then ago="$((delta/60))m ago"; elif [ $delta -lt 86400 ]; then ago="$((delta/3600))h ago"; else ago="$((delta/86400))d ago"; fi; else ago="time unknown"; fi; echo "$log: $count error(s), last seen $ago"; echo "$errs" | tail -5 | sed "s/^/  >> /"; done; true',
    $primary_target,
    '_catch_errors' => true,
  ).ok_set.results.filter |$r| {
    $r['stdout'].strip != ''
  }.map |$r| {
    $certname = $r.target.peadm::certname()
    $r['stdout'].strip.split("\n").map |$l| {
      $l =~ /^  >> / ? {
        true    => $l,
        default => "${certname}: ${$l}",
      }
    }
  }.flatten

  $compiler_log_warnings = $compiler_targets.size > 0 ? {
    true => run_command(
      'errs=$(tail -500 /var/log/puppetlabs/pxp-agent/pxp-agent.log 2>/dev/null | grep -E "ERROR|FATAL"); [ -z "$errs" ] && exit 0; count=$(echo "$errs" | wc -l | tr -d " "); last_ts=$(echo "$errs" | tail -1 | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}" | head -1); if [ -n "$last_ts" ] && epoch=$(date -d "$last_ts" +%s 2>/dev/null) && [ -n "$epoch" ]; then delta=$(( $(date +%s) - epoch )); if [ $delta -lt 60 ]; then ago="${delta}s ago"; elif [ $delta -lt 3600 ]; then ago="$((delta/60))m ago"; elif [ $delta -lt 86400 ]; then ago="$((delta/3600))h ago"; else ago="$((delta/86400))d ago"; fi; else ago="time unknown"; fi; echo "pxp-agent: $count error(s), last seen $ago"; echo "$errs" | tail -5 | sed "s/^/  >> /"; true',
      $compiler_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $r['stdout'].strip != ''
    }.map |$r| {
      $certname = $r.target.peadm::certname()
      $r['stdout'].strip.split("\n").map |$l| {
        $l =~ /^  >> / ? {
          true    => $l,
          default => "${certname}: ${$l}",
        }
      }
    }.flatten,
    default => [],
  }

  $psql_log_warnings = $psql_targets.size > 0 ? {
    true => run_command(
      'logdir=/var/log/puppetlabs/postgresql; logfile=$(ls -t "$logdir"/postgresql-*.log 2>/dev/null | head -1); [ -z "$logfile" ] && exit 0; errs=$(tail -500 "$logfile" 2>/dev/null | grep -E "ERROR|FATAL"); [ -z "$errs" ] && exit 0; count=$(echo "$errs" | wc -l | tr -d " "); last_ts=$(echo "$errs" | tail -1 | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}" | head -1); if [ -n "$last_ts" ] && epoch=$(date -d "$last_ts" +%s 2>/dev/null) && [ -n "$epoch" ]; then delta=$(( $(date +%s) - epoch )); if [ $delta -lt 60 ]; then ago="${delta}s ago"; elif [ $delta -lt 3600 ]; then ago="$((delta/60))m ago"; elif [ $delta -lt 86400 ]; then ago="$((delta/3600))h ago"; else ago="$((delta/86400))d ago"; fi; else ago="time unknown"; fi; echo "postgresql: $count error(s), last seen $ago"; echo "$errs" | tail -5 | sed "s/^/  >> /"; true',
      $psql_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $r['stdout'].strip != ''
    }.map |$r| {
      $certname = $r.target.peadm::certname()
      $r['stdout'].strip.split("\n").map |$l| {
        $l =~ /^  >> / ? {
          true    => $l,
          default => "${certname}: ${$l}",
        }
      }
    }.flatten,
    default => [],
  }

  $all_log_warnings = $log_warnings + $compiler_log_warnings + $psql_log_warnings

  if $all_log_warnings.size > 0 {
    out::message("WARNING: Recent ERROR/FATAL entries found in PE logs:\n${$all_log_warnings.join("\n")}")
  }

  # ── Database node performance checks ──────────────────────────────────────
  # Validates disk write throughput and I/O wait on primary and replica psql
  # nodes. Connectivity is covered by the port 5432 firewall checks above.
  # All checks are warn-only — PE-PostgreSQL may not be installed yet.
  out::message('# Checking database node disk performance')

  # Disk write throughput — PE-PostgreSQL requires sustained sequential writes.
  # Threshold: 100 MB/s. fdatasync ensures kernel buffer flushes are measured.
  $db_throughput_min_mbs = 100
  $db_throughput_raw = $psql_targets.size > 0 ? {
    true => run_command(
      @(CMD),
        dd if=/dev/zero of=/tmp/peadm_preflight_dd bs=1M count=256 conv=fdatasync 2>&1 | awk '/copied/{for(i=1;i<=NF;i++) if($i~/MB\/s/){printf "%.0f",$(i-1); exit}}'
      |-CMD
      $psql_targets,
      '_catch_errors' => true,
    ).ok_set.results,
    default => [],
  }
  if $psql_targets.size > 0 {
    run_command('rm -f /tmp/peadm_preflight_dd', $psql_targets, '_catch_errors' => true)
  }
  $db_throughput_warnings = $db_throughput_raw.filter |$r| {
    $raw = $r['stdout'].strip
    $raw =~ /^\d+$/ and Integer($raw, 10) < $db_throughput_min_mbs
  }.map |$r| {
    "${$r.target.peadm::certname()}: disk write ${$r['stdout'].strip} MB/s (minimum ${db_throughput_min_mbs} MB/s)"
  }

  # I/O wait — sustained iowait > 20% indicates a storage bottleneck that will
  # degrade PostgreSQL write latency. Sampled over a 1-second window.
  $db_iowait_warn_pct = 20
  $db_iowait_warnings = $psql_targets.size > 0 ? {
    true => run_command(
      @(CMD),
        perl -e 'sub r{open F,"/proc/stat";my @v=(split" ",<F>)[1..8];close F;@v} my @a=r();sleep 1;my @b=r();my $dt=0;$dt+=$b[$_]-$a[$_] for 0..$#a;my $diow=$b[4]-$a[4];printf "%.1f\n",$dt>0?$diow*100/$dt:0'
      |-CMD
      $psql_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $raw = $r['stdout'].strip
      $raw =~ /^\d+(\.\d+)?$/ and Float($raw) >= $db_iowait_warn_pct
    }.map |$r| {
      "${$r.target.peadm::certname()}: I/O wait ${$r['stdout'].strip}% (threshold ${db_iowait_warn_pct}%)"
    },
    default => [],
  }

  # pe-postgresql service state — warns if not active (may not be installed yet)
  $db_svc_warnings = $psql_targets.size > 0 ? {
    true => run_command(
      'systemctl is-active pe-postgresql 2>/dev/null || echo inactive',
      $psql_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $r['stdout'].strip != 'active'
    }.map |$r| { "${$r.target.peadm::certname()}: pe-postgresql is ${$r['stdout'].strip} (may not be installed yet)" },
    default => [],
  }

  # CPU load — warn if 1-minute load average > 4.0
  $db_load_warnings = $psql_targets.size > 0 ? {
    true => run_command(
      "awk '{print \$1}' /proc/loadavg",
      $psql_targets,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $raw_load = $r['stdout'].strip
      $raw_load =~ /^[0-9.]+$/ and Float($raw_load) > 4.0
    }.map |$r| { "${$r.target.peadm::certname()}: load average ${$r['stdout'].strip} (threshold 4.0)" },
    default => [],
  }

  # Replication streaming — verify replica psql is receiving WAL from primary.
  # Skipped silently when pe-postgresql is not yet running (pre-install scenario).
  $db_repl_warnings = ($primary_postgresql_target.size > 0 and $replica_postgresql_target.size > 0) ? {
    true => run_command(
      "psql -U pe-postgres -tAc \"SELECT COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), sent_lsn)::text, 'no_replica') FROM pg_stat_replication LIMIT 1;\" 2>/dev/null || echo not_running",
      $primary_postgresql_target,
      '_catch_errors' => true,
    ).ok_set.results.filter |$r| {
      $r['stdout'].strip == 'no_replica'
    }.map |$r| { "${$r.target.peadm::certname()}: no replica currently streaming from primary PostgreSQL" },
    default => [],
  }

  $db_warnings = $db_throughput_warnings + $db_iowait_warnings + $db_svc_warnings + $db_load_warnings + $db_repl_warnings

  if $db_warnings.size > 0 {
    out::message("WARNING: Database node performance checks flagged issues:\n  ${$db_warnings.join("\n  ")}")
  }

  $warning_count = $hostname_mismatches.size
    + ($rules_check['updated'] ? { true => 0, default => 1 })
    + $disk_warnings.size
    + $mem_warnings.size
    + $all_svc_issues.size
    + $all_log_warnings.size
    + $db_warnings.size

  # ── Summary ────────────────────────────────────────────────────────────────
  $pass = '✓'
  $warn = '!'
  $fail = '✗'

  $rbac_summary = ($compiler_targets and $compiler_targets.size > 0) ? {
    true    => "${pass}  RBAC token         : valid",
    default => "-   RBAC token         : skipped (no compilers)",
  }

  $connectivity_summary = "${pass}  Node connectivity  : ${all_targets.size} target(s) reachable"

  $hostname_summary = $hostname_mismatches.size > 0 ? {
    true    => "${warn}  Hostname/certname  : ${$hostname_mismatches.size} mismatch(es) detected\n${
      $hostname_mismatches.map |$r| {
        "           ⤷ ${$r.target.peadm::certname()} reports hostname '${$r['hostname']}'"
      }.join("\n")
    }",
    default => "${pass}  Hostname/certname  : all targets match",
  }

  $platform_summary = "${pass}  OS platform        : ${platform} (homogeneous)"

  $pxp_summary = ($compiler_targets and $compiler_targets.size > 0) ? {
    true    => "${pass}  PXP-agent :8142    : all compilers can reach primary",
    default => "-   PXP-agent :8142    : skipped (no compilers)",
  }

  $fw_summary = $all_fw_failures.size > 0 ? {
    true    => "${fail}  Firewall rules     : ${$all_fw_failures.size} blocked port(s)\n${
      $all_fw_failures.map |$f| { "           ⤷ ${f}" }.join("\n")
    }",
    default => "${pass}  Firewall rules     : all required ports open",
  }

  $disk_summary = $disk_warnings.size > 0 ? {
    true    => "${warn}  Disk space         : ${$disk_warnings.size} node(s) below minimum\n${
      $disk_warnings.map |$d| { "           ⤷ ${d}" }.join("\n")
    }",
    default => "${pass}  Disk space         : all nodes meet requirements",
  }

  $mem_summary = $mem_warnings.size > 0 ? {
    true    => "${warn}  Memory pressure    : ${$mem_warnings.size} node(s) below minimum\n${
      $mem_warnings.map |$m| { "           ⤷ ${m}" }.join("\n")
    }",
    default => "${pass}  Memory pressure    : all nodes have sufficient memory",
  }

  $svc_summary = $all_svc_issues.size > 0 ? {
    true    => "${warn}  Service health     : ${$all_svc_issues.size} issue(s) detected\n${
      $all_svc_issues.map |$s| { "           ⤷ ${s}" }.join("\n")
    }",
    default => "${pass}  Service health     : all services running",
  }

  # Group log warning lines by host: header lines carry "certname: ..." prefix;
  # "  >> ..." lines are raw log excerpts that belong to the preceding header.
  $log_grouped_lines = $all_log_warnings.reduce({ 'current' => '', 'out' => [] }) |$acc, $l| {
    if $l =~ /^  >> / {
      { 'current' => $acc['current'], 'out' => $acc['out'] + ["              ${$l.strip}"] }
    } else {
      $parts = $l.split(': ')
      $host  = $parts[0]
      $entry = $parts[1,-1].join(': ')
      $host != $acc['current'] ? {
        true    => { 'current' => $host, 'out' => $acc['out'] + ["        ── ${host}", "           ⤷ ${entry}"] },
        default => { 'current' => $host, 'out' => $acc['out'] + ["           ⤷ ${entry}"] },
      }
    }
  }['out']

  $log_summary = $all_log_warnings.size > 0 ? {
    true    => "${warn}  Log errors         : ERROR/FATAL entries found in PE logs\n${
      $log_grouped_lines.join("\n")
    }",
    default => "${pass}  Log errors         : no recent ERROR/FATAL entries found",
  }

  $rules_summary = $rules_check['updated'] ? {
    true    => "${pass}  PE master rules    : current",
    default => "${warn}  PE master rules    : not current\n           ⤷ run peadm::convert before upgrading",
  }

  $version_summary = $version ? {
    undef   => "-   PE version         : not checked",
    default => "${pass}  PE version         : ${version} supported",
  }

  $db_summary = $psql_targets.size == 0 ? {
    true    => "-   Database nodes     : skipped (no psql targets)",
    default => $db_warnings.size > 0 ? {
      true    => "${warn}  Database nodes     : ${$db_warnings.size} issue(s) detected\n${
        $db_warnings.map |$d| { "           ⤷ ${d}" }.join("\n")
      }",
      default => "${pass}  Database nodes     : performance and connectivity checks passed",
    },
  }

  out::message(@("SUMMARY"/$))
    ================================================
     Preflight Check Summary
    ================================================
     Architecture : ${$arch['architecture']}
     Platform     : ${platform}
     Targets      : ${all_targets.size}
    ------------------------------------------------
     ${rbac_summary}
     ${connectivity_summary}
     ${hostname_summary}
     ${platform_summary}
     ${pxp_summary}
     ${fw_summary}
     ${disk_summary}
     ${mem_summary}
     ${svc_summary}
     ${log_summary}
     ${rules_summary}
     ${version_summary}
     ${db_summary}
    ================================================
    | SUMMARY

  # ── HTML report ───────────────────────────────────────────────────────────
  if $html_report_file {
    $log_svc_count = $all_log_warnings.filter |$l| { $l !~ /^  >> / }.size

    $html_check_rows = [
      {
        'label'   => 'RBAC Token',
        'status'  => ($compiler_targets and $compiler_targets.size > 0) ? { true => 'pass', default => 'skip' },
        'summary' => ($compiler_targets and $compiler_targets.size > 0) ? { true => 'Token validated', default => 'Skipped (no compilers)' },
        'details' => [],
      },
      {
        'label'   => 'Node Connectivity',
        'status'  => 'pass',
        'summary' => "${all_targets.size} target(s) reachable",
        'details' => [],
      },
      {
        'label'   => 'Hostname / Certname',
        'status'  => $hostname_mismatches.size > 0 ? { true => 'warn', default => 'pass' },
        'summary' => $hostname_mismatches.size > 0 ? {
          true    => "${$hostname_mismatches.size} mismatch(es) detected",
          default => 'All targets match',
        },
        'details' => $hostname_mismatches.map |$r| { "${$r.target.peadm::certname()} reports hostname '${$r['hostname']}'" },
      },
      {
        'label'   => 'OS Platform',
        'status'  => 'pass',
        'summary' => "${platform} (homogeneous)",
        'details' => [],
      },
      {
        'label'   => 'PXP-Agent :8142',
        'status'  => ($compiler_targets and $compiler_targets.size > 0) ? { true => 'pass', default => 'skip' },
        'summary' => ($compiler_targets and $compiler_targets.size > 0) ? { true => 'All compilers can reach primary', default => 'Skipped (no compilers)' },
        'details' => [],
      },
      {
        'label'   => 'Firewall Rules',
        'status'  => $all_fw_failures.size > 0 ? { true => 'fail', default => 'pass' },
        'summary' => $all_fw_failures.size > 0 ? { true => "${$all_fw_failures.size} blocked connection(s)", default => 'All required ports open' },
        'details' => $all_fw_failures,
      },
      {
        'label'   => 'Disk Space',
        'status'  => $disk_warnings.size > 0 ? { true => 'warn', default => 'pass' },
        'summary' => $disk_warnings.size > 0 ? { true => "${$disk_warnings.size} node(s) below minimum", default => 'All nodes meet requirements' },
        'details' => $disk_warnings,
      },
      {
        'label'   => 'Memory',
        'status'  => $mem_warnings.size > 0 ? { true => 'warn', default => 'pass' },
        'summary' => $mem_warnings.size > 0 ? { true => "${$mem_warnings.size} node(s) below minimum", default => 'All nodes have sufficient memory' },
        'details' => $mem_warnings,
      },
      {
        'label'   => 'Service Health',
        'status'  => $all_svc_issues.size > 0 ? { true => 'warn', default => 'pass' },
        'summary' => $all_svc_issues.size > 0 ? { true => "${$all_svc_issues.size} issue(s) detected", default => 'All services running' },
        'details' => $all_svc_issues,
      },
      {
        'label'   => 'Log Errors',
        'status'  => $all_log_warnings.size > 0 ? { true => 'warn', default => 'pass' },
        'summary' => $all_log_warnings.size > 0 ? { true => "${log_svc_count} service log(s) with ERROR/FATAL entries", default => 'No recent ERROR/FATAL entries' },
        'details' => $all_log_warnings,
      },
      {
        'label'   => 'PE Master Rules',
        'status'  => $rules_check['updated'] ? { true => 'pass', default => 'warn' },
        'summary' => $rules_check['updated'] ? { true => 'Current', default => 'Not current — run peadm::convert before upgrading' },
        'details' => [],
      },
      {
        'label'   => 'PE Version',
        'status'  => $version ? { undef => 'skip', default => 'pass' },
        'summary' => $version ? { undef => 'Not checked', default => "${version} supported" },
        'details' => [],
      },
      {
        'label'   => 'Database Nodes',
        'status'  => $psql_targets.size == 0 ? { true => 'skip', default => $db_warnings.size > 0 ? { true => 'warn', default => 'pass' } },
        'summary' => $psql_targets.size == 0 ? {
          true    => 'Skipped (no psql targets)',
          default => $db_warnings.size > 0 ? { true => "${$db_warnings.size} issue(s) detected", default => 'All checks passed' },
        },
        'details' => $db_warnings,
      },
    ]

    $tr_html = $html_check_rows.map |$row| {
      $st   = $row['status']
      $icon = $st ? { 'pass' => '&#10003;', 'warn' => '&#9888;', 'fail' => '&#10007;', default => '&ndash;' }
      $detail_items = $row['details']
      $detail_li = $detail_items.map |$d| {
        $d =~ /^  >> / ? {
          true    => "<li class=\"exc\">${$d.strip.regsubst('^>> ', '')}</li>",
          default => "<li>${d}</li>",
        }
      }
      $detail_html = $detail_items.size > 0 ? {
        true    => "<ul>${$detail_li.join('')}</ul>",
        default => '',
      }
      "<tr class=\"${st}\"><td class=\"ic\">${icon}</td><td class=\"lbl\">${$row['label']}</td><td class=\"det\">${$row['summary']}${detail_html}</td></tr>"
    }.join("\n")

    $overall_cls = $warning_count == 0 ? { true => 'pass', default => 'warn' }
    $overall_msg = $warning_count == 0 ? {
      true    => 'All checks passed &mdash; infrastructure is ready.',
      default => "${warning_count} warning(s) detected &mdash; review before proceeding.",
    }
    $version_meta = $version ? { undef => '', default => " &bull; PE ${version}" }
    $ts              = Timestamp.new()
    $report_ts       = $ts.strftime('%Y-%m-%d %H:%M:%S UTC')
    $report_ts_file  = $ts.strftime('%Y-%m-%d_%H-%M-%S')
    $actual_report_file = $html_report_file =~ /\.html$/ ? {
      true    => $html_report_file.regsubst('\.html$', "-${report_ts_file}.html"),
      default => "${html_report_file}-${report_ts_file}",
    }

    $html_content = @("HTML")
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>PE Preflight Report</title>
        <style>
          *{box-sizing:border-box;margin:0;padding:0}
          body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e;min-height:100vh;padding:24px}
          .card{max-width:900px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.1);overflow:hidden}
          header{background:#1a1a2e;color:#fff;padding:24px 28px}
          header h1{font-size:1.4rem;font-weight:600;margin-bottom:4px}
          header p{font-size:.8rem;opacity:.6}
          .banner{padding:12px 28px;font-weight:600;font-size:.9rem}
          .banner.pass{background:#d4edda;color:#155724}
          .banner.warn{background:#fff3cd;color:#7d6608}
          .banner.fail{background:#f8d7da;color:#721c24}
          .meta{padding:10px 28px;background:#f8f9fa;border-bottom:1px solid #e9ecef;font-size:.8rem;color:#555}
          table{width:100%;border-collapse:collapse}
          th{text-align:left;padding:9px 16px;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;background:#343a40;color:#ccc}
          td{padding:9px 16px;border-bottom:1px solid #f0f0f0;font-size:.85rem;vertical-align:top}
          tr.pass td{background:#f6fff8}
          tr.warn td{background:#fffef0}
          tr.fail td{background:#fff6f6}
          tr.skip td{background:#fafafa;color:#999}
          td.ic{width:28px;font-size:1rem;font-weight:700;text-align:center}
          tr.pass .ic{color:#28a745}
          tr.warn .ic{color:#856404}
          tr.fail .ic{color:#dc3545}
          tr.skip .ic{color:#aaa}
          td.lbl{white-space:nowrap;font-weight:600;width:170px}
          td.det ul{margin-top:5px;padding-left:16px}
          td.det li{color:#666;margin:2px 0}
          li.exc{font-family:'SFMono-Regular',Consolas,monospace;font-size:.78rem;color:#444;background:#f5f5f5;border-radius:3px;padding:2px 5px;word-break:break-word;list-style:none;border-left:2px solid #ccc;margin-left:-16px;padding-left:14px}
          footer{padding:12px 28px;text-align:right;font-size:.75rem;color:#aaa;border-top:1px solid #f0f0f0}
        </style>
      </head>
      <body>
        <div class="card">
          <header>
            <h1>Puppet Enterprise &mdash; Preflight Report</h1>
            <p>Architecture: ${$arch['architecture']} &bull; Platform: ${platform} &bull; Targets: ${all_targets.size}${version_meta}</p>
            <p>Generated: ${report_ts}</p>
          </header>
          <div class="banner ${overall_cls}">${overall_msg}</div>
          <table>
            <thead><tr><th></th><th>Check</th><th>Result</th></tr></thead>
            <tbody>
      ${tr_html}
            </tbody>
          </table>
          <footer>peadm::preflight &bull; ${report_ts}</footer>
        </div>
      </body>
      </html>
      | HTML
    file::write($actual_report_file, $html_content)
    out::message("# HTML report written to ${actual_report_file}")
  }

  if $warning_count > 0 {
    return("Preflight checks completed with ${warning_count} warning(s). Review the summary above before proceeding.")
  }

  return("Preflight checks passed. Infrastructure is ready for peadm::install or peadm::upgrade.")
}
