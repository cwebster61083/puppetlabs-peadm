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
  # PostgreSQL port 5432 is checked separately for XL only (primary → psql node)
  out::message('# Checking firewall rules (PE ports on primary)')
  $primary_fqdn = $primary_target[0].peadm::certname()

  $firewall_infra_targets = peadm::flatten_compact([$replica_target, $compiler_targets])
  $fw_port_results = {}

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

  $fw_5432_failures = [] + ($primary_postgresql_target.size > 0 ? {
    true => run_command(
      "timeout 5 bash -c 'echo >/dev/tcp/${$primary_postgresql_target[0].peadm::certname()}/5432'",
      $primary_target,
      '_catch_errors' => true,
    ).error_set.targets.map |$t| { "${$t.peadm::certname()} -> ${$primary_postgresql_target[0].peadm::certname()}:5432" },
    default => [],
  })

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
    'for log in puppetserver/puppetserver puppetdb/puppetdb console-services/console-services orchestration-services/orchestration-services; do errs=$(tail -500 /var/log/puppetlabs/$log.log 2>/dev/null | grep "ERROR\|FATAL"); if [ -n "$errs" ]; then count=$(echo "$errs" | wc -l | tr -d " "); echo "$log: $count recent error(s)"; echo "$errs" | tail -3 | sed "s/^/  >> /"; fi; done; true',
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
      'errs=$(tail -500 /var/log/puppetlabs/pxp-agent/pxp-agent.log 2>/dev/null | grep "ERROR\|FATAL"); if [ -n "$errs" ]; then count=$(echo "$errs" | wc -l | tr -d " "); echo "pxp-agent: $count recent error(s)"; echo "$errs" | tail -3 | sed "s/^/  >> /"; fi; true',
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

  $all_log_warnings = $log_warnings + $compiler_log_warnings

  if $all_log_warnings.size > 0 {
    out::message("WARNING: Recent ERROR/FATAL entries found in PE logs:\n  ${$all_log_warnings.join("\n  ")}")
  }

  $warning_count = $hostname_mismatches.size
    + ($rules_check['updated'] ? { true => 0, default => 1 })
    + $disk_warnings.size
    + $mem_warnings.size
    + $all_svc_issues.size
    + $all_log_warnings.size

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

  $log_summary = $all_log_warnings.size > 0 ? {
    true    => "${warn}  Log errors         : ERROR/FATAL entries found in PE logs\n${
      $all_log_warnings.map |$l| {
        $l =~ /^  >> / ? {
          true    => "              ${$l.strip}",
          default => "           ⤷ ${l}",
        }
      }.join("\n")
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
    ================================================
    | SUMMARY

  if $warning_count > 0 {
    return("Preflight checks completed with ${warning_count} warning(s). Review the summary above before proceeding.")
  }

  return("Preflight checks passed. Infrastructure is ready for peadm::install or peadm::upgrade.")
}
