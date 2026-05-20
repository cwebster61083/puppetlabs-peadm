# @summary Run peadm::preflight with topology discovered from the PE primary.
#
# Connects to the PE primary and runs the peadm::get_peadm_config task, which
# queries the PE classifier and PuppetDB to return the live infrastructure
# layout. The discovered hosts are then passed directly to peadm::preflight.
#
# Requires PE to be installed and running on the primary.
#
# @param primary_host
#   The hostname or IP of the PE primary server.
# @param version
#   Target PE version to validate. When provided, it is checked against the set
#   of known supported PE versions.
# @param permit_unsafe_versions
#   When true, suppresses the error raised for PE versions not in the known
#   supported list.
# @param html_report_file
#   When provided, the preflight check results are written to this local file
#   path as a self-contained HTML report.
plan peadm::preflight_auto (
  Peadm::SingleTargetSpec $primary_host,
  Optional[String]        $version               = undef,
  Boolean                 $permit_unsafe_versions = false,
  Optional[String]        $html_report_file       = undef,
) {
  $primary_target = peadm::get_targets($primary_host, 1)

  out::message('# Discovering PE infrastructure topology from primary')
  $config_result = run_task('peadm::get_peadm_config', $primary_target).first.value

  if $config_result['error'] {
    fail_plan("get_peadm_config failed: ${$config_result['error']}")
  }

  $params            = $config_result['params']
  $primary           = $params['primary_host']
  $replica           = $params['replica_host']
  $primary_psql      = $params['primary_postgresql_host']
  $replica_psql      = $params['replica_postgresql_host']
  $all_compilers     = ($params['compilers'] + $params['legacy_compilers']).unique
  $compiler_hosts    = $all_compilers.size > 0 ? {
    true    => $all_compilers,
    default => undef,
  }

  # Report what was found
  $replica_line      = $replica       ? { undef => '', default => "\n  replica:             ${replica}" }
  $primary_psql_line = $primary_psql  ? { undef => '', default => "\n  primary postgresql:  ${primary_psql}" }
  $replica_psql_line = $replica_psql  ? { undef => '', default => "\n  replica postgresql:  ${replica_psql}" }
  $compilers_line    = $compiler_hosts ? { undef => '', default => "\n  compilers:           ${$compiler_hosts.join(', ')}" }
  $version_line      = $config_result['pe_version'] ? { undef => '', default => "\n  detected PE version: ${$config_result['pe_version']}" }

  out::message(@("MSG"))
    Discovered topology:
      primary:             ${primary}${replica_line}${primary_psql_line}${replica_psql_line}${compilers_line}${version_line}
    | MSG

  # Use the version detected from the primary if not explicitly provided
  $effective_version = $version ? {
    undef   => $config_result['pe_version'],
    default => $version,
  }

  $preflight_params = {
    primary_host            => $primary,
    replica_host            => $replica,
    primary_postgresql_host => $primary_psql,
    replica_postgresql_host => $replica_psql,
    compiler_hosts          => $compiler_hosts,
    version                 => $effective_version,
    permit_unsafe_versions  => $permit_unsafe_versions,
    html_report_file        => $html_report_file,
  }.filter |$_k, $v| { $v =~ NotUndef }

  run_plan('peadm::preflight', $preflight_params)
}
