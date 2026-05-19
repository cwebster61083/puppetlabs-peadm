# @summary Perform preflight checks for a PE cluster before install or upgrade
#
# Validates that the target infrastructure meets requirements before running
# peadm::install or peadm::upgrade. Checks include Bolt version support,
# PE version support, architecture validity, node connectivity, OS platform
# consistency, and hostname/certname alignment.
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

  # Check that PE master rules are current (relevant for existing installations)
  out::message('# Checking PE master rules')
  $rules_check = run_task('peadm::check_pe_master_rules', $primary_target).first.value
  if ! $rules_check['updated'] {
    out::message('WARNING: PE master rules are not current. Run the peadm::convert plan before proceeding with an upgrade.')
  }

  $warning_count = $hostname_mismatches.size + ($rules_check['updated'] ? { true => 0, default => 1 })

  out::message("# Architecture : ${$arch['architecture']}")
  out::message("# Platform     : ${platform}")

  if $warning_count > 0 {
    return("Preflight checks completed with ${warning_count} warning(s). Review the output above before proceeding.")
  }

  return("Preflight checks passed. Infrastructure is ready for peadm::install or peadm::upgrade.")
}
