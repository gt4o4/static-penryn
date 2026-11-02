"""The `static-penryn` command: `profile`, `workloads` and `bench` select the
profiling tools, anything else is the rewriter's own command line."""
import sys


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command not in ('profile', 'workloads', 'bench'):
        from . import patch
        patch.main()
        return
    # The tool's own usage then names its subcommand.
    sys.argv[0:2] = [f'{sys.argv[0]} {command}']
    if command == 'profile':
        from . import profile
        profile.main()
    elif command == 'workloads':
        from . import workloads
        workloads.main()
    else:
        from . import bench_apps
        bench_apps.main()
