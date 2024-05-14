import matplotlib.pyplot as plt
from collections import defaultdict
import re

logs = """
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  7.14    0.000034           5         6           write
 12.39    0.000059          14         4           mmap
  7.14    0.000034           8         4           writev
  3.57    0.000017           8         2           brk
  6.09    0.000029          14         2           mprotect
  5.04    0.000024          12         2           munmap
  1.68    0.000008           8         1           getuid
  1.68    0.000008           8         1           set_tid_address
  1.26    0.000006           6         1           arch_prctl
 53.99    0.000257         257         1           execve
------ ----------- ----------- --------- --------- ----------------
100.00    0.000476          19        24           total
"""


# Function to parse the logs and return syscall counts
def parse_logs(logs):
    syscall_counts = defaultdict(int)
    pattern = re.compile(r'\s*\d+\.\d+\s+\d+\.\d+\s+\d+\s+(\d+)\s+\d*\s*(\w+)')

    for line in logs.splitlines():
        match = pattern.match(line)
        if match:
            count = int(match.group(1))
            syscall = match.group(2)
            syscall_counts[syscall] += count

    return syscall_counts


def main():
    syscall_counts = parse_logs(logs)

    # Display the parsed data (for verification)
    print(syscall_counts)

    # Plotting the histogram
    plt.figure(figsize=(10, 5))
    plt.bar(syscall_counts.keys(), syscall_counts.values(), color='blue')
    plt.xlabel('Syscall')
    plt.ylabel('Count')
    plt.title('Syscall Histogram')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    main()
