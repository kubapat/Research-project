import syscall

# List of syscall numbers
syscall_numbers = [0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,24,25,28,32,33,34,35,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,58,59,60,61,62,63,72,77,78,79,80,82,83,84,87,89,90,92,95,96,99,102,105,106,107,108,110,112,113,114,115,116,117,119,126,130,137,141,143,144,145,146,147,157,186,201,202,203,213,218,221,228,229,231,232,233,234,235,257,262,273,288,290,296,302,307,318]

syscall_mapping = {}

for num in syscall_numbers:
    try:
        name = syscall.name(num)
        syscall_mapping[num] = name
    except ValueError:
        syscall_mapping[num] = "Unknown"

for num, name in syscall_mapping.items():
    print(f"Syscall Number: {num}, Name: {name}")
