import requests
from bs4 import BeautifulSoup

url = "https://filippo.io/linux-syscall-table/"
response = requests.get(url)
html_content = response.content

soup = BeautifulSoup(html_content, 'html.parser')

syscall_table = {}
for row in soup.find_all('tr'):
    cols = row.find_all('td')
    if len(cols) >= 2:
        number = cols[0].text.strip()
        name = cols[1].text.strip()
        if number.isdigit():
            syscall_table[int(number)] = name

# Provided syscall numbers (INPUT)
syscall_numbers = [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 24, 25, 28, 32, 33, 34, 35, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62, 63, 72, 77, 78, 79, 80, 82, 83, 84, 87, 89, 90, 92, 95, 96, 99, 102, 105, 106, 107, 108, 110, 112, 113, 114, 115, 116, 117, 119, 126, 130, 137, 141, 143, 144, 145, 146, 147, 157, 186, 201, 202, 203, 213, 218, 221, 228, 229, 231, 232, 233, 234, 235, 257, 262, 273, 288, 290, 296, 302, 307, 318]

mapped_syscalls = {num: syscall_table.get(num, "Unknown") for num in syscall_numbers}

# Print the mapping
for num, name in mapped_syscalls.items():
    print(f"Syscall Number: {num}, Name: {name}")
