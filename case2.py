import re

with open('input.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()


def find_system_info(text):
    """
    find sistem information
    return: {'ips': [], 'files': [], 'emails': []}
    """
    potential_ips = []
    potential_emails = []
    potential_files = []
    for line in text:
        potential_ips.extend((re.findall(r'\b[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\b', line)))
        potential_emails.extend(re.findall(r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', line))
        potential_files.extend(re.findall(r'\b[A-Z]:\\(?:[a-zA-Zа-яА-Я0-9_-]+\\)*[a-zA-Zа-яА-Я0-9_-]{1,255}\.[a-zA-Z0-9]{1,}\b', line))
    ips = []
    for ip in potential_ips:
            if all(0 <= int(num) <= 255 and len(str(int(num))) == len(num) for num in ip.split('.')):
                    ips.append(ip)
    emails = []
    for email in potential_emails:
        if len(email) <= 254:
            emails.append(email)
    files = []
    for file in potential_files:
        if len(file) <= 255:
            files.append(file)
    return set(ips), set(emails), set(files)


def normalize_and_validate(text):
    """
    format date to standard and chek it up
    return: { 'phones': {'valid': [], 'invalid': []},
    'dates': {'normalized': [], 'invalid': []},
    'inn': {'valid': [], 'invalid': []},
    'cards': {'valid': [], 'invalid': []} }
    """
print(find_system_info(lines))











