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


def find_and_validate_credit_cards(text):
    cards = r'\b(?:\d{4}[\s]?){3}\d{4}\b'
    match = (re.findall(cards, text))
    valid = []
    invalid = []
    
    for card in match:
        cleaned_card = re.sub(r'[\s-]', '', card)
        potential_card = [int(digit) for digit in cleaned_card]
        odd_position = potential_card[::2]
        even_position = potential_card[1::2]
        check_list = []
        for digit in odd_position:
            digit = digit * 2
            check_list.append(digit)
        check_list_new = []
        for digit in check_list:
            if digit > 9:
                digit -= 9
            check_list_new.append(digit)
            sequence = even_position + check_list_new
        count = 0

        for digit in sequence:
            count += int(digit)
        if count % 10 == 0:
            valid.append(str(card))
        else:
            invalid.append(str(card))
    invalidated = " ".join(list(set(invalid)))
    validated = " ".join(list(set(valid)))
    return f"valid: {validated} invalid: {invalidated}"


print(find_and_validate_credit_cards(text))
print(find_system_info(lines))













