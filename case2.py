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


def decode_messages(text):
    """
    finds and decodes messages
    returns: {'base64': [], 'hex': [], 'rot13': []}
    """
    result = {
        'base64': [],
        'hex': [],
        'rot13': []
        }
    base64_candidates = re.findall(r'[A-Za-z0-9+/=]{4,}', text)

    for candidate in base64_candidates:
        if candidate.isdigit():
            continue
        if candidate.isalpha():
            continue
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_digit = any(c.isdigit() for c in candidate)
        has_special = any(c in '+/=' for c in candidate)
        types_count = sum([has_upper, has_lower, has_digit, has_special])
        if ((len(candidate) % 4 == 0 or '=' in candidate)
            and types_count >= 2):
            try:
                decoded_bytes = base64.b64decode(candidate)
                decoded_str = decoded_bytes.decode('utf-8')
                if (decoded_str.isprintable() and len(decoded_str) > 0
                    and (' ' in decoded_str)):
                    result['base64'].append(decoded_str)
            except:
                pass

    hex_prefix = re.findall(r'0x([A-Fa-f0-9]+)', text)
    hex_escaped = re.findall(r'(?:\\x([A-Fa-f0-9]{2}))+', text)
    hex_candidates = re.findall(r'\b([A-Fa-f0-9]{4,})\b', text)
    all_hex = hex_prefix + hex_escaped + hex_candidates

    for hex_str in all_hex:
        if len(hex_str) % 2 == 0:
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded_str = decoded_bytes.decode('utf-8')
                if decoded_str.isprintable() and len(decoded_str) > 0 and (' ' in decoded_str):
                    result['hex'].append(decoded_str)
            except:
                pass
                
    rot13_candidates = re.findall(r'[A-Za-z]{4,}', text)

    for candidate in rot13_candidates:
        kwords = { 'the', 'be', 'to', 'of', 'and', 'a', 'in',
                   'that', 'have', 'this', 'is', 'are', 'was',
                   'were', 'for', 'with', 'from', 'hello', 'world',
                   'password', 'admin', 'user', 'login', 'secret',
                   'key', 'api', 'token', 'summer', 'winter', 'spring',
                   'autumn', '2024', '2023', '2025', 'true', 'false',
                   'null', 'none', 'yes', 'no', 'error', 'warning', 'info',
                   'debug', 'trace', 'log', 'file', 'data', 'text', 'string'
                   }
        if candidate.lower() in kwords:
            continue
        if candidate[0].isdigit() or candidate[-1].isdigit():
            continue
        if candidate[0].isdigit() or candidate[-1].isdigit():
            continue
        try:
            decoded = codecs.decode(candidate, 'rot_13')
            if decoded == candidate or not decoded.isprintable():
                continue
            vowels = 'aeiouyAEIOUY'
            if not any(c in vowels for c in decoded):
                continue
            if decoded.lower() in kwords:
                result['rot13'].append(decoded)
                continue
        except:
            pass

    for key in result:
        unique = []
        for item in result[key]:
            if item not in unique:
                unique.append(item)
        result[key] = unique

    return result


print(decode_messages(main_text))
print(find_and_validate_credit_cards(text))
print(find_system_info(lines))














