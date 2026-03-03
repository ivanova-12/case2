import re
import codecs
import base64
def find_system_info(text):
    """
    find sistem information
    return: {'ips': [], 'files': [], 'emails': []}
    """
    potential_ips = []
    potential_emails = []
    potential_files = []
    result = {
        'ips': [],
        'files': [],
        'emails': []
    }
    if isinstance(text, list):
        lines = text
    else:
        lines = [text]
    for line in lines:
        potential_ips.extend(
            (re.findall(r'\b[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\b', line)))
        potential_emails.extend(re.findall(r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', line))
        potential_files.extend(
            re.findall(r'\b[A-Z]:\\(?:[a-zA-Zа-яА-Я0-9_-]+\\)*[a-zA-Zа-яА-Я0-9_-]{1,255}\.[a-zA-Z0-9]{1,}\b', line))
    ips = []
    for ip in potential_ips:
        if all(0 <= int(num) <= 255 and len(str(int(num))) == len(num) for num in ip.split('.')):
            ips.append(ip)
    result['ips'] = list(set(ips))
    emails = []
    for email in potential_emails:
        if len(email) <= 254:
            emails.append(email)
    result['emails'] = list(set(emails))
    files = []
    for file in potential_files:
        if len(file) <= 255:
            files.append(file)
    result['files'] = list(set(files))
    return result


def find_and_validate_credit_cards(text):
    """
    find credit cards numbers and check
    return: {'valid': [], 'invalid': []}
    """
    if isinstance(text, list):
        lines = text
    else:
        lines = [text]
    result = {'valid': [], 'invalid': []}
    valid = []
    invalid = []
    for line in lines:
        cards = r'\b(?:\d{4}[\s-]*?){3}\d{4}\b'
        match = (re.findall(cards, line))
        for card in match:
            clean_card = re.sub(r'[\s-]', '', card)
            potential_card = [int(digit) for digit in clean_card]
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
    return f"valid: {set(valid)}, invalid: {set(invalid)}"


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
    if isinstance(text, list):
        text_str = ' '.join(text)
    else:
        text_str = text
    base64_candidates = re.findall(r'[A-Za-z0-9+/=]{4,}', text_str)
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
                if ((decoded_str.isprintable()) and (len(decoded_str) > 0)
                    and (' ' in decoded_str)):
                    
                    for i in decoded_str.split():
                        if i.isalpha():
                            result['hex'].append(decoded_str)
            except:
                pass

    rot13_words = r'\b[A-Za-z]+\s[A-Za-z]+(?:\s[A-Za-z]+)*\b'
    rot13_candidates = re.findall(rot13_words, text)
    kwords = {'the', 'be', 'to', 'of', 'and', 'a', 'in',
              'that', 'have', 'this', 'is', 'are', 'was',
              'were', 'for', 'with', 'from', 'hello', 'world',
              'password', 'admin', 'user', 'login', 'secret',
              'key', 'api', 'token', 'summer', 'winter', 'spring',
              'autumn', '2024', '2023', '2025', 'true', 'false',
              'null', 'none', 'yes', 'no', 'error', 'warning', 'info',
              'debug', 'trace', 'log', 'file', 'data', 'text', 'string',
              'txt', 'api', 'live', 'test', 'i', 'an', 'his', 'her',
              'my', 'he', 'she', 'me', 'google', 'user', 'users', 'secure',
              'megasecure'
              }
    res_candidates = []

    for candidate in rot13_candidates:
        words_in_cand = candidate.split(' ')
        if (len(words_in_cand) >1) and (candidate.isprintable()):
            res_candidates.append(candidate)

            for w in words_in_cand:
                if w.lower() in kwords:
                    res_candidates.remove(candidate)
    decoded_words = []
    for element in res_candidates:
        try:
            decoded_word = codecs.decode(element, 'rot_13')
            decoded_words.append(decoded_word)
        except:
            pass

    for element in decoded_words:
        result['rot13'].append(element)

    for key in result:
        unique = []
        for item in result[key]:
            if item not in unique:
                unique.append(item)
        result[key] = unique

    return result


def generate_comprehensive_report(main_text):
    """
    Generate whole report about investigation
    """
    report = { 'financial_data': find_and_validate_credit_cards(main_text),
               'system_info': find_system_info(main_text),
               'encoded_messages': decode_messages(main_text),
               }
    return report


def print_report(report):
    """
    outputs a report in a specific standard
    """
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    # Вывод результатов каждой роли
    sections = [ ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
                 ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
                 ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
               ]
    for title, data in sections:
        print(f"\n{title}: {data}")
        print("-" * 30)


if __name__ == '__main__':
    with open('input.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
        report = generate_comprehensive_report(main_text)
        print_report(report)

















