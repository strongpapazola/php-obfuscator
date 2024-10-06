import os
import requests
import urllib.parse

def encode_php_code(php_code):
    # Use urllib.parse.quote to encode the PHP code
    return urllib.parse.quote(php_code)

def request_ob(code):
    try:
        headers = {
            'accept': 'text/html, */*; q=0.01',
            'accept-language': 'en-US,en;q=0.5',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://php-minify.com',
            'priority': 'u=1, i',
            'referer': 'https://php-minify.com/php-obfuscator/',
            'sec-ch-ua': '"Brave";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        # Mengencode source code PHP yang akan diobfuscate
        # source_code = code.replace(' ', '+')
        # source_code = code.replace('"', '\"')
        source_code = encode_php_code(code)
        # data = f"csrfToken=&sourceCode={source_code}&evalMode=1"
        data = f"csrfToken=&sourceCode={source_code}"

        response = requests.post('https://php-minify.com/php-obfuscator/index.php', headers=headers, data=data)

        # Handling response untuk status code selain 200
        if response.status_code == 200:
            result = response.text
            # ganti "1<?php" ke "<?php"
            result = result.replace("1<?php", "<?php")
            return result
        else:
            return f"Error: Received status code {response.status_code}"

    except requests.exceptions.RequestException as e:
        # Menangani error saat request
        return f"Error: {str(e)}"


import re

def string_to_hex(s):
    # Convert each character in the string to its hexadecimal representation
    return ''.join(f'\\x{ord(c):02x}' if c.isprintable() else c for c in s)

# def detect_strings_in_php(php_code):
#     # Regular expression pattern to match strings in PHP code
#     # pattern = r'\"(.*?)\"|\'.*?\''
#     # pattern = r'\'.*?\'|\"(.*?)\"'
#     pattern = r'\'.*?\''

#     # Find all strings in the PHP code
#     strings_found = re.findall(pattern, php_code)

#     # Filter out any empty results
#     strings_found = [s for s in strings_found if s]

#     return strings_found

import re

def string_to_hex(s):
    # Convert each character in the string to its hexadecimal representation
    return ''.join(f'\\x{ord(c):02x}' for c in s)

def detect_strings_vscode_style(php_code):
    strings = []
    inside_string = False
    current_string = ""
    escape_char = False
    string_delimiter = None

    for char in php_code:
        if inside_string:
            if escape_char:
                # Handle escaped characters like \", \'
                current_string += char
                escape_char = False
            elif char == '\\':
                # Next character will be escaped
                current_string += char
                escape_char = True
            elif char == string_delimiter:
                # Closing the string
                current_string += char
                strings.append(current_string)
                current_string = ""
                inside_string = False
            else:
                # Still inside the string
                current_string += char
        else:
            if char == '"' or char == "'":
                # Opening a new string
                inside_string = True
                string_delimiter = char
                current_string = char
            # Continue if not inside a string

    return strings

def replace_php_strings_with_hex(php_code):
    strings = detect_strings_vscode_style(php_code)

    # Replace each detected string with its hexadecimal equivalent
    for string in strings:
        # Remove surrounding quotes and convert string contents to hex
        inner_string = string[1:-1]  # Remove the first and last quote
        hex_string = string_to_hex(inner_string)  # Convert to hex
        hex_string_with_quotes = f'{string[0]}{hex_string}{string[-1]}'  # Re-apply the original quote type
        
        # Replace the original string in PHP code with its hex equivalent
        php_code = php_code.replace(string, hex_string_with_quotes)

    # replace ' => "
    php_code = php_code.replace("'", '"')
    return php_code

import base64

def obfuscate_php_with_base64(php_code):
    # Step 1: Remove the PHP opening tag to prevent issues with eval()
    if php_code.startswith('<?php'):
        php_code = php_code[len('<?php'):].strip()  # Remove the opening tag and leading/trailing whitespace
    
    # Step 2: Replace strings with hexadecimal
    php_code_with_hex = replace_php_strings_with_hex(php_code)
    
    # Step 3: Encode the whole PHP code in Base64
    encoded_php = base64.b64encode(php_code_with_hex.encode('utf-8')).decode('utf-8')
    
    # Step 4: Create eval with base64_decode in PHP
    obfuscated_php = f'<?php eval(base64_decode(\'{encoded_php}\')); ?>'
    
    return obfuscated_php

# Fungsi untuk membaca file PHP dari folder input dan menulis hasil obfuscasi ke folder output
def obfuscate_folder(input_folder, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.endswith(".php"):
            # if file.endswith("Bankdata_customer.php"):
                input_file_path = os.path.join(root, file)
                output_file_path = os.path.join(output_folder, os.path.relpath(input_file_path, input_folder))

                # Membaca konten file PHP
                with open(input_file_path, "r", encoding="utf-8") as input_file:
                    code = input_file.read()

                # Obfuscate konten file
                # obfuscated_code = obfuscate_php_code(code)
                # obfuscated_code = request_ob(code)

                # obfuscated_code = replace_php_strings_with_hex(code)
                obfuscated_code = obfuscate_php_with_base64(code)

                # obfuscated_code = "\n".join(detect_strings_in_php(code))
                # obfuscated_code = "\n".join(detect_strings_vscode_style(code))

                # Membuat folder output jika belum ada
                output_file_dir = os.path.dirname(output_file_path)
                if not os.path.exists(output_file_dir):
                    os.makedirs(output_file_dir)

                # Menyimpan hasil obfuscasi ke file di folder output
                with open(output_file_path, "w", encoding="utf-8") as output_file:
                    output_file.write(obfuscated_code)

                print(f"Obfuscated {input_file_path} -> {output_file_path}")

# Main
if __name__ == "__main__":

    # rm controllers
    os.system("rm -rf controllers")
    input_folder = input("Input folder (PHP project): ")
    output_folder = input("Output folder (Obfuscated project): ")
    # input_folder = "controllers-insecure"
    # output_folder = "controllers"

    # Obfuscate the project folder
    obfuscate_folder(input_folder, output_folder)
    # os.system(f"cp -r {input_folder} {output_folder}")

    print("Obfuscation complete.")
