
# PHP Obfuscator Script

This is a Python-based PHP obfuscation tool that allows you to obfuscate your PHP code by encoding strings into hexadecimal or Base64 format, helping protect your code from reverse engineering or unauthorized access.

## Features

- **Base64 Encoding**: Obfuscates your PHP code by encoding it into Base64.
- **Hexadecimal Conversion**: Converts PHP strings to hexadecimal format.
- **Folder-based Obfuscation**: Obfuscates all PHP files in a specified folder and outputs the obfuscated version into another folder.
- **Requests to External Obfuscator**: Optionally integrates with an external service (`php-minify.com`) to obfuscate the code.

## Requirements

- Python 3.x
- `requests` library

Install the `requests` library using pip:

```bash
pip install requests
```

## How to Use

1. Clone the repository and navigate to the project directory.

```bash
git clone https://github.com/your-username/php-obfuscator.git
cd php-obfuscator
```

2. Run the script:

```bash
python obfuscate_script.py
```

3. Input the folder containing the PHP files you want to obfuscate when prompted:

```bash
Input folder (PHP project): /path/to/your/php/files
Output folder (Obfuscated project): /path/to/output/folder
```

The script will obfuscate the PHP files and save them in the specified output folder.

## Example

```bash
Input folder (PHP project): ./php_project
Output folder (Obfuscated project): ./php_project_obfuscated
```

The script will process all `.php` files within the folder and generate obfuscated versions in the output folder.

## Obfuscation Options

1. **Base64 Encoding**: The script encodes the entire PHP code in Base64 format and wraps it in an `eval(base64_decode())` function.
   
2. **Hexadecimal String Conversion**: The script detects and converts all strings in the PHP code into hexadecimal format, further obfuscating the code.

3. **External Obfuscation Request**: The script has an option to use an external service (`php-minify.com`) to further obfuscate the PHP code. This is done via HTTP requests.

## Disclaimer

This script is for educational purposes. Use responsibly to protect your code, but remember that no obfuscation method is foolproof. Always keep a secure backup of your original code.

## Contributing

Feel free to contribute to this project by submitting issues or pull requests. Your feedback and suggestions are welcome!