#!/usr/bin/env python3
"""generate_all_codes.py

Usage:
  generate_all_codes.py [-o|--old]  ANDOTP_AES_BACKUP_FILE
  generate_all_codes.py [-o|--old]  ANDOTP_AES_BACKUP_FILE ISSUER_MATCH_STRING

Options:
  -o --old      Use old encryption (andOTP <= 0.6.2)
  -h --help     Show this screen.
  --version     Show version.

"""
from docopt import docopt
import sys
import pyotp
import json
import andotp_decrypt


def main():
    arguments = docopt(__doc__, version='generate_all_codes 0.1')

    password = andotp_decrypt.get_password()

    text = None
    if arguments['--old']:
        text = andotp_decrypt.decrypt_aes(password,
                                          arguments['ANDOTP_AES_BACKUP_FILE'])
    else:
        text = andotp_decrypt.decrypt_aes_new_format(
                password, arguments['ANDOTP_AES_BACKUP_FILE'])

    if not text:
        print("Something went wrong while loading %s. Maybe the passphrase was"
              " wrong or the input file is empty!"
              % arguments['ANDOTP_AES_BACKUP_FILE'])
        sys.exit(1)
    entries = json.loads(text)

    entry_found_flag = False
    for entry in entries:
        issuer = entry['issuer']
        label = entry['label']

        if arguments["ISSUER_MATCH_STRING"] is None:
            entry_found_flag = True

            if entry['type'] == 'TOTP':
                totp = pyotp.TOTP(entry['secret'], interval=entry['period'])
                print('\n' + issuer + ': ' + label)
                print('TOTP: ' + totp.now())

            else:
                print(issuer + ': ' + label)
                print('Unsupported OTP type')

        elif arguments["ISSUER_MATCH_STRING"].lower() in issuer.lower():
            entry_found_flag = True

            if entry['type'] == 'TOTP':
                totp = pyotp.TOTP(entry['secret'], interval=entry['period'])
                print('\n' + issuer + ': ' + label)
                print('TOTP: ' + totp.now())

            else:
                print(issuer + ': ' + label)
                print('Unsupported OTP type')

    if entry_found_flag is False:
        print("No entry found")


if __name__ == '__main__':
    main()
