import hashlib

import requests

import sys

import os

# FILE PATH VARIABLE
path = os.path.join(os.path.dirname(__file__), 'passwords.txt')
list_passwords = ''

try:
    with open(path) as f:
        list_passwords = f.read().splitlines()
except FileNotFoundError as error:
    print(f'Failed to open file {error}')


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again!')
    else:
        return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check.upper():
            return count
    return 0


def pwned_api_check(password_to_encrypt):
    sha1password = hashlib.sha1(password_to_encrypt.encode('utf-8').upper()).hexdigest()
    first_5char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password}, has been found for {count} times... you should probably need to change it!')
        else:
            print(f'{password} was NOT found. Keep it On!')


if __name__ == '__main__':
    sys.exit(main(list_passwords))
