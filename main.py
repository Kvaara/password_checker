import requests
import hashlib
import sys


def request_api_data(query_char):
    url = f"https://api.pwnedpasswords.com/range/{query_char}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"There was an error fetching the data: {res.status_code}.")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_characters, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_characters)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times... It would be wise to change your password.")
        else:
            print("Your password was NOT found. You're all good to go!")
    return "done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


