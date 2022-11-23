import requests
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Eror fetching :{res.status_code}, check the api and try again"
        )
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # check password if it existes in API reponce
    hash_obj = hashlib.sha1(password.encode("utf-8"))
    sha1_pass = hash_obj.hexdigest().upper()
    first5_char, tail = sha1_pass[:5], sha1_pass[5:]
    res = request_api_data(first5_char)
    return get_password_leaks_count(res, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times ... you should change it")

        else:
            print(f"{password} was NOT FOUND . Carry On!")
    return "done"


if __name__ == "__main__":
    args = sys.argv[1:]
    sys.exit(main(args))
