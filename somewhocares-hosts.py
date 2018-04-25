#!/usr/bin/env python3

import requests
import bs4


def strip(html):
    soup = bs4.BeautifulSoup(html, "html.parser")
    body = soup.find("div", "BODY")
    pre = body.find("pre").text
    lines = [l.strip() for l in pre.splitlines() \
             if not l.strip().startswith("#") and len(l.strip()) ]
    return lines


def main():
    url = "http://someonewhocares.org/hosts/"
    res = requests.get(url)
    if res.status_code != 200:
        print("Failed to get the page: got %d " % res.status_code)
        exit(1)
    html = res.text

    stripped = strip(html)
    print("\n".join(stripped))
    return


if __name__ == "__main__":
    main()
