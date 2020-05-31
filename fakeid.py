#!/usr/bin/env python

import argparse
import sys
import time

import requests
import bs4


__author__    =   "hugsy"
__version__   =   0.2
__licence__   =   "WTFPL v.2"
__file__      =   "fakeid.py"
__desc__      =   """fakeid.py: generates fake people profile"""
__usage__     =   """%prog version {0}, {1}
by {2}
syntax: {0} [options] args
""".format(__version__, __licence__, __author__)


RANDOM_ID_URL = "https://www.fakenamegenerator.com/gen-random-us-us.php"


class RandomPerson:

    def __init__(self):
        text = self.get_page_text()
        if text is None:
            raise Exception
        self.soup = bs4.BeautifulSoup(text, features="html.parser")
        d = self.soup.find("div", "address")
        self.firstname, self.lastname = d.h3.string.rsplit(" ", 1)
        self.address = d.find("div", "adr").text.strip()
        self.age = int(self.get_element("Age").text.split()[0])
        self.email_address = self.get_element("Email Address").text.split()[0]
        self.birthday = " ".join(self.get_element("Birthday").text.split()[:3])
        self.birthday = time.strftime("%d/%m/%Y", time.strptime(self.birthday, "%B %d, %Y"))
        self.username = self.get_element("Username").text
        self.password = self.get_element("Password").text
        self.website = self.get_element("Website").text
        self.occupation = self.get_element("Occupation").text
        return

    def get_element(self, name):
        return self.soup.find("dt", text=name).next_sibling.next_sibling

    def get_page_text(self):
        headers={
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 Edg/83.0.478.37",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9,fr;q=0.8",
        }
        h = requests.get(RANDOM_ID_URL, headers=headers)

        if h.status_code != 200:
            print(h.status_code)
            return None
        return h.text

    def __str__(self):
        return "%s %s" % (self.firstname, self.lastname)

    def to_txt(self):
        buf = "Name: %s" % str(self)

        for attr in dir(self):
            if attr.startswith("__"):
                continue
            a = getattr(self, attr)
            if hasattr(a, "__call__"):
                continue

            buf+= "%s: %s\n" % (attr.capitalize(), a)
        return buf

    def to_csv(self):
        buf = ""
        for attr in dir(self):
            if attr.startswith("__"):
                continue
            a = getattr(self, attr)
            if hasattr(a, "__call__"):
                continue

            buf+= "%s; " % a
        return buf

    def to_xml(self):
        buf = "<person>\n"

        for attr in dir(self):
            if attr.startswith("__"):
                continue
            a = getattr(self, attr)
            if hasattr(a, "__call__"):
                continue

            buf+= "\t<{0}>{1}</{0}>\n".format(attr, a)

        buf+= "</person>"

        return buf


    def as_windows_user(self, ad=None):
        fmt = "net user {0} {1} "
        fmt+= "/active:yes /comment:\"{2}\" "
        fmt+= "/fullname:\"{3}\" /passwordchg:no "

        if ad is not None:
            fmt+= "/domain"

        fmt+= " /add"

        return fmt.format (self.firstname[0].lower() + self.lastname.lower(),
                           self.password, self.occupation, str(self))

    def as_linux_user(self):
        fmt = "adduser -c '{1}' -g users {0} && echo -e \"{2}\\n{2}\" | passwd "
        return fmt.format(self.firstname[0].lower() + self.lastname.lower(),
                          self.occupation,
                          self.password)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = __desc__)

    parser.add_argument("-v", "--verbose", default=False,
	              action="store_true", dest="verbose",
	              help="increments verbosity")

    parser.add_argument("-n", "--num", default=1, dest="number_person", type=int,
                      help="number of person to generate")

    parser.add_argument("--output-format", default="text", dest="output_format",
                        choices=["text", "csv", "xml", "windows", "linux"],
                        help="specify the output format")

    args = parser.parse_args()

    if args.output_format == "xml":
        print("<persons>")
    elif args.output_format == "csv":
        print("address ; age ; birthday ; email ; firstname ; lastname ; occupation ; password ; city ; website ;")

    for i in range(args.number_person):
        p = RandomPerson()

        if args.output_format == "text":
            print(p.to_txt())

        elif args.output_format == "xml":
            print (p.to_xml())

        elif args.output_format == "csv":
            print(p.to_csv())

        elif args.output_format == "windows":
            print(p.as_windows_user())

        elif args.output_format == "linux":
            print(p.as_linux_user())

    if args.output_format == "xml":
        print("</persons>")
