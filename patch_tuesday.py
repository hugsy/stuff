import argparse
import datetime
import re
import os
from typing import List, Optional, Union

import bs4
import requests

DEBUG = True

API_URL: str = "https://api.msrc.microsoft.com/cvrf/v2.0/document"
DEFAULT_PRODUCT: str = "Windows 11 Version 21H2 for x64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for 32-bit Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for ARM64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 1909 for x64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 1809 for x64-based Systems"
KB_SEARCH_URL: str = "https://catalog.update.microsoft.com/v7/site/Search.aspx"
DEFAULT_UA: str = """Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"""
CVE_URL: str = "https://msrc.microsoft.com/update-guide/vulnerability"


def err(x: str): print(f"[-] {x}")
def warn(x: str): print(f"[!] {x}")
def ok(x: str): print(f"[+] {x}")
def info(x: str): print(f"[*] {x}")
def dbg(x: str): DEBUG and print(f"[*] {x}")


class Product:
    id: str
    name: str
    __node: bs4.BeautifulSoup
    vulnerabilities: list["Vulnerability"]

    def __init__(self, soup: bs4.BeautifulSoup):
        self.__node = soup
        self.id = self.__node["ProductID"]
        self.name = self.__node.text.strip()
        self.vulnerabilities = []
        return

    def __str__(self):
        return f"{self.name}"


class Vulnerability:
    product: Product
    cve: str
    title: str
    severity: str
    impact: str
    description: str
    itw: bool
    kb: str
    __characteristics: dict[str, str]

    def __init__(self, product: Product, node):
        self.product = product
        self.__node = node
        self.cve = self.__node.find("vuln:CVE").text.strip()
        self.title = self.__node.find("vuln:Title").text.strip()
        self.__characteristics = {}
        self.severity = self.__get_severity()
        self.impact = self.__get_impact()
        self.description = node.find(
            "vuln:Note", Title="Description", Type="Description").text.strip()
        self.kb = self.__get_remediation_info("Description")
        self.superseeded_kb = self.__get_remediation_info("Supercedence")
        self.itw = "Exploited:Yes" in self.__node.find(
            "vuln:Threat", Type="Exploit Status").text.strip()
        self.product.vulnerabilities.append(self)
        return

    def url(self) -> str:
        return f"{KB_SEARCH_URL}?q={self.kb}"

    def __get_impact_or_severity(self, node, what: str) -> str:
        threads = node.find("vuln:Threats")
        if threads:
            for t in threads.find_all("vuln:Threat", Type=what):
                _value = t.find("vuln:ProductID").text.strip()
                _product_ids = list(map(int, _value.split("-", 1)))
                if self.product in _product_ids:
                    return t.find("vuln:Description").text.strip()
        return f"<UNKNOWN_{what.upper()}>"

    def __get_impact(self) -> str:
        if not "Impact" in self.__characteristics:
            self.__characteristics["Impact"] = self.__get_impact_or_severity(
                self.__node, "Impact")
        return self.__characteristics["Impact"]

    def __get_severity(self) -> str:
        if not "Severity" in self.__characteristics:
            self.__characteristics["Severity"] = self.__get_impact_or_severity(
                self.__node, "Severity")
        return self.__characteristics["Severity"]

    def __get_remediation_info(self, what: str) -> str:
        if not what in self.__characteristics:
            self.__characteristics[what] = ""
            for r in self.__node.find_all("vuln:Remediation", Type="Vendor Fix"):
                field = r.find("vuln:ProductID")
                if not field:
                    continue
                current_product_ids = list(
                    map(int, field.text.strip().split("-", 1)))
                if self.product.id in current_product_ids:
                    info = r.find(f"vuln:{what}")
                    self.__characteristics[what] = info.text.strip(
                    ) if info else ""
        return self.__characteristics[what]

    def __str__(self):
        return f"{self.cve} // KB{self.kb} // {self.title} // {self.severity} // {self.impact}"

    @staticmethod
    def find(soup: bs4.BeautifulSoup, cve_or_kb: Union[str, int]) -> List["Vulnerability"]:
        """Search a vuln"""
        if isinstance(cve_or_kb, str):
            if cve_or_kb.lower().startswith("cve-"):
                return Vulnerability.get_vuln_info_by_cve(soup, cve_or_kb)
            if cve_or_kb.lower().startswith("kb"):
                kb: int = int(cve_or_kb[2:])
                return Vulnerability.get_vuln_info_by_kb(soup, kb)
        if isinstance(cve_or_kb, int):
            return Vulnerability.get_vuln_info_by_kb(soup, cve_or_kb)
        raise ValueError

    @staticmethod
    def get_vuln_info_by_cve(soup: bs4.BeautifulSoup, cve: str) -> List["Vulnerability"]:
        """Search a vuln"""
        vulnerabilities: list[Vulnerability] = []
        for vuln in soup.find_all("vuln:Vulnerability"):
            cve_node = vuln.find("vuln:CVE")
            if not cve_node or not cve_node.text:
                continue
            if cve_node.text.lower() == cve.lower():
                for product_id in cve_node.find("vuln:ProductID"):
                    vulnerabilities.append(Vulnerability(product_id, vuln))
        return vulnerabilities

    @staticmethod
    def get_vuln_info_by_kb(soup: bs4.BeautifulSoup, kb: int) -> List["Vulnerability"]:
        """Search a vuln"""
        vulnerabilities: list[Vulnerability] = []
        for vuln in soup.find_all("vuln:Vulnerability"):
            cve_nodes = vuln.find_all("vuln:Remediation")
            if not cve_nodes:
                continue
            for cve_node in cve_nodes:
                kb_node = cve_node.find("vuln:Description")
                if not kb_node or not kb_node.text:
                    continue
                if kb_node.text.isdigit() and kb == int(kb_node.text):
                    for product_id in cve_node.find("vuln:ProductID"):
                        vulnerabilities.append(Vulnerability(product_id, vuln))
        return vulnerabilities


def collect_products(soup: bs4.BeautifulSoup) -> list[Product]:
    p = []
    for product in soup.find_all("prod:FullProductName"):
        p.append(Product(product))
    return p


def get_patch_tuesday_data_soup(month: datetime.date) -> bs4.BeautifulSoup:
    url = f"{API_URL}/{month.strftime('%Y-%b')}"
    h = requests.get(url, headers={'User-Agent': DEFAULT_UA})
    if h.status_code != requests.codes.ok:
        raise RuntimeError(f"Unexpected code HTTP/{h.status_code}")
    return bs4.BeautifulSoup(h.text, features="xml")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get the Patch Tuesday info")
    parser.add_argument("-V", "--vulns", help="Specifiy the vuln(s) to detail (can be repeated)",
                        default=[], action='append', type=str)
    parser.add_argument("-p", "--products", help="Specifiy Product name(s) (can be repeated)",
                        default=[], action='append', type=str)
    parser.add_argument("-m", "--months", help="Specify the Patch Tuesday month(s) (can be repeated)",
                        default=[], action='append',
                        type=lambda x: datetime.datetime.strptime(x, "%Y-%b"), metavar="YYYY-ABBREVMONTH")
    parser.add_argument("-y", "--years", help="Specify a year - will be expended in months (can be repeated)",
                        default=[], action='append', type=int)
    parser.add_argument("--list-products",
                        help="List all products", action="store_true")
    parser.add_argument("--brief", help="Display a summary",
                        action="store_true")
    parser.add_argument("-v", "--verbose", action="count", dest="verbose",
                        help="Increments verbosity")

    args = parser.parse_args()
    vulnerabilities = []

    if args.list_products:
        soup = get_patch_tuesday_data_soup(datetime.date.today())
        products = collect_products(soup)
        print(os.linesep.join([f"- {x}" for x in products]))
        exit(0)

    if not len(args.products):
        print(f"Using default product as '{DEFAULT_PRODUCT}'")
        args.products = (DEFAULT_PRODUCT,)

    if args.years:
        for year in args.years:
            for month in range(1, 13):
                args.months.append(datetime.date(year, month, 1))

    if not len(args.months):
        print(
            f"Using default month as '{datetime.date.today().strftime('%B %Y')}'")
        args.months = (datetime.date.today(),)

    summary = not (args.brief or args.vulns)

    for month in args.months:
        print(f"For {month.strftime('%B %Y')}")
        soup = get_patch_tuesday_data_soup(month)
        products = collect_products(soup)

        if args.brief:
            for product_name in args.products:
                product = list(
                    filter(lambda p: p.name == product_name, products))[0]
                vulns = product.vulnerabilities
                print(f"{product:-^95}")
                print(
                    f"* {len(vulns)} CVE{'s' if len(vulns)>1 else ''} including:")
                print(
                    f"  - { len( list(filter(lambda x: x.severity == 'Critical', vulns)) ) } critical")
                print(
                    f"  - { len( list(filter(lambda x: x.severity == 'Important', vulns)) ) } important")
                print("* with:")
                print(
                    f"  - { len( list(filter(lambda x: x.impact == 'Remote Code Execution', vulns)) ) } are RCE")
                print(
                    f"  - { len( list(filter(lambda x: x.impact == 'Elevation of Privilege', vulns)) ) } are EoP")
                print(
                    f"  - { len( list(filter(lambda x: x.impact == 'Information Disclosure', vulns)) ) } are EoP")

        if args.vulns:
            for vuln_id in args.vulns:
                for vuln in Vulnerability.find(soup, vuln_id):
                    print(f"- Title: {vuln.title}")
                    print(f"- Description: {vuln.description}")
                    print(f"- Impact: {vuln.impact}")
                    print(f"- Severity: {vuln.severity}")
                    print(f"- KB: {vuln.kb}")
                    print(f"- CVE: {vuln.cve}")
                    print(f"- Link: {CVE_URL}/{vuln.cve}")
                    print(f"{'':-^95}")

        if summary:
            for product_name in args.products:
                product = list(
                    filter(lambda p: p.name == product_name, products))[0]
                print(f"{product:-^95}")
                print(os.linesep.join(
                    [f"- {x}" for x in product.vulnerabilities]))
