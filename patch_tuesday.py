import argparse
import datetime
import logging
import os
import pathlib
import tempfile
from typing import List, Union

import bs4
import requests
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.tree import Tree

API_URL: str = "https://api.msrc.microsoft.com/cvrf/v2.0/document"
DEFAULT_PRODUCT: str = "Windows 11 Version 22H2 for x64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for 32-bit Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for ARM64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 1909 for x64-based Systems"
# DEFAULT_PRODUCT : str = "Windows 10 Version 1809 for x64-based Systems"
KB_SEARCH_URL: str = "https://catalog.update.microsoft.com/v7/site/Search.aspx"
DEFAULT_UA: str = (
    """Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"""
)
CVE_URL: str = "https://msrc.microsoft.com/update-guide/vulnerability"

log = logging.getLogger(__name__)


def get_root(node: bs4.Tag) -> bs4.Tag:
    curnode = node
    valid_parent = None
    while curnode != None:
        valid_parent = curnode
        curnode = curnode.parent
    assert valid_parent
    return valid_parent


class Product:
    def __init__(self, node: bs4.Tag):
        self.node = node
        self.root = get_root(node)
        assert isinstance(self.root, bs4.Tag)
        __id = self.node["ProductID"]
        assert isinstance(__id, str)
        self.id: str = __id
        self.name: str = self.node.text.strip()
        parent = self.node.parent
        assert parent
        self.family = parent.get("Name", "") or ""
        return

    def __str__(self):
        return f"{self.name}"

    def __format__(self, format_spec) -> str:
        match format_spec[-1]:
            case "s":
                return format(str(self), format_spec)
            case "i":
                return format(self.id, format_spec)
            case "v":
                return format(self.vulnerabilities, format_spec)
        return ""

    @property
    def vulnerabilities(self) -> set["Vulnerability"]:
        res = set()
        vulns = self.root.find_all("vuln:Vulnerability")
        if not vulns:
            return res
        for vuln in vulns:
            if not Vulnerability.is_impacted(self, vuln):
                continue
            res.add(Vulnerability(self, vuln))

        return res


class Vulnerability:
    vuln_node: bs4.Tag
    product: Product
    cve: str
    title: str
    severity: str
    impact: str
    description: str
    itw: bool
    kb: str
    superseeded_kb: str
    characteristics: dict[str, str]

    def __init__(self, product: Product, node: bs4.BeautifulSoup):
        assert isinstance(product, Product)

        self.product = product
        self.vuln_node = node
        cve = self.vuln_node.find("vuln:CVE")
        assert cve
        self.cve = cve.text.strip()
        title = self.vuln_node.find("vuln:Title")
        assert title
        self.title = title.text.strip()
        self.characteristics = {}
        self.severity = self.__get_severity()
        self.impact = self.__get_impact()
        desc = node.find("vuln:Note", Title="Description", Type="Description")
        assert desc
        self.description = desc.text.strip()
        self.kb = self.__get_remediation_info("Description")
        self.superseeded_kb = self.__get_remediation_info("Supercedence")
        threats = self.vuln_node.find("vuln:Threat", Type="Exploit Status")
        assert threats
        self.itw = "Exploited:Yes" in threats.text.strip()

    @staticmethod
    def is_impacted(product: Product, node: bs4.BeautifulSoup) -> bool:
        pid = product.id
        return any(
            filter(
                lambda x: x.find("vuln:ProductID").text.strip() == pid,
                node.find_all("vuln:Threat", Type="Impact"),
            )
        )

    def url(self) -> str:
        return f"{KB_SEARCH_URL}?q={self.kb}"

    def __get_impact_or_severity(self, node, what: str) -> str:
        threats = self.vuln_node.find("vuln:Threats")
        if threats and isinstance(threats, bs4.Tag):
            for threat in threats.find_all("vuln:Threat", Type=what):
                _product_id = threat.find("vuln:ProductID").text.strip()
                if self.product.id == _product_id:
                    return threat.find("vuln:Description").text.strip()
        return f"<UNKNOWN_{what.upper()}>"

    def __get_impact(self) -> str:
        if not "Impact" in self.characteristics:
            self.characteristics["Impact"] = self.__get_impact_or_severity(
                self.vuln_node, "Impact"
            )
        return self.characteristics["Impact"]

    def __get_severity(self) -> str:
        if not "Severity" in self.characteristics:
            self.characteristics["Severity"] = self.__get_impact_or_severity(
                self.vuln_node, "Severity"
            )
        return self.characteristics["Severity"]

    def __get_remediation_info(self, what: str) -> str:
        if not what in self.characteristics:
            self.characteristics[what] = ""
            for r in self.vuln_node.find_all("vuln:Remediation", Type="Vendor Fix"):
                nod = r.find(f"vuln:{what}")
                val = nod.text if nod else ""
                if not val:
                    continue
                self.characteristics[what] = val
                break
        return self.characteristics[what]

    def __str__(self):
        return f"{self.cve} // KB{self.kb} // {self.title} // {self.severity} // {self.impact}"

    def __format__(self, format_spec) -> str:
        match format_spec:
            case "s":
                return format(str(self), format_spec)
            case "c":
                return format(self.cve, format_spec)
        return ""

    @staticmethod
    def find(
        soup: bs4.BeautifulSoup, cve_or_kb: Union[str, int]
    ) -> List["Vulnerability"]:
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
    def get_vuln_info_by_cve(
        soup: bs4.BeautifulSoup, cve: str
    ) -> List["Vulnerability"]:
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
    def get_vuln_info_by_kb(soup: bs4.BeautifulSoup, kb: int) -> list["Vulnerability"]:
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


def collect_products(root: bs4.BeautifulSoup) -> dict[str, Product]:
    node = root.find("prod:ProductTree")
    assert isinstance(node, bs4.Tag)
    return {
        product.text.strip(): Product(product)
        for product in node.find_all("prod:FullProductName")
    }


def get_patch_tuesday_data_soup(month: datetime.date) -> bs4.BeautifulSoup:
    fname = f"patch-tuesday-{month.strftime('%Y-%b')}.xml"
    fpath = pathlib.Path(tempfile.gettempdir()) / fname
    if not fpath.exists():
        url = f"{API_URL}/{month.strftime('%Y-%b')}"
        log.debug(f"Caching XML data from '{url}'")
        h = requests.get(url, headers={"User-Agent": DEFAULT_UA})
        if h.status_code != requests.codes.ok:
            raise RuntimeError(f"Unexpected code HTTP/{h.status_code}")
        fpath.write_text(h.text, encoding="utf-8")
    else:
        log.debug(f"Reading from cached file {fpath}")
    data = fpath.read_text(encoding="utf-8")
    return bs4.BeautifulSoup(data, features="xml")


if __name__ == "__main__":
    logging.basicConfig(
        level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )

    parser = argparse.ArgumentParser(description="Get the Patch Tuesday info")
    parser.add_argument(
        "-V",
        "--vulns",
        help="Specifiy the vuln(s) to detail (can be repeated)",
        default=[],
        action="append",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--products",
        help="Specifiy Product name(s) (can be repeated)",
        default=[],
        action="append",
        type=str,
    )
    parser.add_argument(
        "-m",
        "--months",
        help="Repeatable arguemnt to specify the Patch Tuesday month(s), ex: 2021-Jun",
        default=[],
        action="append",
        type=lambda x: datetime.datetime.strptime(x, "%Y-%b"),
        metavar="YYYY-ABBREVMONTH",
    )
    parser.add_argument(
        "-y",
        "--years",
        help="Specify a year - will be expended in months (can be repeated)",
        default=[],
        action="append",
        type=int,
    )
    parser.add_argument(
        "--list-products", help="List all products", action="store_true"
    )
    parser.add_argument("--brief", help="Display a summary", action="store_true")
    parser.add_argument("--debug", help="Set debug output", action="store_true")

    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)

    vulnerabilities: list[Vulnerability] = []
    today = datetime.date.today()
    console = Console()

    if args.list_products:
        soup = get_patch_tuesday_data_soup(today)
        products = collect_products(soup)
        log.info(
            os.linesep.join(
                [f"- {name} (ID:{product.id})" for name, product in products.items()]
            )
        )
        exit(0)

    if not len(args.products):
        log.info(f"Using default product as '{DEFAULT_PRODUCT}'")
        args.products = (DEFAULT_PRODUCT,)

    if args.years:
        args.months.extend(
            [
                args.months.append(datetime.date(year, month, 1))
                for year in args.years
                for month in range(1, 13)
            ]
        )

    if not len(args.months):
        log.debug(f"Using default month as '{today.strftime('%B %Y')}'")
        args.months = (today,)

    summary = not (args.brief or args.vulns)

    log.debug(
        f"Expanding KBs for {len(args.products)} products over {len(args.months)} months"
    )

    for month in args.months:
        log.info(f"For {month.strftime('%B %Y')}")
        soup = get_patch_tuesday_data_soup(month)
        products = collect_products(soup)
        log.info(f"Discovered {len(products)} products")

        if args.brief:
            tree = Tree(month.strftime("%B %Y"))
            for product_name in args.products:
                product = products[product_name]
                vulns = product.vulnerabilities
                branch = tree.add(product_name)

                subbranch = branch.add("Severity")
                subbranch.add(
                    f"{ len( list(filter(lambda x: x.severity == 'Critical', vulns)) ) } critical"
                )
                subbranch.add(
                    f"{ len( list(filter(lambda x: x.severity == 'Important', vulns)) ) } important"
                )

                subbranch = branch.add("Impact")
                subbranch.add(
                    f"{ len( list(filter(lambda x: x.impact == 'Remote Code Execution', vulns)) ) } RCE"
                )
                subbranch.add(
                    f"{ len( list(filter(lambda x: x.impact == 'Elevation of Privilege', vulns)) ) } EoP"
                )
                subbranch.add(
                    f"{ len( list(filter(lambda x: x.impact == 'Information Disclosure', vulns)) ) } EoP"
                )
            console.print(tree)
            continue

        if args.vulns:
            for product_name in args.products:
                product = products[product_name]
                vulns = product.vulnerabilities
                for vuln in vulns:
                    print(f"- Title: {vuln.title}")
                    print(f"- Description: {vuln.description}")
                    print(f"- Impact: {vuln.impact}")
                    print(f"- Severity: {vuln.severity}")
                    print(f"- KB: {vuln.kb}")
                    print(f"- CVE: {vuln.cve}")
                    print(f"- Link: {CVE_URL}/{vuln.cve}")
                    print(f"{'':-^95}")
            continue

        if summary:
            for product_name in args.products:
                product = products[product_name]
                vulns = product.vulnerabilities

                table = Table(
                    title=f"Summary: {len(vulns)} vuln(s) affecting {product_name} on {month.strftime('%B %Y')}"
                )
                table.add_column("CVE")
                table.add_column("Title")
                table.add_column("Impact")
                table.add_column("Severity")
                table.add_column("KB")

                max_title_length = 50
                for vuln in vulns:
                    title = (
                        vuln.title
                        if len(vuln.title) < max_title_length
                        else f"{vuln.title[:max_title_length]}..."
                    )
                    table.add_row(
                        vuln.cve,
                        title,
                        vuln.impact,
                        vuln.severity,
                        vuln.kb,
                    )

            console.print(table)
