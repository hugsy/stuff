import requests
import bs4
import argparse
import datetime
import re


URL = "https://api.msrc.microsoft.com/cvrf/v2.0/document"
DEFAULT_PRODUCT = "Windows 10 Version 21H1 for x64-based Systems"
# DEFAULT_PRODUCT = "Windows 10 Version 20H2 for x64-based Systems"
# DEFAULT_PRODUCT = "Windows 10 Version 2004 for x64-based Systems"
# DEFAULT_PRODUCT = "Windows 10 Version 1909 for x64-based Systems"
# DEFAULT_PRODUCT = "Windows 10 Version 1809 for x64-based Systems"



class Vulnerability:
    product_id: int
    cve: str
    title: str
    severity: str
    impact: str
    description: str
    itw: bool
    kb: int

    def __init__(self, product_id, node):
        self.product_id = product_id
        self.cve = node.find("vuln:cve").text.strip()
        self.title = node.find("vuln:title").text.strip()
        self.severity = self.__get_impact_or_severity(node, "Severity")
        self.impact =  self.__get_impact_or_severity(node, "Impact")
        self.description = node.find("vuln:note", title="Description", type="Description").text.strip()
        self.kb = self.__get_kb(node)
        self.itw = "Exploited:Yes" in node.find("vuln:threat", type="Exploit Status").text.strip()
        return


    def url(self):
        return f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q={self.kb}"


    def __get_impact_or_severity(self, node, what):
        threads = node.find("vuln:threats")
        for t in threads.find_all("vuln:threat", type=what):
            __product_id = int(t.find("vuln:productid").text.strip())
            if __product_id == self.product_id:
                return t.find("vuln:description").text.strip()
        raise KeyError(f"Impact/Severity not found for {self.cve}")


    def __get_kb(self, node):
        for r in node.find_all("vuln:remediation"):
            __product_id = int(r.find("vuln:productid").text.strip())
            if __product_id == self.product_id:
                return r.find("vuln:description").text.strip()
        raise KeyError(f"KB not found for {self.cve}")


    def __str__(self):
        return f"{self.cve} // {self.title} // {self.severity} // {self.impact}"


def get_product_name_from_id(soup, _id):
    """Get a product name from a product id"""
    product = soup.find("prod:fullproductname", productid=_id)
    return product.text.strip()


def get_product_id_from_name(soup, pattern):
    """Retrieve the Product ID from a name."""
    for product in  soup.find_all("prod:fullproductname"):
        _name = product.text.strip()
        if pattern.match(_name):
            return int(product["productid"])
    raise KeyError("Product not found")


def get_vulns_for_product(soup, product=DEFAULT_PRODUCT):
    """Get a list of vuln object nodes for a specific product"""
    def is_affected(productid, vuln):
        for affected in vuln.find("vuln:status", type="Known Affected").find_all("vuln:productid"):
            _id = int(affected.text.strip())
            if _id == productid:
                return True
        return False

    vulnerabilities : list[Vulnerability] = []
    pattern = re.compile(product, re.IGNORECASE)
    productid = get_product_id_from_name(soup, pattern)
    for vuln in soup.find_all("vuln:vulnerability"):
        if not is_affected(productid, vuln):
            continue
        vulnerability = Vulnerability(productid, vuln)
        vulnerabilities.append(vulnerability)
    return vulnerabilities


def print_products(soup):
    """Print all products"""
    for product in  soup.find_all("prod:fullproductname"):
        print(f"- {product.text.strip()}")
    return


def get_patch_tuesday_data_soup():
    url = f"{URL}/{args.month.strftime('%Y-%b')}"
    h = requests.get(url)
    if h.status_code != requests.codes.ok:
        raise RuntimeError(f"Unexpected code HTTP/{h.status_code}")
    return bs4.BeautifulSoup(h.text, features="html.parser")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get the Patch Tuesday info")
    parser.add_argument("-p", "--product", help="Specifiy Product name", default=DEFAULT_PRODUCT)
    parser.add_argument("-m", "--month", help="Specifiy the Patch Tuesday month", default=datetime.date.today(),
                        type=lambda x: datetime.datetime.strptime(x, "%Y-%b"), metavar="YYYY-ABBREVMONTH")
    parser.add_argument("--list-products", help="List all products", action="store_true")
    parser.add_argument("--summary", help="Display a summary", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", dest="verbose",
                        help="Increments verbosity")
    args = parser.parse_args()

    soup = get_patch_tuesday_data_soup()

    if args.list_products:
        print_products(soup)
        exit(0)


    vulns = get_vulns_for_product(soup, args.product)
    if args.summary:
        print(f"For {args.month.strftime('%B %Y')}:")
        print(f"* {len(vulns)} CVE{'s' if len(vulns)>1 else ''} for '{args.product}' including:")
        print(f"  - { len( list(filter(lambda x: x.severity == 'Critical', vulns)) ) } critical")
        print(f"  - { len( list(filter(lambda x: x.severity == 'Important', vulns)) ) } important")
        print("* with:")
        print(f"  - { len( list(filter(lambda x: x.impact == 'Remote Code Execution', vulns)) ) } are RCE")
        print(f"  - { len( list(filter(lambda x: x.impact == 'Elevation of Privilege', vulns)) ) } are EoP")
        print(f"  - { len( list(filter(lambda x: x.impact == 'Information Disclosure', vulns)) ) } are EoP")
        exit(0)


    for vuln in vulns:
        print(f"- {vuln}")


