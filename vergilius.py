import requests
import bs4
import argparse
import logging

BASE = "https://www.vergiliusproject.com"


def dump_structure(struct: str, arch: str, os: str, release: str) -> str:
    """_summary_

    Args:
        struct (str): _description_
        arch (str): _description_
        os (str): _description_
        release (str): _description_

    Returns:
        str: _description_
    """

    struct = struct.upper()

    url = f"{BASE}/kernels/{arch}/{os}/{release}/{struct}"
    h = requests.get(url, timeout=60)
    assert h.status_code == 200, f"Received HTTP {h.status_code}, expected 200"

    soup = bs4.BeautifulSoup(h.text, "html.parser")
    code = soup.find_all("div", id="copyblock")
    assert len(code) == 1
    return code[0].text


if __name__ == "__main__":
    conf: dict[str, dict[str, list[str]]] = {
        "x64": {
            "Windows XP | 2003": [
                "SP2",
            ],
            "Windows Vista | 2008": [
                "SP2",
                "SP1",
                "RTM",
            ],
            "Windows 7 | 2008R2": [
                "SP1",
                "RTM",
            ],
            "Windows 8 | 2012": [
                "RTM",
            ],
            "Windows 8.1 | 2012R2": [
                "Update 1",
                "RTM",
            ],
            "Windows 10 | 2016": [
                "2210 22H2 (May 2023 Update)",
                "2110 21H2 (November 2021 Update)",
                "2104 21H1 (May 2021 Update)",
                "2009 20H2 (October 2020 Update)",
                "2004 20H1 (May 2020 Update)",
                "1909 19H2 (November 2019 Update)",
                "1903 19H1 (May 2019 Update)",
                "1809 Redstone 5 (October Update)",
                "1803 Redstone 4 (Spring Creators Update)",
                "1709 Redstone 3 (Fall Creators Update)",
                "1703 Redstone 2 (Creators Update)",
                "1607 Redstone 1 (Anniversary Update)",
                "1511 Threshold 2",
                "1507 Threshold 1",
            ],
            "Windows 11": [
                "22H2 (2022 Update)",
                "21H2 (RTM)",
                "Insider Preview (Jun 2021)",
            ],
        },
        "x86": {
            "Windows XP": [
                "SP3",
            ],
            "Windows 2003": [
                "SP2",
            ],
            "Windows Vista | 2008": [
                "SP2",
                "SP1",
                "RTM",
            ],
            "Windows 7": [
                "SP1",
                "RTM",
            ],
            "Windows 8": [
                "RTM",
            ],
            "Windows 8.1": [
                "Update 1",
                "RTM",
            ],
            "Windows 10": [
                "Windows 10 2210 22H2 (May 2023 Update)",
                "Windows 10 2110 21H2 (November 2021 Update)",
                "Windows 10 2104 21H1 (May 2021 Update)",
                "Windows 10 2009 20H2 (October 2020 Update)",
                "Windows 10 2004 20H1 (May 2020 Update)",
                "Windows 10 1909 19H2 (November 2019 Update)",
                "Windows 10 1903 19H1 (May 2019 Update)",
                "Windows 10 1809 Redstone 5 (October Update)",
                "Windows 10 1803 Redstone 4 (Spring Creators Update)",
                "Windows 10 1709 Redstone 3 (Fall Creators Update)",
                "Windows 10 1703 Redstone 2 (Creators Update)",
                "Windows 10 1607 Redstone 1 (Anniversary Update)",
                "Windows 10 1511 Threshold 2",
                "Windows 10 1507 Threshold 1",
            ],
        },
    }

    parser = argparse.ArgumentParser("vergilius.py")
    parser.add_argument("--arch", type=str, default="x64")
    parser.add_argument("--os", type=str, default="Windows 11")
    parser.add_argument("--release", type=str, default="22H2 (2022 Update)")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("struct", type=lambda x: x.upper())
    args = parser.parse_args()

    assert args.arch in conf, f"Invalid option {args.arch}"
    assert args.os in conf[args.arch], f"Invalid option {args.os} for {args.arch}"
    assert (
        args.release in conf[args.arch][args.os]
    ), f"Invalid option {args.release} for {args.arch}/{args.os}"

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    logging.debug(
        f"Looking for {args.struct=}, {args.arch=}, {args.os=}, {args.release=}"
    )
    _code = dump_structure(args.struct, args.arch, args.os, args.release)
    print(_code)
