#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# -*- mode: python-mode -*-
#
#


"""
unmap is a script that helps to manipulate nmap XML output, allowing (among other
things) to dump to transform the output into a specific plugin (stdout -> default,
file, odt, html).

It has filtering features to accurately select your targets, which can be defined
either by black listing or white listing, based on IP address, port number, or nmap
ServiceName.

Examples :
1. basic (stdout output)
% ./unmap.py < tests/nmap-test.xml
             IP   Port Service
    172.16.0.10     22 ssh (Cisco SSH protocol 1.99)
    172.16.0.10     23 telnet (Cisco router)
    172.16.0.10    443 tcpwrapped ()
...

2. OpenDocument output $HOME/toto.odt using verbose mode
% ./unmap.py --verbose --type=odt tests/nmap-test.xml --output=$PENTEST/toto.odt
[*] 26/01/11 14:39:34 : Service name filter:
[*] 26/01/11 14:39:34 : New host : IPv4:172.16.0.1, MAC: ()
...
[*] 26/01/11 14:39:34 : Writing ODT file to './toto.odt'
[*] 26/01/11 14:39:34 : MD5: ffa9ce2e562c1e63b16ba858682d3f49

3. blacklist filter on port 445 and group WEB
./unmap.py --verbose --filter-port=445 --group=WEB tests/nmap-test.xml
...
[*] 26/01/11 14:46:37 : New port : 443/tcp (Microsoft IIS webserver)
[*] 26/01/11 14:46:37 : Ignoring port 445/tcp
             IP   Port Service
    172.16.0.10     22 ssh (Cisco SSH protocol 1.99)
    172.16.0.10     23 telnet (Cisco router)
...

4. whitelist filter for IP addresses 172.16.0.51 and 172.16.0.52
% ./unmap.py -v --show-only --filter-ip=172.16.0.51 --filter-ip=172.16.0.52 tests/nmap-test.xml
[*] 26/01/11 14:49:57 : Ignoring host 172.16.0.10
[*] 26/01/11 14:49:57 : Ignoring host 172.16.0.50
[*] 26/01/11 14:49:57 : New host : IPv4:172.16.0.51, MAC: ()
[*] 26/01/11 14:49:57 : New port : 80/tcp (Microsoft IIS webserver)
...
[*] 26/01/11 14:49:57 : New host : IPv4:172.16.0.52, MAC: ()
[*] 26/01/11 14:49:57 : New port : 25/tcp (Microsoft ESMTP)
[*] 26/01/11 14:49:57 : New port : 80/tcp (Microsoft IIS webserver)
...


UNmap can also be used from an interactive Python client.
% ipython
>>> from unmap import UNMap
>>> nmap = UNmap("tests/nmap-test.xml")
>>> ["%s has %d open ports"%(x.ip, str(len(x.ports)) for x in nmap.hosts]
--> ['192.168.56.101 has 3 open ports', '192.168.56.73 has 4 open ports']

Making it very easy to bind with Scapy or else.

"""

#
# import built-in packages
#

from __future__ import with_statement  # pour python 2.5 et 2.6
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError
from sys import argv, version_info, stdout
from argparse import ArgumentParser
from os import access, R_OK
from logging import Formatter, StreamHandler, DEBUG, INFO, getLogger
from datetime import datetime
from hashlib import md5
from os import path
from sqlite3 import connect as pysql_connect
from sqlite3 import Error as SQLError, DatabaseError, ProgrammingError


mj, mn = version_info[0:2]
if mj < 2 or mn < 6:
    raise ImportError ("Python version must be at least 2.6+")


try:
    import relatorio.templates.opendocument
except ImportError :
    pass

try:
    import docxtpl
    import docx.shared
    import docx.enum.text
except ImportError :
    pass


__author__     =  "@_hugsy_"
__version__    =  "0.4"
__licence__    =  "WTFPL v.2"
__file__       =  "unmap.py"
__desc__       =  """ Convert nmap xml output to human exploitable data.
pydoc ./unmap.py for man page"""


# Global variables
# Logging and verbosity
verbose = 0
logger = None
handler = StreamHandler()
handler.setLevel(DEBUG)
handler.setFormatter(Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                               datefmt="%d/%m/%Y %H:%M:%S"))

# Group based on Nmap ServiceName
GROUPS = {
    "CL"         : ["ssh", "telnet", "rsh"],
    "FTP"        : ["ftp", "ftps"],
    "MSSQL"      : ["ms-sql", "ms-sql-s", "ms-sql-m"],
    "ORACLE"     : ["oracle-mts", "oracle-tns"],
    "MYSQL"      : ["mysql", "mysql-proxy"],
    "PGSQL"      : ["postgres"],
    "VNC"        : ["vnc", "vnc-http"],
    "TSE"        : ["ms-term-serv", "microsoft-rdp"],
    "NS"         : ["domain", "wins"],
    "ANNUAIRE"   : ["ldap", "ldaps", "nis"],
    "MAIL"       : ["smtp", "pop3", "pop3s", "lotus-notes", "imap", "imaps"],
    "WEB"        : ["http", "https"],
    "PRINTER"    : ["ipp", "printer", "swat"],
    "RPC"        : ["rpcbind", "msrpc"],
    "DAMEWARE"   : ["landesk", "damewaremr"],
    }

GROUPS["SQL"] = []
for i in ["MSSQL", "ORACLE", "MYSQL", "PGSQL"]: GROUPS["SQL"].extend(GROUPS[i])

GROUPS["RACCESS"]  = []
for i in ["FTP", "CL",]: GROUPS["RACCESS"].extend(GROUPS[i])

GROUPS["RACCESSG"]  = []
for i in ["VNC", "TSE", "DAMEWARE"]: GROUPS["RACCESSG"].extend(GROUPS[i])


class UNmapPlugin:
    """
    Generic template UNmap plugin
    """

    def __init__(self, nmap_results, **kwargs):
        """
        Class definition
        """
        self.__name__ = self.__class__.__name__
        self.logger = getLogger(self.__name__)
        self.logger.addHandler(handler)
        self.logger.setLevel(INFO)
        self.nmap_results = nmap_results

        if kwargs.has_key("verbose") and kwargs["verbose"] > 0:
            self.verbose = kwargs["verbose"]
        else:
            self.verbose = 0

        if self.verbose:
            self.logger.info("Using plugin %s" % self.__name__)

        if kwargs.has_key("filename") and kwargs["filename"] not in ("", None):
            self.filename = kwargs["filename"]
        else:
            self.filename = "output-%s" % datetime.today().strftime("%Y-%m-%d")


    def export(self):
        """
        Export function, generates output
        """
        pass


    def add_suffix(self, suffix):
        """
        Add suffix to filename
        """
        if not self.filename.endswith(suffix):
            self.filename += suffix



class HtmlUNmapPlugin (UNmapPlugin):
    """
    UNmap plugin to generate html file
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)
        self.add_suffix(".html")

        if self.verbose :
            self.logger.info("HTML will be written in '%s'" % self.filename)

        if 'add_thumb' in kwargs.keys() and type(kwargs['add_thumb']) is bool:
            self.add_thumb = kwargs['add_thumb']
            if self.verbose :
                self.logger.info("HTTP thumbnails will be generated")
        else:
            self.add_thumb = False



    def export(self):
        page = self.header()
        page += self.summary()
        page += self.hosts_detail()
        page += self.ports_detail()
        page += self.footer()

        with open(self.filename, "w") as f :
            f.write(page)
            f.flush()


    def header(self):
        return """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html><head><title>%s : HTML export</title></head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<link rel="stylesheet" type="text/css" href="style.css" media="screen">
<script type="text/javascript">
  <!--
  function HideAllTables(){var tables = document.getElementsByTagName("table");for(var x=0; x < tables.length; ++x){if(tables[x].rows.length > 2 && tables[x].rows[0].cells[0].innerHTML.charAt(0) != '+'){tables[x].rows[0].cells[0].innerHTML = '+ ' + tables[x].rows[0].cells[0].innerHTML;}if(tables[x].rows.length < 3 || tables[x].id == 'hide'){for(var y=1; y < tables[x].rows.length; ++y){tables[x].rows[y].style.display = 'none';}}}document.getElementById("topframe").style.display = '';}

  window.onload=function(){HideAllTables();wordWrap();}

  function ShowOrHideTable(Node){var theTable = Node.parentNode.parentNode.parentNode;if(theTable.rows.length <= 2)return; var ShowOrHide = theTable.rows[1].style.display == 'none';for(var x=1; x < theTable.rows.length; ++x) { if(ShowOrHide){theTable.rows[x].style.display = '';}else{theTable.rows[x].style.display = 'none';}}var innerHTML;if(Node.innerHTML.charAt(0) == '+' ||Node.innerHTML.charAt(0) == '-'){innerHTML = Node.innerHTML.substring(2,Node.innerHTML.length);}else{innerHTML = Node.innerHTML;}  if(ShowOrHide){Node.innerHTML = '- ' + innerHTML;}else{Node.innerHTML = '+ ' + innerHTML;}}
  function wordWrap(){var tds = document.getElementsByTagName("td");for(var x=0; x < tds.length; ++x){if(tds[x].id == 'raw'){var z = 0; if(tds[x].innerHTML.length > 30){var buf = ""; while(z+8 < tds[x].innerHTML.length){buf = buf + tds[x].innerHTML.substr(z,8) + "&#8203;";z = z + 8;}if(z < tds[x].innerHTML.length){buf = buf + tds[x].innerHTML.substr(z,tds[x].innerHTML.length-z);}tds[x].innerHTML = buf;}}}}
    -->
</script>
<style type="text/css" media="screen">
  div.mainframe
  { background-color: #FFFFFF; border: 2px #F6F9FB solid; border-collapse: collapse; padding-top: 7px; padding-left: 3px; padding-right: 5px; margin-top: 50px; margin-left: 64px; margin-right: 64px; }
  div.childframe
  { background-color: #fafafa; margin-bottom: 7px; }
  td.tableheader
  { border-bottom: 1px solid #000000; background-color: #93B6F7; text-align: left; font-family: Verdana; font-weight: bold; font-size: 11px; padding-left: 3px; }
  td.subtableheader
  { border-bottom: 1px solid #000000; background-color: #D0DFFB; text-align: left; font-family: Verdana; font-weight: bold; font-size: 11px; padding-left: 3px; }
  td
  { border-bottom: 1px dotted #6699CC; font-family: Verdana, sans-serif, Arial; font-weight: normal; font-size: 11px; color: #404040; text-align: left; padding-left: 3px; }
  td.subchildframe
  { border-bottom: none; padding-left: 4px; padding-right: 5px; padding-top: 5px; }
  td.right
  { border-left: 1px dotted #6699CC; }
  td.column
  { background-color: #ECEFFD; }
  table
  { border: 1px #000000 solid; background-color: white; border-collapse: collapse; width: 100%%; }
  div.header
  { border: 1px solid #000000; border-collapse: collapse; background-color: #FFFFFF; font-family: Verdana, sans-serif, Arial; font-weight: normal; font-size: 10px; color: #404040; margin-bottom: 7px; padding: 3px; }
  div.subheader
  {  border: 1px solid #000000;border-collapse: collapse;background-color: #061E4A;font-family: Verdana, sans-serif, Arial;  font-weight: bold;font-size: 12px;color: #FFFFFF;margin-bottom: 7px;padding: 3px; }
  div.footer
  { margin-top: 5px; margin-left: 72px; font-family: Verdana, sans-serif, Arial; font-weight: normal; font-size: 10px; color: #404040; }
  ul
  { padding-left: 10px; margin-left: 10px; padding-top: 1px; margin-top: 1px; padding-bottom: 1px; margin-bottom: 1px; list-style-type: circle; }
  div#chart
  { float: left; position: relative; background-color: #D0DFFB; border: 1px solid #000000; }
</style>
</head>
<body>
<div id="topframe" style="display:none">
<div class="mainframe" id="top">
<div class="subheader">%s: HTML Export (%s)</div>
""" % (self.filename, __file__, datetime.today().strftime("%d/%m/%Y at %H:%M:%S"))


    def footer(self):
        return """
<div class="footer">Automatically generated by {0}</div>
</div>
</body>
</html>
""".format(__file__)


    def summary(self):
        return """
<div class="childframe">
<table cellspacing="0">
<tr><td colspan="2" class="tableheader" onclick="ShowOrHideTable(this);">General information</td></tr>
<tr><td width="70%">Number of hosts:</td><td class="right">{0}</td></tr>
<tr><td>Number of open ports:</td><td class="right">{1}</td></tr>
</table>
</div>
""".format(len(self.nmap_results.hosts), sum([len(h.ports) for h in self.nmap_results.hosts]))


    def hosts_detail(self):
        buf = """
<div class="childframe">
<table cellspacing="0" id="hide">
<tr>
<td colspan="5" class="tableheader" onclick="ShowOrHideTable(this);">
Hosts list:
</td>
</tr>

<tr>
<td class="column right">IP Address</td>
<td class="column right">MAC</td>
<td class="column right">Operating System</td>
</tr>
"""
        if len(self.nmap_results.hosts) > 0:
            for h in self.nmap_results.hosts:
                buf += """
<tr>
<td><a href="#ip-{0}">{0}</a></td>
<td>{1} {2}</td>
<td>{3}</td>
</tr>\n
""".format(h.ip, h.mac, '('+h.vendor+')' if len(h.mac) else "", h.os)

        buf += """ </table></div>"""

        return buf


    def ports_detail(self):
        buf = """
<div class="childframe">
<table cellspacing="0" id="hide">
<tr>
<td colspan="5" class="tableheader" onclick="ShowOrHideTable(this);">
Ports list:
</td>
</tr>
"""

        img_path = "./img/"
        urls = []
        try:
            from browser_screenshot import screenshot_list
        except:
            self.add_thumb = False

        for h in self.nmap_results.hosts :
            if len(h.ports)==0:
                continue

            buf += """
<tr>
<td class="subchildframe">
<table cellspacing="0">
<tbody><tr><td colspan="4" class="subtableheader" id="ip-{0}">Detail: {0}</td></tr>

<tr>
<td class="column right">Protocol</td>
<td class="column right">Service</td>
<td class="column right">Banner</td>
""".format(h.ip)

            if self.add_thumb:
                buf += """<td class="column right">Snapshot</td>"""

            buf += "</tr>"

            for p in h.ports:
                banner = " ".join([p.product, p.version, p.extrainfo]).strip()
                buf += "<tr>"
                buf += "<td>{0}/{1}</td>".format(p.port, p.protocol)
                buf += "<td>{0}</td>".format(p.service)
                buf += "<td>{0}</td>".format(banner)

                if not self.add_thumb:
                    buf += "</tr>"
                    continue

                if p.port not in (80,443):  # todo: add other condition (banner, etc.)
                    buf += "<td></td>"
                else:
                    if p.port==443: proto = 'https'
                    else: proto = 'http'
                    url = "%(proto)s://%(ip)s/" % {'proto': proto, 'ip': h.ip}
                    urls.append(url)

                    img = "%(path)s/%(prefix)s_%(name)s.png"
                    img%= {'path':img_path,'prefix':'thumb','name':url.replace('/','')}

                    buf += """<td><img src="%s" width="200px" height="200px"></td>""" % img
                buf += "</tr>"

            buf += """ </table></td></tr>\n"""
            buf += """ <tr><td colspan="3"><center><a href="#top">Top</a></center></td></tr>"""

        if self.add_thumb and img_path is not None:
            self.logger.info("Starting thumbnails generation... Can take some time")
            screenshot_list(urls, path=img_path)

        buf += """ </table></div>\n"""


        return buf


class SqliteUNmapPlugin (UNmapPlugin):
    """
    UNmap plugin for generating an SQLite database. SQLite version used is 3.x
    Hence, python-sqlite3 *must* be installed for this plugin.
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)
        self.add_suffix(".sqlite")

        if self.verbose :
            self.logger.info("SQLite3 database will be written in '%s'" % self.filename)

        if kwargs.has_key("table_name"):
            self.table_name = kwargs["table_name"]
        else :
            self.table_name = "hosts"



    def export(self):
        """
        export function will generate the sqlite3 database
        """

        global verbose

        def execute_sql (query, fd):
            try:
                fd.execute(query)

            except DatabaseError, de:
                print ("Database Error : %s" % de)
            except ProgrammingError, pe:
                print ("Programming Error : %s" % pe)
            except SQLError, e:
                print ("SQL Generic Error: %s" % e)
            except Exception, e:
                print ("Exception: %s" % e)


        with pysql_connect(self.filename) as sql_ctx:
            req = "CREATE TABLE IF NOT EXISTS {0}(".format(self.table_name)
            req += "ip VARCHAR, "
            req += "port INTEGER, "
            req += "protocol VARCHAR, "
            req += "banner VARCHAR, "
            req += "os VARCHAR)"

            execute_sql(req, sql_ctx)
            idx = 0

            if self.verbose:
                self.logger.info("Table %s created in '%s'" % (self.table_name, self.filename))

            for h in self.nmap_results.hosts :
                for p in h.ports:
                    banner = " ".join([p.product, p.version, p.extrainfo]).strip()
                    req = "INSERT INTO {0} VALUES ('{1}',{2},'{3}','{4}','{5}')".format(self.table_name,
                                                                                        h.ip,
                                                                                        int(p.port),
                                                                                        p.protocol,
                                                                                        banner,
                                                                                        h.os)
                    execute_sql(req, sql_ctx)
                    idx += 1

            if self.verbose:
                self.logger.info("Table %s filled with %d entries" % (self.table_name, idx))


class FileUNmapPlugin(UNmapPlugin):
    """
    UNmap plugin for writing output in a file
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)
        self.add_suffix(".txt")

        if self.verbose :
            self.logger.info("Text file will be written in '%s'" % self.filename)

        if access(self.filename, R_OK):
            self.logger.info("'%s' already exists, will be overwritten" % self.filename)


    def export(self):
        global verbose

        with open(self.filename, 'w') as fd:
            fd.write('%15s %11s %s\n' % ("IP", "Port", "Service"))

            for h in self.nmap_results.hosts:
                for p in h.ports:
                    banner = '(' + " ".join([p.product, p.version, p.extrainfo]) + ')'
                    fd.write('%15s %6s/%-5s %s %s\n' % (h.ip,
                                                        p.port,
                                                        p.protocol,
                                                        p.service,
                                                        banner))
                fd.flush()


class TextUNmapPlugin(UNmapPlugin):
    """
    Basic UNmap plugin for generating output in stdout
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)

        if self.verbose :
            self.logger.info("Output will be written in stdout")

        del self.filename


    def export(self):
        from sys import stdout

        stdout.write('%18s %10s   %s\n' % ("IP", "Port", "Service"))

        for h in self.nmap_results.hosts:
            for p in h.ports:
                banner = '(' + " ".join([p.product, p.version, p.extrainfo]).strip() + ')'
                stdout.write('%18s %6s/%-5s %s %s\n' % (h.ip,
                                                        p.port,
                                                        p.protocol,
                                                        p.service,
                                                        banner))
            stdout.flush()


class CsvUNmapPlugin(UNmapPlugin):
    """
    UNmap plugin for exporting unmap results in CSV format
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)

        if self.verbose :
            self.logger.info("Output will be written in stdout")

        del self.filename
        return


    def export(self):
        fmt = '"{}" ; "{}" ; "{}"\n'

        line =  fmt.format("IP", "Port", "Service")
        stdout.write(line)

        for h in self.nmap_results.hosts:
            for p in h.ports:
                stdout.write(fmt.format(h.ip, p.port, p.banner))
            stdout.flush()

        return


class OdtUNmapPlugin(UNmapPlugin):
    """
    UNmap plugin for generating OpenDocument output.
    This requires relatorio module (http://relatorio.openhex.org/)
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)

        if 'relatorio' not in sys.modules.keys():
            print ("[-] Missing python-relatorio package")
            exit(1)

        if not kwargs.has_key("template"):
            print ("[-] Your must provide a template ODT file for this plugin.")
            exit(1)

        self.add_suffix(".odt")

        if self.verbose:
            self.logger.info("Writing ODT file to '%s'" % self.filename)

        self.template = kwargs["template"]
        self.content = []
        self.summary = []


    def sort_data(self):
        found = False

        for h in self.nmap_results.hosts :
            for p in h.ports:
                found = False

                netloc = "%s:%d/%s" % (h.ip, p.port, p.protocol)
                srv = p.service if len(p.service.strip()) else "unknown"
                nfo = '('+" ".join([p.product, p.version, p.extrainfo]).strip()+')' if " ".join([p.product, p.version, p.extrainfo]).strip() else "(no banner)"
                extrainfo = srv + " " + nfo

                for entry in self.content :
                    if entry['type'] == extrainfo and netloc not in entry['ip_addr'] :
                        entry['ip_addr'].append([netloc])
                        found = True

                if not found :
                    self.content.append({"type" : extrainfo, "ip_addr" : [netloc]})

        synthese = []

        for elt in self.content:
            nom = elt['type']
            nb = len(elt['ip_addr'])
            synthese.append({ "name": nom, "count": nb })

        total = sum( [x['count'] for x in synthese] )
        tab = dict(lines=self.content, summary=synthese, total=total)

        return tab


    def export(self):
        tab = self.sort_data()

        try :
            relatorio =  sys.modules['relatorio']
            template = relatorio.templates.opendocument.Template(source=None, filepath=self.template)
            data = template.generate(o=tab).render().getvalue()

            if len(tab['lines']) > 0:
                with open(self.filename,'w') as fd:
                    fd.write(data)
                    if self.verbose:
                        self.logger.info ("MD5: %s" % md5(data).hexdigest())

        except Exception, e:
            self.logger.error("export failed : %s" % e)



class DocxOdtUNmapPlugin(UNmapPlugin):
    """
    Docx plugin for generating MS Office DOCX document.
    This requires docxtpl module (https://pypi.python.org/pypi/docxtpl)
    """

    def __init__(self, nmap_results, **kwargs):
        UNmapPlugin.__init__(self, nmap_results, **kwargs)

        if 'docxtpl' not in sys.modules.keys():
            print ("[-] Missing docxtpl package")
            exit(1)

        if not kwargs.has_key("template"):
            print ("[-] Your must provide a template DOCX file for this plugin.")
            exit(1)

        self.add_suffix(".docx")

        if self.verbose:
            self.logger.info("Writing docx file to '%s'" % self.filename)

        self.template = kwargs["template"]
        self.content = []
        self.summary = []


    def export(self):
        ctx = {"tcp": self.nmap_results.hosts , "udp": []}

        try :
            docxtpl =  sys.modules["docxtpl"]
            docx = docxtpl.DocxTemplate(self.template)
            docx.render(ctx)
            self.docx.save(self.filename)

        except Exception as e:
            self.logger.error("export failed : %s" % e)


class Port :
    """
    Port object definition
    """
    def __init__ (self, *args, **kwargs):
        for i in ["port", "protocol", "service", "product", "version", "extrainfo"]:
            setattr(self, i, kwargs.get(i, ''))

    @property
    def banner(self):
        return self.service + "(" +" ".join([self.product, self.version, self.extrainfo]).strip() + ")"

class Host :
    """
    Host object definition
    """
    def __init__(self, *args, **kwargs):
        self.ports = []
        self.banner = []

        for i in ["ip", "mac", "vendor", "os"]:
            setattr(self, i, kwargs.get(i, ''))


    def get_or_create_port(self, portnum, protocol):
        port = None

        for p in self.ports:
            if p.port==portnum and p.protocol==protocol:
                return p

        port = Port(port=portnum, protocol=protocol)
        self.ports.append(port)
        return port


class UNmap :
    """
    Parse XML file into an object that will be used by export plugins
    Can also be called from (i)Python interactive client :

    >>> nmap = UNmap("~/tmp/nmap-test.xml")
    >>> [h.ip for h in nmap.hosts]
    ['192.168.56.101', '192.168.56.73']

    """


    def __init__(self, filelist, filter_ips=[], filter_ports=[], filter_services=[], show_only=False):

        self.__name__ = self.__class__.__name__
        self.logger = getLogger(self.__name__)
        self.logger.addHandler(handler)
        self.hosts = []
        self.filter_ips = filter_ips
        self.filter_ports = filter_ports
        self.filter_services = filter_services
        self.show_only = show_only
        if isinstance(filelist, str):
            filelist = [filelist,]
        elif not isinstance(filelist, list):
            raise AttributeError("Invalid type for filelist")
        self.msf_path = ''


        if verbose:
            self.logger.info("Starting parsing")

        for fic in filelist:

            et = self.parse_xml(fic)
            if et == -1:
                continue

            for h in et.findall("host"):
                ip, mac, vendor = None, None, None

                # addresses gathering
                for address in h.findall("address"):
                    if address.attrib.has_key("addrtype") :
                        if address.attrib["addrtype"] == "ipv4" :
                            ip = address.attrib["addr"]
                        elif address.attrib["addrtype"] == "mac" :
                            mac = address.attrib["addr"]
                            vendor = address.attrib["vendor"]

                host = self.get_or_create_host_by_ip(ip)
                if host.mac is None and mac is not None:
                    host.mac = mac
                if host.vendor is None and vendor is not None:
                    host.vendor = vendor

                if self.show_only :
                    if len(self.filter_ips):
                        filter_rule = host.ip not in self.filter_ips
                    else :
                        filter_rule = False

                else :
                    filter_rule = host.ip in self.filter_ips

                if filter_rule :
                    if verbose:
                        self.logger.info("Ignoring host %s" % host.ip)
                    continue


                if verbose :
                    self.logger.info("New host : IPv4:%s, MAC:%s (%s)" % (host.ip,
                                                              host.mac,
                                                              host.vendor))

                # ports discovery
                for p in h.findall("ports/port"):
                    state = p.find("state")
                    if state.attrib["state"] != "open":
                        continue

                    portnum = int(p.attrib["portid"])
                    protocol = p.attrib["protocol"]
                    if self.show_only :
                        if len(self.filter_ports):
                            filter_rule = portnum not in self.filter_ports
                        else :
                            filter_rule = False

                    else :
                        filter_rule = portnum in self.filter_ports

                    if filter_rule :
                        if verbose:
                            self.logger.info("Ignoring port %d/%s" % (port.port, port.protocol))
                        continue


                    port = host.get_or_create_port(portnum, protocol)

                    svc = p.find("service")

                    if svc is not None:
                        if svc.attrib.has_key("name"):
                            port.service = svc.attrib["name"]
                        if svc.attrib.has_key("product"):
                            port.product = svc.attrib["product"]
                        if svc.attrib.has_key("version"):
                            port.version = svc.attrib["version"]
                        if svc.attrib.has_key("extrainfo"):
                            port.version = svc.attrib["extrainfo"]

                    if self.show_only :
                        if len(self.filter_services):
                            filter_rule = port.service not in self.filter_services
                        else :
                            filter_rule = False
                    else :
                        filter_rule = port.service in self.filter_services

                    if filter_rule :
                        if verbose:
                            self.logger.info("Ignoring service %s" % (port.service,))
                        continue

                    if verbose:
                        self.logger.info("New port : %d/%s (%s)" % (port.port,
                                                                    port.protocol,
                                                                    port.product))


                # OS matching
                os = h.find("os/osmatch")

                if os is None:
                    accuracy = -1
                    for elt in h.findall("os/osclass"):

                        if int(elt.attrib["accuracy"]) > accuracy:
                            accuracy = elt.attrib["accuracy"]
                            if not elt.attrib.has_key("vendor"):
                                elt.attrib["vendor"] = ""
                            if not elt.attrib.has_key("osfamily"):
                                elt.attrib["osfamily"] = ""
                            if not elt.attrib.has_key("osgen"):
                                elt.attrib["osgen"] = ""

                            os = " ".join([elt.attrib["vendor"],
                                           elt.attrib["osfamily"],
                                           elt.attrib["osgen"]])

                else :
                    host.os = os.attrib["name"]

                if verbose :
                    self.logger.info("New host OS: %s" % host.os)


    def parse_xml(self, f):
        """
        Parse the Nmap XML output and return a pointer to the lxml object or -1 if unsuccessful
        """
        if f == "" or not access (f, R_OK):
            self.logger.error ("Could not read file %s, skipping" % fic)
            return -1

        et = None
        while et is None :
            try :
                et = ElementTree.parse(f)

            except ExpatError, xpe:
                self.logger.error("XML Parse Error %s" % xpe)
                SEEK_END = 2
                with open(fic, "r") as f:
                    f.seek(-(len("</nmaprun>")+2), SEEK_END)
                    content = f.read()

                # most of the time, broken xml file is generated because nmap was
                # interrupted, resulting in a missing final '</nmaprun>' flag
                if "</nmaprun>" not in content:
                    self.logger.info("XML '%s' seems broken (nmap not finished ?)"%fic)
                    if raw_input("Would you like to try to repair '%s' [y/N]? "%fic) in ("y","Y"):
                        with open(fic, "a") as f:
                            f.write("</nmaprun>\n")
                        et = None
                    else :
                        et = -1

            except Exception, e:
                self.logger.error("Exception raised: %s" % e)
                et = -1

        return et


    def get_or_create_host_by_ip(self, ip):
        """
        Returns the host object matching an IP address.
        """
        for host in self.hosts:
            if host.ip == ip:
                return host

        h = Host(ip=ip)
        self.hosts.append(h)

        return h


    def find_ip_by_port(self, port_num):
        """
        Returns an generator of host IP addresses which have matching port number.
        """
        for host in self.hosts:
            for p in host.ports:
                if port_num == p.port:
                    yield host.ip


def proceed(nmap_results, plugin, **kwargs):
    """
    Applies an UNmap object to a plugin
    """
    if not hasattr(plugin, "export"):
        raise ImportError("%s plugin structure is invalid." % plugin.__name__)

    exp = plugin(nmap_results, **kwargs)
    exp.export()


class Database:
    """
    Class to manipulate the SQLite database generated by UNmap
    """

    def __init__(self, db_path, *args, **kwargs):
        self.db = db_path
        self.conn = pysql_connect( self.db )
        return

    def get_ip_by_ports(self, *args):
        p = "?,"*len(args)
        ips = [ x[0] for x in self.conn.execute("SELECT ip FROM hosts WHERE port in (%s)" % p[:-1], args) ]
        return ips

    def get_ip_port_by_ports(self, *args):
        p = "?,"*len(args)
        ips = [ x[0] for x in self.conn.execute("SELECT ip || ':' || port FROM hosts WHERE port in (%s)" % p[:-1], args) ]
        return ips

    def get_ip_by_banner(self, pattern):
        ips = [ x[0] for x in self.conn.execute("SELECT ip FROM hosts WHERE banner LIKE ?", ("%"+pattern+"%", )) ]
        return ips

    def get_ports_by_ip(self, ip):
        ports = [ x[0] for x in self.conn.execute("SELECT port FROM hosts WHERE ip = ?", (ip, )) ]
        return ports

    def raw_sql(self, sql):
        return self.conn.execute(sql)

    def __del__(self):
        self.conn.close()
        return


# When new plugin is developped, add it here with the keyword to trigger it
SUPPORTED_FORMATS = {"txt": TextUNmapPlugin,
                     "file": FileUNmapPlugin,
                     "sql": SqliteUNmapPlugin,
                     "odt": OdtUNmapPlugin,
                     "html": HtmlUNmapPlugin,
                     "csv": CsvUNmapPlugin,
                     "docx": DocxOdtUNmapPlugin,}



if __name__ == "__main__":

    # I like colors :-)
    RESET = "\x1B[0m"
    RED   = "\x1B[31m"
    GREEN = "\x1B[32m"
    BLUE  = "\x1B[34m"

    parser = ArgumentParser(description=__desc__,
                            epilog="\t---[ EOT ]---",
                            prog=__file__)

    parser.usage = """{0} [--type {4}format{2}] [options*] {3}nmap.xml{2} [nmap.xml ...]
    \twhere {3}nmap.xml{2} is the XML file provided by nmap -oA/-oX option
    \tand {4}format{2} is in {1}
    """.format(__file__,
               '/'.join(SUPPORTED_FORMATS.keys()),
               RESET, BLUE, GREEN )

    parser.add_argument("filelist", type=str, metavar="nmap.xml[,nmap.xml]*", nargs='*',
                        help="specify path to XML Nmap file(s)",)

    parser.add_argument("-v", "--verbose", action="count", dest="verbose",
                        help="increments verbosity")

    parser.add_argument("--version", action="version", version=__version__)

    parser.add_argument("-t", "--type", type=str, metavar="TYPE",
                        dest="type", help="specify output format output. "+
                        "Supported formats are: "+'/'.join(SUPPORTED_FORMATS.keys()),
                        choices = SUPPORTED_FORMATS.keys(), default="txt")

    parser.add_argument("-o", "--output", type=str, metavar="FILE",
                        dest="output", help="specify output format file name",
                        default=None)

    parser.add_argument("-i", "--filter-ip", dest="filter_ips", metavar="IP",
                        action="append", type=str, default=[],
                        help="IP address to discard (can be repeated)")

    parser.add_argument("-p", "--filter-port", dest="filter_ports", metavar="PORT",
                        action="append", type=int, default=[],
                        help="Port number address to discard (can be repeated)")

    parser.add_argument("-s", "--filter-service", dest="filter_services", metavar="SVC",
                        action="append", type=str, default=[],
                        help="Service name to discard (can be repeated)")

    parser.add_argument("-g", "--group", dest="groups", metavar="GROUP",
                        action="append", type=str, default=[],
                        help="Service name group to discard (can be repeated)"+
                        "Supported groups are: "+'/'.join(GROUPS.keys()))

    parser.add_argument("--show-only", dest="show_only", action="store_true",
                        default=False, help="Show only what is filtered [default: False]")

    parser.add_argument("--list", dest="list", action="store_true",
                        default=False, help="Shows group signification [default: False]")

    parser.add_argument("--template", type=str, metavar="TEMPLATE",
                        dest="template", help="specify new template file")

    parser.add_argument("--genthumbs", dest="add_thumb", action="store_true",
                        help="Generate HTTP thumbnails on the fly", default=False)

    args = parser.parse_args()

    if args.list :
        parser.print_usage()
        print("Listing groups:")
        for k,v in GROUPS.iteritems():
            print("\t%-15s: %s" % (k,", ".join(v)))
        exit(0)

    verbose = args.verbose
    logger = getLogger(__file__)
    logger.setLevel(INFO)
    logger.addHandler(handler)

    if len(args.filelist) == 0:
        if verbose:
            logger.info("No XML input provided, using stdin")
        args.filelist = ["/dev/stdin",]

    if len(args.groups):
        for g in args.groups:
            if g not in GROUPS.keys():
                logger.error("Cannot find group '%s'. Skipping ..." % g)
                continue
            if g in args.filter_services :
                if verbose:
                    logger.info("%s already in filter list" % g)
                continue

            args.filter_services.extend([ x for x in GROUPS[g] if x not in args.filter_services ])

    if verbose :
        logger.info("Verbose mode %d" % verbose)
        logger.info("Parsing file(s) : %s" % ','.join([f for f in args.filelist]))
        logger.info("Output file: " + str(args.output))
        logger.info("Output type: " + args.type)
        logger.info("Show only filtered ? " + str(args.show_only))
        logger.info("IP filter: " + (" ".join(args.filter_ips) if len(args.filter_ips) else "[]"))
        logger.info("Port filter: " + (" ".join(["%d" % x for x in args.filter_ports]) \
                                       if len(args.filter_ports) else "[]" ))
        logger.info("Service name filter: " + (" ".join(args.filter_services) \
                                               if len(args.filter_services) else "[]" ))

    unmap = UNmap (args.filelist, args.filter_ips, args.filter_ports,
                   args.filter_services, args.show_only)

    if unmap is None:
        exit(1)

    plugin = SUPPORTED_FORMATS[args.type]
    if args.type == "html" and args.add_thumb:
        proceed(unmap, plugin, filename=args.output, verbose=args.verbose, add_thumb=True)
    else:
        proceed(unmap, plugin, filename=args.output, verbose=args.verbose)

    exit(0)
