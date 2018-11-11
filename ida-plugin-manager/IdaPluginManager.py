"""
IDA Plugin Manager

"One plugin to install them all"

Install plugins in:
 -  %APPDATA%\Hex-Rays\IDA-Pro for Windows
 - ~/.idapro for Linux

Author: @_hugsy_
License: WTFPL v2
"""

import ConfigParser
import sys
import sqlite3
import os
import platform
import datetime
import operator

try:
    import idaapi
    import idautils
    import idc
    is_running_in_ida = True
except ImportError:
    is_running_in_ida = False
    # todo later: implem standalone qt gui


try:
    import PyQt5
except ImportError:
    print("Python-Qt5 is missing")
    sys.exit(1)

NAME           = "IDA Plugin Manager"
DESCRIPTION    = "Install clean and simply new IDA plugins."
HOTKEY         = "Ctrl-Alt-I"
CFGFILE_PATH   = os.path.dirname(os.path.realpath(__file__)) + "\\IdaPluginManager.cfg"


from PyQt5.QtWidgets import (QApplication, QWidget,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QGridLayout, QHBoxLayout, QVBoxLayout,
                             QTableView,
)
from PyQt5.QtCore import (Qt, QAbstractTableModel, QVariant,
)
from PyQt5.QtGui import (QFont,
)


def __log(m, prefix=""):
    ts = datetime.datetime.now()
    print(ts.strftime("%c") + prefix + m)

def ok(m):
    __log(" [+] " + m)

def info(m):
    __log(" [*] " + m)

def error(m):
    __log(" [-] " + m)


class Plugin:
    SQLITE_COLUMNS = ["name", "description", "author", "version", "url"]
    SQLITE_PROTOTYPE = "CREATE TABLE plugins (p plugin); CREATE TABLE metadata(last_refresh_db_ts timestamp);"

    def __init__(self, *args, **kwargs):
        self.name        = kwargs.get("name")
        self.description = kwargs.get("description")
        self.author      = kwargs.get("author")
        self.version     = kwargs.get("version")
        self.url         = kwargs.get("url")
        return

    def to_sqlite(self):
        return ";".join([self.name,
                         self.description,
                         self.author,
                         self.version,
                         self.url])

    @staticmethod
    def from_sqlite(data):
        v = data.split(";")
        k = SQLITE_COLUMNS
        args = {}
        for i in enumerate(v):  args[k[i]] = v[i]
        return Plugin(args)


sqlite3.register_adapter(Plugin, Plugin.to_sqlite)
sqlite3.register_converter("Plugin", Plugin.from_sqlite)


class PluginTableModel(QAbstractTableModel):
    def __init__(self, rows_data_list, header_list, parent=None, *args):
        QAbstractTableModel.__init__(self, parent, *args)
        self.rows = rows_data_list
        self.headers = header_list
        return

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(Plugin.SQLITE_COLUMNS)

    def data(self, index, role):
        if not index.isValid():
            return QVariant()
        elif role != Qt.DisplayRole:
            return QVariant()
        return QVariant(self.rows[index.row()][index.column()])

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return QVariant(self.headers[col].title() )
        return QVariant()

    def sort(self, ncol, order):
        # self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self.rows = sorted(self.rows, key=operator.itemgetter(ncol))
        if order == Qt.DescendingOrder:
            self.rows.reverse()
        # self.emit(SIGNAL("layoutChanged()"))
        return


class PluginManager(idaapi.PluginForm):

    def __init__(self, *args, **kwargs):
        super(PluginManager, self).__init__()
        info("Starting '{}'...".format(NAME))
        info("Loading Configuration file...")
        self.LoadConfig()
        info("Loading plugin list from cache file...")
        self.LoadAvailablePlugins()
        ok("Ready")
        return

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.SetupUI(self.parent)
        return

    def OnClose(self, form):
        self.db_cursor.close()
        self.db_connector.close()
        return

    def Show(self):
        return idaapi.PluginForm.Show(self, NAME, options=idaapi.PluginForm.FORM_PERSIST)

    def LoadAvailablePlugins(self):
        db_path = self.cfg.get("main", "plugin_db_path")
        is_new = False
        if not os.access(db_path, os.W_OK):
            info("'{}' doesn't exist, creating it".format(db_path))
            is_new = True
            open(db_path, "wb").close()

        self.db_connector = sqlite3.connect(db_path,
                                            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self.db_cursor = self.db_connector.cursor()
        if is_new:
            self.db_cursor.execute(Plugin.SQLITE_PROTOTYPE)
            self.db_connector.commit()

        self.db_cursor.execute("select p from plugins")
        self.available_plugins = self.db_cursor.fetchall()
        return

    def LoadConfig(self):
        os_version = platform.system()
        if os_version == "Windows":
            plugin_root = os.path.expandvars("%APPDATA%") + "\\Hex-Rays\\IDA Pro"
        elif os_version == "Linux":
            plugin_root = os.path.expandvars("$HOME") + "/.idapro"
        else:
            raise Exception("Unsupported OS")

        self.cfg = ConfigParser.SafeConfigParser({"ROOT": plugin_root})
        self.cfg.read(CFGFILE_PATH)
        return

    def SetupUI(self, w):
        info("SetupUI")

        # Search bar
        lblName = QLabel('Search')
        lblResults = QLabel('Results')

        # Plugin table
        ledtName = QLineEdit()
        tblResults = QTableView()
        tblResultsModel = PluginTableModel(self.available_plugins, Plugin.SQLITE_COLUMNS, w)
        tblResults.setModel( tblResultsModel )
        tblResults.horizontalHeader().setStretchLastSection(True)
        tblResults.verticalHeader().setVisible(False)
        tblResults.resizeColumnsToContents()
        tblResults.setSortingEnabled(True)
        tblResults.setFont( QFont("Courier New", 8) )
        tblResults.setShowGrid(False)

        ## event handlers
        ledtName.textChanged.connect(self.OnSearchFieldChange)


        # Button row
        btnUpdate = QPushButton("Refresh Plugins List")
        btnInstall = QPushButton("Install")

        ## event handlers
        btnUpdate.clicked.connect(self.RefreshPluginsList)
        btnInstall.clicked.connect(self.InstallSelected)


        grid = QGridLayout()
        grid.addWidget(lblName, 1, 0)
        grid.addWidget(ledtName, 1, 1)
        grid.addWidget(lblResults, 2, 0)
        grid.addWidget(tblResults, 2, 1, 5, 1)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(btnUpdate)
        vbox.addWidget(btnInstall)
        wButtons = QWidget()
        wButtons.setLayout(vbox)

        grid.addWidget(wButtons, 5, 1, 4, 1)
        w.setLayout(grid)
        return


    def OnSearchFieldChange(self):
        return

    def RefreshPluginsList(self):
        return

    def InstallSelected(self):
        return


class plugin_manager_plugin_t(idaapi.plugin_t):
    comment        = NAME
    help           = DESCRIPTION
    flags          = idaapi.PLUGIN_UNL
    wanted_name    = NAME
    wanted_hotkey  = HOTKEY

    def init(self):
        self.icon_id = 0
        self.p = PluginManager()
        self.p.Show()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        return

    def term(self):
        self.p.OnClose()
        return


def PLUGIN_ENTRY():
    if idaapi.IDA_SDK_VERSION >= 690:
        return plugin_manager_plugin_t().init()
    elif 670 <= idaapi.IDA_SDK_VERSION < 690:
        return plugin_manager_plugin_t()
    raise Exception("IDA version too old")


if __name__ == "__main__":
    PLUGIN_ENTRY()
