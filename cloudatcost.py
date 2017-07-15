#!/usr/bin/python3 -i

import os, json
import requests

target = "https://panel.cloudatcost.com/api/v1"
cac_api = os.getenv("CAC_API")
cac_login = os.getenv("CAC_LOGIN")


def list_servers(server_id=None):
    """Without parameters, list all servers on the account. If `idx` is specified,
    show all the information corresponding to this server ID."""
    url = "{}/listservers.php".format(target)
    params = {"key": cac_api, "login": cac_login}
    req = requests.get(url, params=params)
    if req.status_code != requests.codes.ok:
        print("[-] Got %d: %s" % (req.status_code, req.reason))
        return

    res = req.json()
    print("[+] Status: {:s}".format(res["status"]))

    if res["status"] == "ok":
        for server in res["data"]:
            if server_id is None:
                print("[+] Name: {} ({} - {}), id: {}".format(server["label"], server["ip"], server["rdns"], server["id"]))
                continue
            if server["id"]!=str(server_id):
                continue

            print(json.dumps(server, sort_keys=True, indent=4))
    return


def list_tasks(server_id=None):
    """List all tasks in operation."""
    url = "{}/listtasks.php".format(target)
    params = {"key": cac_api, "login": cac_login}
    req = requests.get(url, params=params)
    if req.status_code != requests.codes.ok:
        print("[-] Got %d: %s" % (req.status_code, req.reason))
        return

    res = req.json()
    print("[+] Status: {:s}".format(res["status"]))

    if res["status"] == "ok":
        for server in res["data"]:
            if server_id is None:
                print("[+] Name: {}, id: {}: {} - {}".format(server["label"], server["serverid"]), server["action"], server["status"], )
                continue
            if server["serverid"]!=str(server_id):
                continue

            print(json.dumps(server, sort_keys=True, indent=4))
    return


def power_operations(server_id, action="reset"):
    """Activate server power operations."""
    valid_actions = ("poweron", "poweroff", "reset")
    if action not in valid_actions:
        print("[-] Incorrect action, must be in %s" % valid_actions)
        return

    url = "{}/powerop.php".format(target)
    params = {"key": cac_api, "login": cac_login, "sid": server_id, "action": action}
    req = requests.post(url, data=params)
    if req.status_code != requests.codes.ok:
        print("[-] Got %d: %s" % (req.status_code, req.reason))
        print(req.text)
        return

    res = req.json()
    if res["status"] != "ok":
        print("[-] {:s}".format(res["error_description"]))
        return

    print("[+] Success: {:s} - {:s}".format(res["action"], res["result"]))
    return


def poweron(server_id): return power_operations(server_id, action="poweron")
def poweroff(server_id): return power_operations(server_id, action="poweroff")
def reset(server_id): return power_operations(server_id, action="reset")


def console(server_id):
    """Request URL for console access."""
    url = "{}/console.php".format(target)
    params = {"key": cac_api, "login": cac_login, "sid": server_id}
    req = requests.post(url, data=params)
    if req.status_code != requests.codes.ok:
        print("[-] Got %d: %s" % (req.status_code, req.reason))
        return

    if len(req.text)==0:
        print("[-] Invalid server response")
        return

    res = req.json()
    if res["status"] != "ok":
        print("[-] {}".format(res["error_description"]))
        return

    print("[+] Success: {}".format(res["console"]))
    return
