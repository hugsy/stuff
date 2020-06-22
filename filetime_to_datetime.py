import datetime

def filetime_to_datetime(ft):
    us = (ft - 116444736000000000) // 10
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds = us)
