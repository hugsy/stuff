#!/usr/bin/env python3

import argparse
import datetime
import requests
import sys
import threading


__author__    =   "@_hugsy_"
__version__   =   0.1
__licence__   =   "WTFPL v.2"
__file__      =   "bc_camping.py"
__desc__      =   "Checks the availability of camping spots in BC"
__usage__     =   """{3} v{0}\nby {2} under {1}\nsyntax: {3} [options] args""".format(__version__, __licence__, __author__, __file__)


MAX_LOCATION_ID = 160


def get_data(location_id: int, start_date: datetime.datetime, number_of_nights: int) -> requests.Response:
    url = "https://bccrdr.usedirect.com/rdr/rdr/search/place"
    data = {
        "PlaceId": location_id,
        "Latitude": 0,
        "Longitude": 0,
        "HighlightedPlaceId": location_id,
        "StartDate": start_date.strftime("%Y-%m-%d"),
        "Nights": number_of_nights,
        "CountNearby": False,
        "NearbyLimit": 0,
        "NearbyOnlyAvailable": False,
        "NearbyCountLimit": 0,
        "Sort": 'Distance',
        "CustomerId": 0,
        "RefreshFavourites": True,
        "IsADA": False,
        "UnitCategoryId": 2,
        "SleepingUnitId": 10,
        "MinVehicleLength": 0,
        "UnitTypesGroupIds": [],
    }
    h = requests.post(
        url,
        json=data,
        headers={
            "accept": "application/json, text/javascript, */*; q=0.01",
            "content-type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 Edg/83.0.478.37",
        }
    )

    if h.status_code != requests.codes.ok:
        raise RuntimeError(f"Unexpected code HTTP/{h.status_code}")

    js = h.json()
    if not js:
        raise RuntimeError(f"Unexpected response")

    if js['SelectedPlaceId'] == 0:
        raise KeyError('invalid location_id')

    return js


def print_availability_for_location_and_dates(location_id: int, start_date: datetime.datetime, number_of_nights: int) -> None:
    js = get_data(location_id, start_date, number_of_nights)
    if not js['SelectedPlace']['Available']:
        if args.verbose > 2:
            print(f"No spot available for '{js['SelectedPlace']['Name']}'")
        return

    for facility_index in js['SelectedPlace']['Facilities']:
        facility = js['SelectedPlace']['Facilities'][facility_index]
        if facility['Available']:
            for unit_type_index in facility['UnitTypes']:
                unit_type = facility['UnitTypes'][unit_type_index]
                if unit_type['Available'] and not unit_type['AvailableFiltered'] and unit_type['AvailableCount'] > 0:
                    print(f"{unit_type['AvailableCount']} '{unit_type['Name']}' spot{'s' if unit_type['AvailableCount'] > 1 else ''} ({facility['Name']}) available at '{js['SelectedPlace']['Name']}'")


def thread_run(i:int , start_date: datetime.datetime, number_of_nights: int):
    try:
        print_availability_for_location_and_dates(i, start_date, number_of_nights)
    except:
        pass
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage = __usage__, description = __desc__, prog = __file__)

    parser.add_argument("-n", "--number-night", type=int, default=2, dest="number_of_nights",
                        help="Specify the number of nights to camp")
    parser.add_argument("-l", "--location", type=int, default=100,
                        help="Specify the location ID")
    parser.add_argument("-v", "--verbose", action="count", dest="verbose",
                        help="Increments verbosity")
    parser.add_argument("-t", "--threads", dest="threads", type=int, metavar="N",
                        default=20, help="Specify number of threads to use")
    parser.add_argument("start_date", type=lambda x: datetime.datetime.strptime(x, '%Y/%m/%d'),
                        metavar="YYYY/MM/DD", help="Specify the start date")
    args = parser.parse_args()


    thread_pool = []
    i = 0

    if args.verbose:
        print(f"Lookup for available spot for {args.number_of_nights} from {args.start_date.strftime('%Y/%m/%d')} using {args.threads} threads")

    while True:
        for j in range(1, args.threads):
            if i >= MAX_LOCATION_ID:
                break
            t = threading.Thread(target=thread_run, args=(i, args.start_date, args.number_of_nights))
            t.daemon = True
            thread_pool.append(t)
            t.start()
            i += 1

        for t in thread_pool:
            t.join()

        thread_pool.clear()

        if i >= MAX_LOCATION_ID:
            break

    sys.exit(0)