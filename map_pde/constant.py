from obspy import UTCDateTime


OPTIONAL_DATASELECT_PARAMETERS = [
    "quality", "minimumlength", "longestonly"]

DEFAULT_STATION_PARAMETERS = [
    "starttime", "endtime", "network", "station", "location", "channel",
    "minlatitude", "maxlatitude", "minlongitude", "maxlongitude", "level"]

OPTIONAL_STATION_PARAMETERS = [
    "startbefore", "startafter", "endbefore", "endafter", "latitude",
    "longitude", "minradius", "maxradius", "includerestricted",
    "includeavailability", "updatedafter", "matchtimeseries", "format"]


OPTIONAL_EVENT_PARAMETERS = [
    "latitude", "longitude", "minradius", "maxradius", "magnitudetype",
    "eventtype", "includeallorigins", "includeallmagnitudes",
    "includearrivals", "eventid", "limit", "offset", "catalog", "contributor",
    "updatedafter"]

OPTIONAL_PARAMETERS = {
    "dataselect1": OPTIONAL_DATASELECT_PARAMETERS,
    "dataselect2": OPTIONAL_DATASELECT_PARAMETERS,
    "event": OPTIONAL_EVENT_PARAMETERS,
    "station": OPTIONAL_STATION_PARAMETERS}




DEFAULT_SERVICE_VERSIONS = {'dataselect1': 1, 'dataselect2':1, 'station': 1, 'event': 1}
URL_MAPPINGS = {
    "MAP": "http://10.99.12.109:38080"
}
DEFAULT_SUB_PATH = "map"
IS_LOGIN_URL = "http://10.99.12.109:38080/user/is_login"
URL_DEFAULT_SUBPATH = None
DEFAULT_DATASELECT1_PARAMETERS = [
    "site", "dataType", "device", "startTime", "endTime"]
DEFAULT_DATASELECT2_PARAMETERS = [
    "network", "station", "location", "channel", "startTime", "endTime"]
DEFAULT_STATION_PARAMETERS = [
    "site", "dataType", "device"
]
DEFAULT_EVENT_PARAMETERS = [
   "startTime", "endTime"
]

DEFAULT_PARAMETERS = {
    "dataselect1": DEFAULT_DATASELECT1_PARAMETERS,
    "dataselect2": DEFAULT_DATASELECT2_PARAMETERS,
    "event": DEFAULT_EVENT_PARAMETERS,
    "station": DEFAULT_STATION_PARAMETERS}

PARAMETER_ALIASES = {
    "site": "site",
    "dataType": "dataType",
    "device": "device",
    "startTime": "startTime",
    "endTime": "endTime",
    "net": "network",
    "sta": "station",
    "loc": "location",
    "cha": "channel",
    "start": "starttime",
    "end": "endtime",
    "minlat": "minlatitude",
    "maxlat": "maxlatitude",
    "minlon": "minlongitude",
    "maxlon": "maxlongitude",
    "lat": "latitude",
    "lon": "longitude",
    "minmag": "minmagnitude",
    "maxmag": "maxmagnitude",
    "magtype": "magnitudetype",
}

DEFAULT_VALUES = {
    "site": None,
    "dataType": None,
    "device": None,
    "startTime": None,
    "endTime": None,
    "starttime": None,
    "endtime": None,
    "network": None,
    "station": None,
    "location": None,
    "channel": None,
    "quality": "B",
    "minimumlength": 0.0,
    "longestonly": False,
    "startbefore": None,
    "startafter": None,
    "endbefore": None,
    "endafter": None,
    "maxlongitude": 180.0,
    "minlongitude": -180.0,
    "longitude": 0.0,
    "maxlatitude": 90.0,
    "minlatitude": -90.0,
    "latitude": 0.0,
    "maxdepth": None,
    "mindepth": None,
    "maxmagnitude": None,
    "minmagnitude": None,
    "magnitudetype": None,
    "maxradius": 180.0,
    "minradius": 0.0,
    "level": "station",
    "includerestricted": True,
    "includeavailability": False,
    "includeallorigins": False,
    "includeallmagnitudes": False,
    "includearrivals": False,
    "matchtimeseries": False,
    "eventid": None,
    "eventtype": None,
    "limit": None,
    "offset": 1,
    "orderby": "time",
    "catalog": None,
    "contributor": None,
    "updatedafter": None,
}
DEFAULT_TYPES = {
    "site": list,
    "dataType": list,
    "device": list,
    "startTime": UTCDateTime,
    "endTime": UTCDateTime,
    "starttime": UTCDateTime,
    "endtime": UTCDateTime,
    "network": str,
    "station": str,
    "location": str,
    "channel": str,
    "quality": str,
    "minimumlength": float,
    "longestonly": bool,
    "startbefore": UTCDateTime,
    "startafter": UTCDateTime,
    "endbefore": UTCDateTime,
    "endafter": UTCDateTime,
    "maxlongitude": float,
    "minlongitude": float,
    "longitude": float,
    "maxlatitude": float,
    "minlatitude": float,
    "latitude": float,
    "maxdepth": float,
    "mindepth": float,
    "maxmagnitude": float,
    "minmagnitude": float,
    "magnitudetype": str,
    "maxradius": float,
    "minradius": float,
    "level": str,
    "includerestricted": bool,
    "includeavailability": bool,
    "includeallorigins": bool,
    "includeallmagnitudes": bool,
    "includearrivals": bool,
    "matchtimeseries": bool,
    "eventid": str,
    "eventtype": str,
    "limit": int,
    "offset": int,
    "orderby": str,
    "catalog": str,
    "contributor": str,
    "updatedafter": UTCDateTime,
    "format": str}
DEFAULT_SERVICES = {}
for service in ["dataselect1", "dataselect2","event", "station"]:
    DEFAULT_SERVICES[service] = {}

    for default_param in DEFAULT_PARAMETERS[service]:
        DEFAULT_SERVICES[service][default_param] = {
            "default_value": DEFAULT_VALUES[default_param],
            "type": DEFAULT_TYPES[default_param],
            "required": False,
        }

    for optional_param in OPTIONAL_PARAMETERS[service]:
        if optional_param == "format":
            if service == "dataselect1" or service == "dataselect2":
                default_val = "miniseed"
            else:
                default_val = "xml"
        else:
            default_val = DEFAULT_VALUES[optional_param]

        DEFAULT_SERVICES[service][optional_param] = {
            "default_value": default_val,
            "type": DEFAULT_TYPES[optional_param],
            "required": False,
        }