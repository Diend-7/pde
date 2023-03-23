import copy
import gzip
import io
import os
import re
import textwrap
import threading
import warnings
import urllib.request as urllib_request
import queue
import obspy
from obspy import UTCDateTime, read_inventory
from obspy.core.compatibility import collections_abc
from obspy.clients.fdsn.header import (DEFAULT_USER_AGENT, FDSNWS,
                     OPTIONAL_PARAMETERS,  URL_MAPPING_SUBPATHS,
                     WADL_PARAMETERS_NOT_TO_BE_PARSED,
                     FDSNException, FDSNRedirectException, FDSNNoDataException,
                     FDSNTimeoutException,
                     FDSNBadRequestException, FDSNNoServiceException,
                     FDSNInternalServerException,
                     FDSNNotImplementedException,
                     FDSNBadGatewayException,
                     FDSNTooManyRequestsException,
                     FDSNRequestTooLargeException,
                     FDSNServiceUnavailableException,
                     FDSNUnauthorizedException,
                     FDSNForbiddenException,
                     FDSNDoubleAuthenticationException,
                     FDSNInvalidRequestException)
from obspy.clients.fdsn.wadl_parser import WADLParser
from obspy.clients.fdsn.client import download_url
from urllib.parse import urlencode
from collections import OrderedDict
from http.client import HTTPException, IncompleteRead
from socket import timeout as socket_timeout
from lxml import etree


DEFAULT_SERVICE_VERSIONS = {'dataselect': 1, 'station': 1, 'event': 1}
URL_MAPPINGS = {
    "MAP": "http://10.99.12.109:38080"
}
URL_DEFAULT_SUBPATH = None
DEFAULT_DATASELECT_PARAMETERS = [
    "site", "dataType", "device", "startTime", "endTime"]
DEFAULT_STATION_PARAMETERS = [
    "site", "dataType", "device"
]
DEFAULT_EVENT_PARAMETERS = [
   "startTime", "endTime"
]

DEFAULT_PARAMETERS = {
    "dataselect": DEFAULT_DATASELECT_PARAMETERS,
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
for service in ["dataselect", "event", "station"]:
    DEFAULT_SERVICES[service] = {}

    for default_param in DEFAULT_PARAMETERS[service]:
        DEFAULT_SERVICES[service][default_param] = {
            "default_value": DEFAULT_VALUES[default_param],
            "type": DEFAULT_TYPES[default_param],
            "required": False,
        }

    for optional_param in OPTIONAL_PARAMETERS[service]:
        if optional_param == "format":
            if service == "dataselect":
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


class CustomRedirectHandler(urllib_request.HTTPRedirectHandler):
    """
    Custom redirection handler to also do it for POST requests which the
    standard library does not do by default.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """
        Copied and modified from the standard library.
        """
        # Force the same behaviour for GET, HEAD, and POST.
        m = req.get_method()
        if (not (code in (301, 302, 303, 307) and
                 m in ("GET", "HEAD", "POST"))):
            raise urllib_request.HTTPError(req.full_url, code, msg, headers,
                                           fp)

        # be conciliant with URIs containing a space
        newurl = newurl.replace(' ', '%20')
        content_headers = ("content-length", "content-type")
        newheaders = dict((k, v) for k, v in req.headers.items()
                          if k.lower() not in content_headers)

        # Also redirect the data of the request which the standard library
        # interestingly enough does not do.
        return urllib_request.Request(
            newurl, headers=newheaders,
            data=req.data,
            origin_req_host=req.origin_req_host,
            unverifiable=True)


class NoRedirectionHandler(urllib_request.HTTPRedirectHandler):
    """
    Handler that does not direct!
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """
        Copied and modified from the standard library.
        """
        raise FDSNRedirectException(
            "Requests with credentials (username, password) are not being "
            "redirected by default to improve security. To force redirects "
            "and if you trust the data center, set `force_redirect` to True "
            "when initializing the Client.")


class Client(object):
    """
    FDSN Web service request client.

    For details see the :meth:`~obspy.clients.fdsn.client.Client.__init__()`
    method.
    """
    # Dictionary caching any discovered service. Therefore repeatedly
    # initializing a client with the same base URL is cheap.
    __service_discovery_cache = {}
    #: Regex for UINT8
    RE_UINT8 = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})'
    #: Regex for HEX4
    RE_HEX4 = r'(?:[\d,a-f]{4}|[1-9,a-f][0-9,a-f]{0,2}|0)'
    #: Regex for IPv4
    RE_IPv4 = r'(?:' + RE_UINT8 + r'(?:\.' + RE_UINT8 + r'){3})'
    #: Regex for IPv6
    RE_IPv6 = \
        r'(?:\[' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){7}\]' + \
        r'|\[(?:' + RE_HEX4 + r':){0,5}' + RE_HEX4 + r'::\]' + \
        r'|\[::' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){0,5}\]' + \
        r'|\[::' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){0,3}:' + RE_IPv4 + \
        r'\]' + \
        r'|\[' + RE_HEX4 + r':' + \
        r'(?:' + RE_HEX4 + r':|:' + RE_HEX4 + r'){0,4}' + \
        r':' + RE_HEX4 + r'\])'
    #: Regex for checking the validity of URLs
    URL_REGEX = r'https?://' + \
                r'(' + RE_IPv4 + \
                r'|' + RE_IPv6 + \
                r'|localhost' + \
                r'|\w(?:[\w-]*\w)?' + \
                r'|(?:\w(?:[\w-]{0,61}[\w])?\.){1,}([a-z][a-z0-9-]{1,62}))' + \
                r'(?::\d{2,5})?' + \
                r'(/[\w\.-]+)*/?$'

    @classmethod
    def _validate_base_url(cls, base_url):
        """
        用来判断一个base_url是否是有效的
        :param base_url: 基本的url
        :return: 合法则返回true,不合法则返回false
        """
        if re.match(cls.URL_REGEX, base_url, re.IGNORECASE):
            return True
        else:
            return False

    def __init__(self, base_url="MAP", major_versions=None, user=None,
                 password=None, user_agent=DEFAULT_USER_AGENT, debug=False,
                 timeout=120, service_mappings=None, force_redirect=False,
                 sa_token=None, _discover_services=True):

        self.debug = debug
        self.user = user
        self.timeout = timeout
        self._force_redirect = force_redirect

        # Cache for the webservice versions. This makes interactive use of
        # the client more convenient.
        self.__version_cache = {}

        # 先根据指定的数据中心去拿到它的url地址
        if base_url.upper() in URL_MAPPINGS:
            url_mapping = base_url.upper()
            base_url = URL_MAPPINGS[url_mapping]
            url_subpath = URL_MAPPING_SUBPATHS.get(
                url_mapping, URL_DEFAULT_SUBPATH)
        else:
            if base_url.isalpha():
                msg = "The FDSN service shortcut `{}` is unknown."\
                      .format(base_url)
                raise ValueError(msg)
            url_subpath = URL_DEFAULT_SUBPATH
        # Make sure the base_url does not end with a slash.
        base_url = base_url.strip("/")
        # Catch invalid URLs to avoid confusing error messages
        # 判断这个url地址是否合法
        if not self._validate_base_url(base_url):
            msg = "The FDSN service base URL `{}` is not a valid URL."\
                  .format(base_url)
            raise ValueError(msg)

        self.base_url = base_url
        self.url_subpath = "map"

        # 如果输入了用户名密码则需要加入认证处理
        self._set_opener(user, password)

        self.request_headers = {"User-Agent": user_agent}
        # Avoid mutable kwarg.
        if major_versions is None:
            major_versions = {}
        # Make a copy to avoid overwriting the default service versions.
        self.major_versions = DEFAULT_SERVICE_VERSIONS.copy()
        self.major_versions.update(major_versions)

        # Avoid mutable kwarg.
        if service_mappings is None:
            service_mappings = {}
        self._service_mappings = service_mappings

        if self.debug is True:
            print("Base URL: %s" % self.base_url)
            if self._service_mappings:
                print("Custom service mappings:")
                for key, value in self._service_mappings.items():
                    print("\t%s: '%s'" % (key, value))
            print("Request Headers: %s" % str(self.request_headers))

        # 看是否需要发现服务
        # if _discover_services:
        #     self._discover_services()
        # else:
        #     self.services = DEFAULT_SERVICES
        self.services = DEFAULT_SERVICES

        # Use EIDA token if provided - this requires setting new url openers.
        #
        # This can only happen after the services have been discovered as
        # the clients needs to know if the fdsnws implementation has support
        # for the EIDA token system.
        #
        # This is a non-standard feature but we support it, given the number
        # of EIDA nodes out there.
        if sa_token is not None:
            # Make sure user/pw are not also given.
            if user is not None or password is not None:
                msg = ("EIDA authentication token provided, but "
                       "user and password are also given.")
                raise FDSNDoubleAuthenticationException(msg)
            self.set_eida_token(sa_token)

    @property
    def _has_sa_token(self):
        """
        判断是否加入了token
        :return: 有返回true，没有返回false
        """
        return self.request_headers.get('satoken', False)

    def set_eida_token(self, token):
        """
        在请求头里面添加token，没有token是没有办法获取数据的
        :param token:
        :return:
        """
        self.request_headers["satoken"] = token

    def _set_opener(self, user, password):
        # Only add the authentication handler if required.
        handlers = []
        if user is not None and password is not None:
            # Create an OpenerDirector for HTTP Digest Authentication
            password_mgr = urllib_request.HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, self.base_url, user, password)
            handlers.append(urllib_request.HTTPDigestAuthHandler(password_mgr))

        if (user is None and password is None) or self._force_redirect is True:
            # Redirect if no credentials are given or the force_redirect
            # flag is True.
            handlers.append(CustomRedirectHandler())
        else:
            handlers.append(NoRedirectionHandler())

        # Don't install globally to not mess with other codes.
        self._url_opener = urllib_request.build_opener(*handlers)
        if self.debug:
            print('Installed new opener with handlers: {!s}'.format(handlers))

    def get_waveforms(self, site, dataType, device, startTime,
                      endTime, filename=None, attach_response=False, **kwargs):

        if "dataselect" not in self.services:
            msg = "The current client does not have a dataselect service."
            raise ValueError(msg)

        locs = locals()
        setup_query_dict('dataselect', locs, kwargs)

        # Special location handling. Convert empty strings to "--".
        # if "location" in kwargs and not kwargs["location"]:
        #     kwargs["location"] = "--"

        url = self._create_url_from_parameters(
            "dataselect", DEFAULT_PARAMETERS['dataselect'], kwargs)

        # Gzip not worth it for MiniSEED and most likely disabled for this
        # route in any case.
        data_stream = self._download(url, use_gzip=False)
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            st = obspy.read(data_stream)
            data_stream.close()
            if attach_response:
                self._attach_responses(st)
            self._attach_dataselect_url_to_stream(st)
            # st.trim(startTime, endTime)
            return st

    def get_events(self, startTime=None, endTime=None, filename=None, **kwargs):

        if "event" not in self.services:
            msg = "The current client does not have an event service."
            raise ValueError(msg)

        locs = locals()
        setup_query_dict('event', locs, kwargs)

        url = self._create_url_from_parameters(
            "event", DEFAULT_PARAMETERS['event'], kwargs)

        data_stream = self._download(url)
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            cat = obspy.read_events(data_stream, format="quakeml")
            data_stream.close()
            return cat

    def get_stations(self, site, dataType, device, filename=None,
                     format=None, **kwargs):

        if "station" not in self.services:
            msg = "The current client does not have a station service."
            raise ValueError(msg)

        locs = locals()
        setup_query_dict('station', locs, kwargs)

        url = self._create_url_from_parameters(
            "station", DEFAULT_PARAMETERS['station'], kwargs)

        data_stream = self._download(url)
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            # This works with XML and StationXML data.
            inventory = read_inventory(data_stream ,  format="STATIONXML")
            # inventory = read_inventory(data_stream)
            data_stream.close()
            return inventory



    def _attach_responses(self, st):
        """
        Helper method to fetch response via get_stations() and attach it to
        each trace in stream.
        """
        netids = {}
        for tr in st:
            if tr.id not in netids:
                netids[tr.id] = (tr.stats.starttime, tr.stats.endtime)
                continue
            netids[tr.id] = (
                min(tr.stats.starttime, netids[tr.id][0]),
                max(tr.stats.endtime, netids[tr.id][1]))

        inventories = []
        for key, value in netids.items():
            net, sta, loc, chan = key.split(".")
            starttime, endtime = value
            try:
                inventories.append(self.get_stations(
                    network=net, station=sta, location=loc, channel=chan,
                    starttime=starttime, endtime=endtime, level="response"))
            except Exception as e:
                warnings.warn(str(e))
        st.attach_response(inventories)

    def get_waveforms_bulk(self, bulk, quality=None, minimumlength=None,
                           longestonly=None, filename=None,
                           attach_response=False, **kwargs):

        if "dataselect" not in self.services:
            msg = "The current client does not have a dataselect service."
            raise ValueError(msg)

        arguments = OrderedDict(
            quality=quality,
            minimumlength=minimumlength,
            longestonly=longestonly
        )
        bulk = get_bulk_string(bulk, arguments)

        url = self._build_url("dataselect", "query")

        data_stream = self._download(
            url, data=bulk, content_type='text/plain')
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            st = obspy.read(data_stream, format="MSEED")
            data_stream.close()
            if attach_response:
                self._attach_responses(st)
            self._attach_dataselect_url_to_stream(st)
            return st

    def get_stations_bulk(self, bulk, level=None, includerestricted=None,
                          includeavailability=None, filename=None, **kwargs):

        if "station" not in self.services:
            msg = "The current client does not have a station service."
            raise ValueError(msg)

        arguments = OrderedDict(
            level=level,
            includerestricted=includerestricted,
            includeavailability=includeavailability
        )
        bulk = get_bulk_string(bulk, arguments)

        url = self._build_url("station", "query")

        data_stream = self._download(
            url, data=bulk, content_type='text/plain')
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
            return
        else:
            # Works with text and StationXML data.
            inv = obspy.read_inventory(data_stream)
            data_stream.close()
            return inv

    def _write_to_file_object(self, filename_or_object, data_stream):
        if hasattr(filename_or_object, "write"):
            filename_or_object.write(data_stream.read())
            return
        with open(filename_or_object, "wb") as fh:
            fh.write(data_stream.read())

    def _create_url_from_parameters(self, service, default_params, parameters):
        """
        """
        service_params = self.services[service]
        # Get all required parameters and make sure they are available!
        required_parameters = [
            key for key, value in service_params.items()
            if value["required"] is True]
        for req_param in required_parameters:
            if req_param not in parameters:
                msg = "Parameter '%s' is required." % req_param
                raise TypeError(msg)

        final_parameter_set = {}

        # Now loop over all parameters, convert them and make sure they are
        # accepted by the service.
        for key, value in parameters.items():
            if key not in service_params:
                # If it is not in the service but in the default parameters
                # raise a warning.
                if key in default_params:
                    msg = ("The standard parameter '%s' is not supported by "
                           "the webservice. It will be silently ignored." %
                           key)
                    warnings.warn(msg)
                    continue
                elif key in WADL_PARAMETERS_NOT_TO_BE_PARSED:
                    msg = ("The parameter '%s' is ignored because it is not "
                           "useful within ObsPy")
                    warnings.warn(msg % key)
                    continue
                # Otherwise raise an error.
                else:
                    msg = \
                        "The parameter '%s' is not supported by the service." \
                        % key
                    raise TypeError(msg)
            # Now attempt to convert the parameter to the correct type.
            this_type = service_params[key]["type"]

            # Try to decode to be able to work with bytes.
            if this_type is str:
                try:
                    value = value.decode()
                except AttributeError:
                    pass

            try:
                value = this_type(value)
            except Exception:
                msg = "'%s' could not be converted to type '%s'." % (
                    str(value), this_type.__name__)
                raise TypeError(msg)
            # Now convert to a string that is accepted by the webservice.
            value = convert_to_string(value)
            final_parameter_set[key] = value

        return self._build_url(service, "query",
                               parameters=final_parameter_set)

    def __str__(self):
        versions = dict([(s, self._get_webservice_versionstring(s))
                         for s in self.services if s in FDSNWS])
        services_string = ["'%s' (v%s)" % (s, versions[s])
                           for s in FDSNWS if s in self.services]
        other_services = sorted([s for s in self.services if s not in FDSNWS])
        services_string += ["'%s'" % s for s in other_services]
        services_string = ", ".join(services_string)
        ret = ("FDSN Webservice Client (base url: {url})\n"
               "Available Services: {services}\n\n"
               "Use e.g. client.help('dataselect') for the\n"
               "parameter description of the individual services\n"
               "or client.help() for parameter description of\n"
               "all webservices.".format(url=self.base_url,
                                         services=services_string))
        return ret

    def _repr_pretty_(self, p, cycle):
        p.text(str(self))

    def help(self, service=None):
        """
        Print a more extensive help for a given service.

        This will use the already parsed WADL files and be specific for each
        data center and always up-to-date.
        """
        if service is not None and service not in self.services:
            msg = "Service '%s' not available for current client." % service
            raise ValueError(msg)

        if service is None:
            services = list(self.services.keys())
        elif service in FDSNWS:
            services = [service]
        else:
            msg = "Service '%s is not a valid FDSN web service." % service
            raise ValueError(msg)

        msg = []
        for service in services:
            if service not in FDSNWS:
                continue
            service_default = DEFAULT_PARAMETERS[service]
            service_optional = OPTIONAL_PARAMETERS[service]

            msg.append("Parameter description for the "
                       "'%s' service (v%s) of '%s':" % (
                           service,
                           self._get_webservice_versionstring(service),
                           self.base_url))

            # Loop over all parameters and group them in four lists: available
            # default parameters, missing default parameters, optional
            # parameters and additional parameters.
            available_default_parameters = []
            missing_default_parameters = []
            optional_parameters = []
            additional_parameters = []

            printed_something = False

            for name in service_default:
                if name in self.services[service]:
                    available_default_parameters.append(name)
                else:
                    missing_default_parameters.append(name)

            for name in service_optional:
                if name in self.services[service]:
                    optional_parameters.append(name)

            defined_parameters = service_default + service_optional
            for name in self.services[service].keys():
                if name not in defined_parameters:
                    additional_parameters.append(name)

            def _param_info_string(name):
                param = self.services[service][name]
                name = "%s (%s)" % (name, param["type"].__name__.replace(
                    'new', ''))
                req_def = ""
                if param["required"]:
                    req_def = "Required Parameter"
                elif param["default_value"]:
                    req_def = "Default value: %s" % str(param["default_value"])
                if param["options"]:
                    req_def += ", Choices: %s" % \
                        ", ".join(map(str, param["options"]))
                if req_def:
                    req_def = ", %s" % req_def
                if param["doc_title"]:
                    doc_title = textwrap.fill(param["doc_title"], width=79,
                                              initial_indent="        ",
                                              subsequent_indent="        ",
                                              break_long_words=False)
                    doc_title = "\n" + doc_title
                else:
                    doc_title = ""

                return "    {name}{req_def}{doc_title}".format(
                    name=name, req_def=req_def, doc_title=doc_title)

            if optional_parameters:
                printed_something = True
                msg.append("The service offers the following optional "
                           "standard parameters:")
                for name in optional_parameters:
                    msg.append(_param_info_string(name))

            if additional_parameters:
                printed_something = True
                msg.append("The service offers the following "
                           "non-standard parameters:")
                for name in sorted(additional_parameters):
                    msg.append(_param_info_string(name))

            if missing_default_parameters:
                printed_something = True
                msg.append("WARNING: The service does not offer the following "
                           "standard parameters: %s" %
                           ", ".join(missing_default_parameters))

            if service == "event" and \
                    "available_event_catalogs" in self.services:
                printed_something = True
                msg.append("Available catalogs: %s" %
                           ", ".join(
                               self.services["available_event_catalogs"]))

            if service == "event" and \
                    "available_event_contributors" in self.services:
                printed_something = True
                msg.append("Available contributors: %s" %
                           ", ".join(
                               self.services["available_event_contributors"]))

            if printed_something is False:
                msg.append("No derivations from standard detected")

        print("\n".join(msg))

    def _download(self, url, return_string=False, data=None, use_gzip=True,
                  content_type=None):
        headers = self.request_headers.copy()
        if content_type:
            headers['Content-Type'] = content_type
        code, data = download_url(
            url, opener=self._url_opener, headers=headers,
            debug=self.debug, return_string=return_string, data=data,
            timeout=self.timeout, use_gzip=use_gzip)
        raise_on_error(code, data)
        return data

    def _build_url(self, service, resource_type, parameters={}):
        """
        Builds the correct URL.

        Replaces "query" with "queryauth" if client has authentication
        information.
        """
        # authenticated dataselect queries have different target URL
        if self.user is not None:
            if service == "dataselect" and resource_type == "query":
                resource_type = "queryauth"
        return build_url(self.base_url, service, self.major_versions[service],
                         resource_type, parameters,
                         service_mappings=self._service_mappings,
                         subpath=self.url_subpath)

    def _discover_services(self):
        """
        Automatically discovers available services.

        They are discovered by downloading the corresponding WADL files. If a
        WADL does not exist, the services are assumed to be non-existent.
        自动发现可用服务。

        它们是通过下载相应的 WADL 文件来发现的。如果WADL 不存在，假定服务不存在。
        """
        services = ["dataselect", "event", "station"]
        # omit manually deactivated services
        for service, custom_target in self._service_mappings.items():
            if custom_target is None:
                services.remove(service)
        urls = [self._build_url(service, "application.wadl")
                for service in services]
        if "event" in services:
            urls.append(self._build_url("event", "catalogs"))
            urls.append(self._build_url("event", "contributors"))
        # Access cache if available.
        url_hash = frozenset(urls)
        if url_hash in self.__service_discovery_cache:
            if self.debug is True:
                print("Loading discovered services from cache.")
            self.services = copy.deepcopy(
                self.__service_discovery_cache[url_hash])
            return

        # Request all in parallel.
        wadl_queue = queue.Queue()

        headers = self.request_headers
        debug = self.debug
        opener = self._url_opener

        def get_download_thread(url):
            class ThreadURL(threading.Thread):
                def run(self):
                    # Catch 404s.
                    try:
                        code, data = download_url(
                            url, opener=opener, headers=headers,
                            debug=debug, timeout=self._timeout)
                        if code == 200:
                            wadl_queue.put((url, data))
                        # Pass on the redirect exception.
                        elif code is None and isinstance(
                                data, FDSNRedirectException):
                            wadl_queue.put((url, data))
                        else:
                            wadl_queue.put((url, None))
                    except urllib_request.HTTPError as e:
                        if e.code in [404, 502]:
                            wadl_queue.put((url, None))
                        else:
                            raise
                    except urllib_request.URLError:
                        wadl_queue.put((url, "timeout"))
                    except socket_timeout:
                        wadl_queue.put((url, "timeout"))
            threadurl = ThreadURL()
            threadurl._timeout = self.timeout
            return threadurl

        threads = list(map(get_download_thread, urls))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.services = {}

        # Collect the redirection exceptions to be able to raise nicer
        # exceptions.
        redirect_messages = set()

        for _ in range(wadl_queue.qsize()):
            item = wadl_queue.get()
            url, wadl = item

            # Just a safety measure.
            if hasattr(wadl, "decode"):
                decoded_wadl = wadl.decode('utf-8')
            else:
                decoded_wadl = wadl

            if wadl is None:
                continue
            elif isinstance(wadl, FDSNRedirectException):
                redirect_messages.add(str(wadl))
                continue
            elif decoded_wadl == "timeout":
                raise FDSNTimeoutException("Timeout while requesting '%s'."
                                           % url)

            if "dataselect" in url:
                wadl_parser = WADLParser(wadl)
                self.services["dataselect"] = wadl_parser.parameters
                # check if EIDA auth endpoint is in wadl
                # we need to attach it to the discovered services, as these are
                # later loaded from cache and just attaching an attribute to
                # this client won't help knowing later if EIDA auth is
                # supported at the server. a bit ugly but can't be helped.
                if wadl_parser._has_eida_auth:
                    self.services["eida-auth"] = True
                if self.debug is True:
                    print("Discovered dataselect service")
            elif "event" in url and "application.wadl" in url:
                self.services["event"] = WADLParser(wadl).parameters
                if self.debug is True:
                    print("Discovered event service")
            elif "station" in url:
                self.services["station"] = WADLParser(wadl).parameters
                if self.debug is True:
                    print("Discovered station service")
            elif "event" in url and "catalogs" in url:
                try:
                    self.services["available_event_catalogs"] = \
                        parse_simple_xml(wadl)["catalogs"]
                except ValueError:
                    msg = "Could not parse the catalogs at '%s'." % url
                    warnings.warn(msg)
            elif "event" in url and "contributors" in url:
                try:
                    self.services["available_event_contributors"] = \
                        parse_simple_xml(wadl)["contributors"]
                except ValueError:
                    msg = "Could not parse the contributors at '%s'." % url
                    warnings.warn(msg)
        if not self.services:
            if redirect_messages:
                raise FDSNRedirectException(", ".join(redirect_messages))

            msg = ("No FDSN services could be discovered at '%s'. This could "
                   "be due to a temporary service outage or an invalid FDSN "
                   "service address." % self.base_url)
            raise FDSNNoServiceException(msg)
        # Cache.
        if self.debug is True:
            print("Storing discovered services in cache.")
        self.__service_discovery_cache[url_hash] = \
            copy.deepcopy(self.services)

    def get_webservice_version(self, service):
        """
        Get full version information of webservice (as a tuple of ints).

        This method is cached and will only be called once for each service
        per client object.
        """
        if service is not None and service not in self.services:
            msg = "Service '%s' not available for current client." % service
            raise ValueError(msg)

        if service not in FDSNWS:
            msg = "Service '%s is not a valid FDSN web service." % service
            raise ValueError(msg)

        # Access cache.
        if service in self.__version_cache:
            return self.__version_cache[service]

        url = self._build_url(service, "version")
        version = self._download(url, return_string=True)
        version = list(map(int, version.split(b".")))

        # Store in cache.
        self.__version_cache[service] = version

        return version

    def _get_webservice_versionstring(self, service):
        """
        Get full version information of webservice as a string.
        """
        version = self.get_webservice_version(service)
        return ".".join(map(str, version))

    def _attach_dataselect_url_to_stream(self, st):
        """
        Attaches the actually used dataselet URL to each Trace.
        """
        url = self._build_url("dataselect", "query")
        for tr in st:
            tr.stats._fdsnws_dataselect_url = url


def convert_to_string(value):
    if isinstance(value, str):
        return value
    # Boolean test must come before integer check!
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, int):
        return str(value)
    elif isinstance(value, float):
        return str(value)
    elif isinstance(value, UTCDateTime):
        return (value + 8 * 36000).strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(value, list):
        str_value = [str(x) for x in value]
        return ",".join(str_value)
    else:
        raise TypeError("Unexpected type %s" % repr(value))


def build_url(base_url, service, major_version, resource_type,
              parameters=None, service_mappings=None, subpath='fdsnws'):
    # Avoid mutable kwargs.
    if parameters is None:
        parameters = {}
    if service_mappings is None:
        service_mappings = {}

    # Only allow certain resource types.
    if service not in ["dataselect", "event", "station"]:
        msg = "Resource type '%s' not allowed. Allowed types: \n%s" % \
            (service, ",".join(("dataselect", "event", "station")))
        raise ValueError(msg)

    # Special location handling.
    if "location" in parameters:
        loc = parameters["location"].replace(" ", "")
        # Empty location.
        if not loc:
            loc = "--"
        # Empty location at start of list.
        if loc.startswith(','):
            loc = "--" + loc
        # Empty location at end of list.
        if loc.endswith(','):
            loc += "--"
        # Empty location in middle of list.
        loc = loc.replace(",,", ",--,")
        parameters["location"] = loc

    # Apply per-service mappings if any.
    if service in service_mappings:
        url = "/".join((service_mappings[service], resource_type))
    else:
        if subpath is None:
            parts = (base_url, service, str(major_version),
                     resource_type)
        else:
            parts = (base_url, subpath.lstrip('/'), service,
                     str(major_version), resource_type)
        url = "/".join(parts)

    if parameters:
        # Strip parameters.
        for key, value in parameters.items():
            try:
                parameters[key] = value.strip()
            except Exception:
                pass
        url = "?".join((url, urlencode(parameters)))
    return url


def raise_on_error(code, data):
    """
    Raise an error for non-200 HTTP response codes

    :type code: int
    :param code: HTTP response code
    :type data: :class:`io.BytesIO`
    :param data: Data returned by the server
    """
    # get detailed server response message
    if code != 200:
        try:
            server_info = data.read()
        except Exception:
            server_info = None
        else:
            server_info = server_info.decode('ASCII', errors='ignore')
        if server_info:
            server_info = "\n".join(
                line for line in server_info.splitlines() if line)
    # No data.
    if code == 204:
        raise FDSNNoDataException("No data available for request.",
                                  server_info)
    elif code == 400:
        msg = ("Bad request. If you think your request was valid "
               "please contact the developers.")
        raise FDSNBadRequestException(msg, server_info)
    elif code == 401:
        raise FDSNUnauthorizedException("Unauthorized, authentication "
                                        "required.", server_info)
    elif code == 403:
        raise FDSNForbiddenException("Authentication failed.",
                                     server_info)
    elif code == 413:
        raise FDSNRequestTooLargeException("Request would result in too much "
                                           "data. Denied by the datacenter. "
                                           "Split the request in smaller "
                                           "parts", server_info)
    # Request URI too large.
    elif code == 414:
        msg = ("The request URI is too large. Please contact the ObsPy "
               "developers.", server_info)
        raise NotImplementedError(msg)
    elif code == 429:
        msg = ("Sent too many requests in a given amount of time ('rate "
               "limiting'). Wait before making a new request.", server_info)
        raise FDSNTooManyRequestsException(msg, server_info)
    elif code == 500:
        raise FDSNInternalServerException("Service responds: Internal server "
                                          "error", server_info)
    elif code == 501:
        raise FDSNNotImplementedException("Service responds: Not implemented ",
                                          server_info)
    elif code == 502:
        raise FDSNBadGatewayException("Service responds: Bad gateway ",
                                      server_info)
    elif code == 503:
        raise FDSNServiceUnavailableException("Service temporarily "
                                              "unavailable",
                                              server_info)
    elif code is None:
        if "timeout" in str(data).lower() or "timed out" in str(data).lower():
            raise FDSNTimeoutException("Timed Out")
        else:
            raise FDSNException("Unknown Error (%s): %s" % (
                (str(data.__class__.__name__), str(data))))
    # Catch any non 200 codes.
    elif code != 200:
        raise FDSNException("Unknown HTTP code: %i" % code, server_info)


def download_url(url, opener, timeout=10, headers={}, debug=False,
                 return_string=True, data=None, use_gzip=True):
    """
    Returns a pair of tuples.

    The first one is the returned HTTP code and the second the data as
    string.

    Will return a tuple of Nones if the service could not be found.
    All encountered exceptions will get raised unless `debug=True` is
    specified.

    Performs a http GET if data=None, otherwise a http POST.
    """
    if debug is True:
        print("Downloading %s %s requesting gzip compression" % (
            url, "with" if use_gzip else "without"))
        if data:
            print("Sending along the following payload:")
            print("-" * 70)
            print(data.decode())
            print("-" * 70)
    try:
        request = urllib_request.Request(url=url, headers=headers)
        # Request gzip encoding if desired.
        if use_gzip:
            request.add_header("Accept-encoding", "gzip")
        url_obj = opener.open(request, timeout=timeout, data=data)
    # Catch HTTP errors.
    except urllib_request.HTTPError as e:
        if debug is True:
            msg = "HTTP error %i, reason %s, while downloading '%s': %s" % \
                  (e.code, str(e.reason), url, e.read())
            print(msg)
        else:
            # Without this line we will get unclosed sockets
            e.read()
        return e.code, e
    except Exception as e:
        if debug is True:
            print("Error while downloading: %s" % url)
        return None, e

    code = url_obj.getcode()

    # Unpack gzip if necessary.
    if url_obj.info().get("Content-Encoding") == "gzip":
        if debug is True:
            print("Uncompressing gzipped response for %s" % url)
        # Cannot directly stream to gzip from urllib!
        # http://www.enricozini.org/2011/cazzeggio/python-gzip/
        try:
            reader = url_obj.read()
        except IncompleteRead:
            msg = 'Problem retrieving data from datacenter. '
            msg += 'Try reducing size of request.'
            raise HTTPException(msg)
        buf = io.BytesIO(reader)
        buf.seek(0, 0)
        f = gzip.GzipFile(fileobj=buf)
    else:
        f = url_obj

    if return_string is False:
        data = io.BytesIO(f.read())
    else:
        data = f.read()

    if debug is True:
        print("Downloaded %s with HTTP code: %i" % (url, code))

    return code, data


def setup_query_dict(service, locs, kwargs):
    """
    """
    # check if alias is used together with the normal parameter
    for key in kwargs:
        if key in PARAMETER_ALIASES:
            if locs[PARAMETER_ALIASES[key]] is not None:
                msg = ("two parameters were provided for the same option: "
                       "%s, %s" % (key, PARAMETER_ALIASES[key]))
                raise FDSNInvalidRequestException(msg)
    # short aliases are not mentioned in the downloaded WADLs, so we have
    # to map it here according to the official FDSN WS documentation
    for key in list(kwargs.keys()):
        if key in PARAMETER_ALIASES:
            value = kwargs.pop(key)
            if value is not None:
                kwargs[PARAMETER_ALIASES[key]] = value

    for param in DEFAULT_PARAMETERS[service]:
        param = PARAMETER_ALIASES.get(param, param)
        value = locs[param]
        if value is not None:
            kwargs[param] = value


def parse_simple_xml(xml_string):
    """
    Simple helper function for parsing the Catalog and Contributor availability
    files.

    Parses XMLs of the form::

        <Bs>
            <total>4</total>
            <B>1</B>
            <B>2</B>
            <B>3</B>
            <B>4</B>
        </Bs>

    and return a dictionary with a single item::

        {"Bs": set(("1", "2", "3", "4"))}
    """
    root = etree.fromstring(xml_string.strip())

    if not root.tag.endswith("s"):
        msg = "Could not parse the XML."
        raise ValueError(msg)
    child_tag = root.tag[:-1]
    children = [i.text for i in root if i.tag == child_tag]

    return {root.tag.lower(): set(children)}


def get_bulk_string(bulk, arguments):
    if not bulk:
        msg = ("Empty 'bulk' parameter potentially leading to a FDSN request "
               "of all available data")
        raise FDSNInvalidRequestException(msg)
    # If its an iterable, we build up the query string from it
    # StringIO objects also have __iter__ so check for 'read' as well
    if isinstance(bulk, collections_abc.Iterable) \
            and not hasattr(bulk, "read") \
            and not isinstance(bulk, str):
        tmp = ["%s=%s" % (key, convert_to_string(value))
               for key, value in arguments.items() if value is not None]
        # empty location codes have to be represented by two dashes
        tmp += [" ".join((net, sta, loc or "--", cha,
                          convert_to_string(t1), convert_to_string(t2)))
                for net, sta, loc, cha, t1, t2 in bulk]
        bulk = "\n".join(tmp)
    else:
        if any([value is not None for value in arguments.values()]):
            msg = ("Parameters %s are ignored when request data is "
                   "provided as a string or file!")
            warnings.warn(msg % arguments.keys())
        # if it has a read method, read data from there
        if hasattr(bulk, "read"):
            bulk = bulk.read()
        elif isinstance(bulk, str):
            # check if bulk is a local file
            if "\n" not in bulk and os.path.isfile(bulk):
                with open(bulk, 'r') as fh:
                    tmp = fh.read()
                bulk = tmp
            # just use bulk as input data
            else:
                pass
        else:
            msg = ("Unrecognized input for 'bulk' argument. Please "
                   "contact developers if you think this is a bug.")
            raise NotImplementedError(msg)

    if hasattr(bulk, "encode"):
        bulk = bulk.encode("ascii")
    return bulk


def _validate_eida_token(token):
    """
    Just a basic check if the string contains something that looks like a PGP
    message
    """
    if re.search(pattern='BEGIN PGP MESSAGE', string=token,
                 flags=re.IGNORECASE):
        return True
    elif re.search(pattern='BEGIN PGP SIGNED MESSAGE', string=token,
                   flags=re.IGNORECASE):
        return True
    return False


if __name__ == '__main__':
    client = Client(sa_token="42936707-b2de-43de-b25c-8da50daca6e8")

    # 通过Client获取波形数据
    st = client.get_waveforms([1], [1], [1, 2, 3], UTCDateTime("2023-03-07 12:00:00"), UTCDateTime("2023-03-07 12:10:00"))
    print(st)

    # 通过Client去获取站点数据
    inventory = client.get_stations([1], [1], [1])
    print(inventory)

    # 通过Client获取事件数据
    t1 = UTCDateTime("2023-02-19T04:12:10")
    t2 = UTCDateTime("2023-02-19T09:12:10")
    events = client.get_events(startTime="2023-02-19 12:12:10", endTime="2023-02-19 17:12:13")
    print(events)
    # data_stream.seek(0, 0)
    # st = obspy.read(data_stream, format="MSEED")
    # data_stream.close()
    # print(st)

