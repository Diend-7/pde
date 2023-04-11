import copy
import os
import re
import textwrap
import threading

import queue
import obspy
from obspy import read_inventory
from obspy.clients.fdsn.header import (DEFAULT_USER_AGENT, FDSNWS,
                     URL_MAPPING_SUBPATHS,
                     WADL_PARAMETERS_NOT_TO_BE_PARSED,
                    FDSNRedirectException,
                     FDSNTimeoutException,
                     FDSNNoServiceException,
                     FDSNDoubleAuthenticationException)
from obspy.clients.fdsn.wadl_parser import WADLParser
from collections import OrderedDict
from socket import timeout as socket_timeout
from pde.constant import *
from pde.util import *


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

    def __init__(self, base_url="MAP", major_versions=None, user_agent=DEFAULT_USER_AGENT, debug=False,
                 timeout=120, service_mappings=None, force_redirect=False,
                 sa_token=None, _discover_services=True):

        self.debug = debug
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
        self.url_subpath = DEFAULT_SUB_PATH
        # 如果输入了用户名密码则需要加入认证处理
        self._set_opener()

        self.request_headers = {"User-Agent": user_agent}
        # Avoid mutable kwarg.
        if major_versions is None:
            major_versions = {}
        # Make a copy to avoid overwriting the default service versions.
        self.major_versions = DEFAULT_SERVICE_VERSIONS.copy()
        self.major_versions.update(major_versions)

        self.sa_token = sa_token
        # 如果指定token了就使用用户指定的token
        if self.sa_token is not None:
            # 将token加入到请求头里面
            self.set_eida_token(self.sa_token)
            # 先判断用户输入的token是否合法，不合法会抛出异常
            self._validate_token()
            # 将用户这次输入的token保存到本地
            self._save_token_local()
        else:
            # 没有指定则会去从本地获取，获取失败也会抛异常
            self._get_token_local()
            # 将token加入到请求头里面
            self.set_eida_token(self.sa_token)


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

    def _set_opener(self):
        # Only add the authentication handler if required.
        handlers = []
        handlers.append(CustomRedirectHandler())
        self._url_opener = urllib_request.build_opener(*handlers)
        if self.debug:
            print('Installed new opener with handlers: {!s}'.format(handlers))

    def get_map_waveforms(self, site, dataType=None, device=None, startTime=None,
                          endTime=None, filename=None, attach_response=False, **kwargs):

        if "dataselect1" not in self.services:
            msg = "The current client does not have a dataselect1 service."
            raise ValueError(msg)
        if dataType is None:
            dataType = []
        if device is None:
            device = []
        locs = locals()
        setup_query_dict('dataselect1', locs, kwargs)

        # Special location handling. Convert empty strings to "--".
        # if "location" in kwargs and not kwargs["location"]:
        #     kwargs["location"] = "--"

        url = self._create_url_from_parameters(
            "dataselect1", DEFAULT_PARAMETERS['dataselect1'], kwargs)
        # url = "http://localhost:38085/dataselect/1/query?site=1&dataType=1&device=1%2C2&startTime=2023-03-07+12%3A00%3A00&endTime=2023-03-07+12%3A00%3A01"
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
            self._attach_dataselect_url_to_stream("dataselect1", st)
            # st.trim(startTime, endTime)
            return st

    def get_obspy_waveforms(self, network="*", station="*", location="*", channel="*", startTime=None,
                          endTime=None, filename=None, attach_response=False, **kwargs):

        if "dataselect2" not in self.services:
            msg = "The current client does not have a dataselect2 service."
            raise ValueError(msg)
        locs = locals()
        setup_query_dict('dataselect2', locs, kwargs)

        # Special location handling. Convert empty strings to "--".
        # if "location" in kwargs and not kwargs["location"]:
        #     kwargs["location"] = "--"

        url = self._create_url_from_parameters(
            "dataselect2", DEFAULT_PARAMETERS['dataselect2'], kwargs)
        # url = "http://localhost:38085/dataselect/1/query?site=1&dataType=1&device=1%2C2&startTime=2023-03-07+12%3A00%3A00&endTime=2023-03-07+12%3A00%3A01"
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
            self._attach_dataselect_url_to_stream("dataselect2", st)
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
        code, message, data = download_url(
            url, opener=self._url_opener, headers=headers,
            debug=self.debug, return_string=return_string, data=data,
            timeout=self.timeout, use_gzip=use_gzip)
        raise_on_error(code, data, message)
        return data

    def _build_url(self, service, resource_type, parameters={}):
        """
        Builds the correct URL.

        Replaces "query" with "queryauth" if client has authentication
        information.
        """

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

    def _attach_dataselect_url_to_stream(self,service, st):
        """
        Attaches the actually used dataselet URL to each Trace.
        """
        url = self._build_url(service, "query")
        for tr in st:
            tr.stats._fdsnws_dataselect_url = url

    def _validate_token(self):
        """
        检查token是否有效
        :return:
        """
        headers = self.request_headers.copy()
        code, message, data = download_url(
            IS_LOGIN_URL, opener=self._url_opener, headers=headers,
            debug=self.debug, timeout=self.timeout)
        # 只要code不是200就是token存在问题
        if code != 200:
            raise FDSNException("There is a problem with your token, if this is your first time using it, \n"
                                "please go to 'http://10.99.12.109:38090/login' to register an account to get the \n "
                                "token, and initialize the token the first time you use it. The specific reasons are:\n"
                                + message)

    def _get_token_local(self):
        """
        从本地获取token
        :return:
        """
        user_home = os.path.expanduser('~')
        file_path = user_home + "\\pde\\token"
        if not os.path.exists(file_path):
            raise FDSNException("There is no token locally, if this is your first time using it, \n please go to "
                                "'http://10.99.12.109:38090/login' to register an account to get the token, \n and "
                                "initialize the token the first time you use it.")
        with open(file_path) as f:
            token = f.read()
        self.sa_token = token

    def _save_token_local(self):
        user_home = os.path.expanduser('~')
        dir = user_home + "\\pde"
        if not os.path.exists(dir):
            os.mkdir(dir)
        file_path = dir + "\\token"
        with open(file_path, "w") as f:
            f.write(self.sa_token)


if __name__ == '__main__':
    client = Client()


    # 通过Client获取波形数据
    st = client.get_map_waveforms([1], [1], [1, 2], startTime=UTCDateTime("2023-03-07 12:00:01"), endTime=UTCDateTime("2023-03-07 12:01:00"))
    print(st)

    # 对数据进行绘图
    for trace in st:
        trace.plot()

    # st1 = client.get_obspy_waveforms(station="I57*", startTime="2023-04-08 12:00:00", endTime="2023-04-08 12:00:01")
    # print(st1)
    # 通过Client去获取站点数据
    inventory = client.get_stations([1], [1], [1])
    print(inventory)

    net = inventory[0]
    print(net)
    # 获取所有的站点信息
    for station in net:
        print(station)

    # 通过Client获取事件数据
    t1 = UTCDateTime("2023-02-19T04:12:10")
    t2 = UTCDateTime("2023-02-19T09:12:10")
    events = client.get_events(startTime="2023-02-19 12:12:10", endTime="2023-02-19 17:12:13")
    print(events)

    # 获取所有的事件信息
    for event in events:
        print(event)
    # data_stream.seek(0, 0)
    # st = obspy.read(data_stream, format="MSEED")
    # data_stream.close()
    # print(st)

