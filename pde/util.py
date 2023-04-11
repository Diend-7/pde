import gzip
import io
import json
import os
import warnings
import urllib.request as urllib_request
from obspy import UTCDateTime
from obspy.core.compatibility import collections_abc
from obspy.clients.fdsn.header import (FDSNException,
                                       FDSNNoDataException,
                                       FDSNTimeoutException,
                                     FDSNBadRequestException,
                                     FDSNInternalServerException,
                                     FDSNNotImplementedException,
                                     FDSNBadGatewayException,
                                     FDSNTooManyRequestsException,
                                     FDSNRequestTooLargeException,
                                     FDSNServiceUnavailableException,
                                     FDSNUnauthorizedException,
                                     FDSNForbiddenException,
                                     FDSNInvalidRequestException)
from constant import PARAMETER_ALIASES, DEFAULT_PARAMETERS
from urllib.parse import urlencode
from http.client import HTTPException, IncompleteRead
from lxml import etree


def convert_to_string(value):
    """
    将一些数据类型强制转换成string 类型
    :param value: 目前支持的类型， bool,int,float,UTCDateTime, list
    :return: 字符串类型的数据
    """
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
        return (value + 8 * 3600).strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(value, list):
        str_value = [str(x) for x in value]
        return ",".join(str_value)
    else:
        raise TypeError("Unexpected type %s" % repr(value))


def build_url(base_url, service, major_version, resource_type,
              parameters=None, service_mappings=None, subpath='map'):
    """
    将一些参数拼接成需要请求的链接，url
    :param base_url: 最基本的url
    :param service: 服务类型，目前只有3个dataselect,station,event
    :param major_version: 版本号 1
    :param resource_type:
    :param parameters: 需要拼接的参数
    :param service_mappings:
    :param subpath: 所属服务
    :return:
    """
    # Avoid mutable kwargs.
    if parameters is None:
        parameters = {}
    if service_mappings is None:
        service_mappings = {}

    # Only allow certain resource types.
    if service not in ["dataselect1", "dataselect2", "event", "station"]:
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


def raise_on_error(code, data, message=None):
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
        else:
            server_info = message
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
        return e.code, e, None
    except Exception as e:
        if debug is True:
            print("Error while downloading: %s" % url)
        return None, e, None

    code = url_obj.getcode()
    # 如果请求得到的资源不是文件或者xml，则检查是没有登入还是什么token等出现了问题
    if code == 200 and url_obj.info().get("Content-Type") == "text/plain; charset=utf-8":
        data = url_obj.read()
        data = json.loads(data)
        code = data.get("code")
        message = data.get("message")
        data = data.get("data")
        return code, message, data

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

    return code, None, data


def setup_query_dict(service, locs, kwargs):
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