#
# healthvault: A Pythonic Interface to the Microsoft HealthVault's API
#
# Arjun Sanyal <arjun.sanyal@childrens.harvard.edu>
#
# note: method names match the HV API but with a leading lowercase letter
#
# Todo
# - refactor using lxml's CSSSelectors (see 'csss') and E-factory?
#   <http://lxml.de/tutorial.html#the-e-factory>
# - add newlines and spacing to the templates
# - do a regex compacting multiple spaces and newlines
import base64
from   Crypto.Signature import PKCS1_v1_5
from   Crypto.Hash import SHA
from   Crypto.PublicKey import RSA
import datetime
import hashlib
import hmac
import httplib
from   lxml import etree
from   lxml.cssselect import CSSSelector as csss
import pdb
import re
import settings
import socket
import string
from   xml.dom import minidom

DEBUG = True
LOG_XML = True

class HVPerson(object):
    person_id = None
    name = None
    selected_record_id = None
    gender = None # m or f
    birth_year = None
    weights = []

class HVConn(object):
    _user_auth_token = None
    _auth_token = None
    _record_id = None
    _app_specific_record_id = None
    _shared_secret = None
    _private_key = None
    _version = '2.0.0.0'
    _language = 'en'
    _country = 'US'
    _ttl = '1800'

    person = HVPerson()

    def _get_single_el_value(self, dom, tag_name):
        el = dom.getElementsByTagName(tag_name)[0]
        return el.firstChild.nodeValue

    def _pretty_print_dom(self, dom):
        print dom.toprettyxml(indent='  ')

    def _pretty_print_xml_str(self, s):
        self._pretty_print_dom(minidom.parseString(s))

    def _now_in_iso(self):
        return datetime.datetime.utcnow().isoformat()

    def _init_private_key(self):
        self._private_key = RSA.construct((
            long(settings.APP_PUBLIC_KEY, 16),
            long(65537),
            long(settings.APP_PRIVATE_KEY, 16)
        ))

    def _sign(self, data):
        signer = PKCS1_v1_5.new(self._private_key)
        return base64.encodestring(signer.sign(SHA.new(data)))

    def _send_request(self, payload):
        conn = httplib.HTTPSConnection(settings.HV_SERVICE_SERVER, 443)
        conn.putrequest('POST', '/platform/wildcat.ashx')
        conn.putheader('Content-Type', 'text/xml')
        conn.putheader('Content-Length', '%d' % len(payload))
        conn.endheaders()
        try:
            conn.send(payload)
        except socket.error, v:
            if v[0] == 32:      # Broken pipe
                conn.close()
            raise
        resp = conn.getresponse()
        if resp.status != 200:
            raise
        else:
            return resp

    def _send_request_and_get_dom(self, payload):
        conn = httplib.HTTPSConnection(settings.HV_SERVICE_SERVER, 443)
        conn.putrequest('POST', '/platform/wildcat.ashx')
        conn.putheader('Content-Type', 'text/xml')
        conn.putheader('Content-Length', '%d' % len(payload))
        conn.endheaders()
        try:
            conn.send(payload)
        except socket.error, v:
            if v[0] == 32:      # Broken pipe
                conn.close()
            raise
        resp = conn.getresponse()
        if resp.status != 200:
            raise
        else:
            dom = minidom.parseString(resp.read())
            if DEBUG:
                print self._pretty_print_dom(dom)

            el = dom.getElementsByTagName('code')[0]
            code = self._get_single_el_value(dom, 'code')
            if code != '0':
                raise 'Non-zero return code in _send_request_and_get_dom()'
            else:
                return dom

    def _authenticate(self):
        content_tmpl = string.Template("""
            <content>
                <app-id>$APP_ID</app-id>
                <hmac>HMACSHA256</hmac>
                <signing-time>$NOW</signing-time>
            </content>
        """)

        content_str = content_tmpl.substitute({
            'APP_ID': settings.APP_ID,
            'NOW': self._now_in_iso()
        }).translate(None, '\n ')

        t = string.Template("""
            <wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">
                <header>
                    <method>CreateAuthenticatedSessionToken</method>
                    <method-version>2</method-version>
                    <app-id>$APP_ID</app-id>
                    <msg-time>$NOW</msg-time>
                    <msg-ttl>$MSG_TTL</msg-ttl>
                    <version>$VERSION</version>
                </header>
                <info>
                    <auth-info>
                        <app-id>$APP_ID</app-id>
                        <credential>
                            <appserver2>
                                <sig digestMethod="SHA1"
                                     sigMethod="RSA-SHA1"
                                     thumbprint="$APP_THUMBPRINT">
                                        $SIGNATURE
                                </sig>
                                $CONTENT
                            </appserver2>
                        </credential>
                    </auth-info>
                </info>
            </wc-request:request>""")

        payload = t.substitute({
            'APP_ID': settings.APP_ID,
            'NOW': self._now_in_iso(),
            'MSG_TTL': self._ttl,
            'VERSION': self._version,
            'APP_THUMBPRINT': settings.APP_THUMBPRINT,
            'SIGNATURE': self._sign(content_str),
            'CONTENT': content_str

        }).translate(None, '\n')

        dom = self._send_request_and_get_dom(payload)
        self._auth_token = str(self._get_single_el_value(dom, 'token'))
        self._shared_secret = str(self._get_single_el_value(dom, 'shared-secret'))

    def __init__(self, user_auth_token=None):
        self._init_private_key()
        self._authenticate()

        if user_auth_token:
            self._user_auth_token = str(user_auth_token)
            self.getPersonInfo()

    def _build_header(self, method, method_version, hash_data, record_id=None):
        """ Create the header string. record_id is optional """
        header = '<header><method>$METHOD</method><method-version>$METHOD_VERSION</method-version>'
        if record_id:
            header = header + '<record-id>'+record_id+'</record-id>'
        header = header + '<auth-session><auth-token>$AUTH_TOKEN</auth-token><user-auth-token>$USER_AUTH_TOKEN</user-auth-token></auth-session><language>$LANGUAGE</language><country>$COUNTRY</country><msg-time>$NOW</msg-time><msg-ttl>$TTL</msg-ttl><version>$VERSION</version><info-hash><hash-data algName="SHA256">$HASH_DATA</hash-data></info-hash></header>'
        return string.Template(header).substitute({
            'METHOD': method,
            'METHOD_VERSION': method_version,
            'AUTH_TOKEN': self._auth_token,
            'USER_AUTH_TOKEN': self._user_auth_token,
            'LANGUAGE': self._language,
            'COUNTRY': self._country,
            'NOW': self._now_in_iso(),
            'TTL': self._ttl,
            'VERSION': self._version,
            'HASH_DATA': hash_data,
            'RECORD_ID': record_id
        })

    def _build_header_hmac(self, header):
        h = hmac.new(base64.b64decode(self._shared_secret),
                     header,
                     hashlib.sha256)
        return base64.b64encode(h.digest())

    def _build_request(self, header, info):
        # NOTE: don't add spaces and newlines here!
        req_tmpl = string.Template("""<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request"><auth><hmac-data algName="HMACSHA256">$HMAC</hmac-data></auth>$HEADER$INFO</wc-request:request>""")
        return req_tmpl.substitute({
            'HMAC': self._build_header_hmac(header),
            'HEADER': header,
            'INFO': info
        })

    def _create_request(self, info, method, method_version='1', record_id=None):
        hash_data = base64.b64encode(hashlib.sha256(info).digest()).strip()
        header = self._build_header(method=method,
                                    method_version=method_version,
                                    hash_data=hash_data,
                                    record_id=record_id)
        return self._build_request(header, info)

    def getPersonInfo(self):
        # TODO: extract more record data
        # <record app-record-auth-action="NoActionRequired" app-specific-record-id="218697" auth-expires="9999-12-31T23:59:59.999Z" date-created="2012-09-19T16:07:52.507Z" date-updated="2012-09-24T19:22:00.877Z" display-name="Arjun" id="f9982b79-4369-4357-8268-0b344941ab02" location-country="US" max-size-bytes="4294967296" record-custodian="true" rel-name="Self" rel-type="1" size-bytes="3167" state="Active">
        dom = self._send_request_and_get_dom(
            self._create_request('<info></info>', 'GetPersonInfo')
        )
        self.person.person_id = self._get_single_el_value(dom, 'person-id')
        self.person.name = self._get_single_el_value(dom, 'name')
        self.person.selected_record_id = self._get_single_el_value(
                                            dom,
                                            'selected-record-id')
        self._record_id = self.person.selected_record_id

    def getThings(self, type):
        info = \
            '<info><group><filter><type-id>'+type+'</type-id></filter><format></format></group></info>'
        return self._send_request_and_get_dom(
            self._create_request(info,
                                 'GetThings',
                                 record_id=self._record_id)
        )

    def getThingById(self, id):
        # todo: hardcoding for now... refactor with above
        # need to supply some context here: either record, person or app id
        # potentially same has header_tmpl above then
        header_tmpl = string.Template("""<header><method>GetThings</method><method-version>1</method-version><record-id>$RECORD_ID</record-id><auth-session><auth-token>$AUTH_TOKEN</auth-token><user-auth-token>$USER_AUTH_TOKEN</user-auth-token></auth-session><language>en</language><country>US</country><msg-time>$NOW</msg-time><msg-ttl>$TTL</msg-ttl><version>$VERSION</version><info-hash><hash-data algName="SHA256">$HASH_DATA</hash-data></info-hash></header>""")

        # this is the query: note: added "<section>core</section>", maybe can add to above?
        # do we need <xml/>?? Yes we do! It would be awesome if that was
        # not '<xml />*' in the spec
        info_str = '<info><group><id>'+id+'</id><format><section>core</section><xml/></format></group></info>'
        hash_data_str = base64.b64encode(hashlib.sha256(info_str).digest()).strip()

        header_str = header_tmpl.substitute({
            'RECORD_ID': self._record_id,
            'AUTH_TOKEN': self._auth_token,
            'USER_AUTH_TOKEN': self._user_auth_token,
            'NOW': self._now_in_iso(),
            'TTL': self._ttl,
            'VERSION': self._version,
            'HASH_DATA': hash_data_str
        })

        # hmac the complete <header> (don't forget to b64 decode the secret)
        h = hmac.new(base64.b64decode(self._shared_secret),
                header_str,
                hashlib.sha256)
        hmac_data_str = base64.b64encode(h.digest())

        # build the final <request>
        req_tmpl = string.Template("""<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request"><auth><hmac-data algName="HMACSHA256">$HMAC</hmac-data></auth>$HEADER$INFO</wc-request:request>""")
        req_str = req_tmpl.substitute({
            'HMAC': hmac_data_str,
            'HEADER': header_str,
            'INFO': info_str
        })

        #req_str = re.sub(' {2,}', '', req_str.strip())
        #print '---\n'+req_str+'\n---'
        response = self._send_request(req_str)
        dom = minidom.parseString(response.read())
        if DEBUG:
            print self._pretty_print_dom(dom)

        el = dom.getElementsByTagName('code')[0]
        code = str(el.firstChild.nodeValue)
        code = self._get_single_el_value(dom, 'code')
        if code != '0':
            raise # 'Non-zero return code in getPersonInfo'
        else:
            return dom

    def getBasicDemographicInformation(self):
        dom = self.getThings('bf516a61-5252-4c28-a979-27f45f62f78d')
        thing_id_els = dom.getElementsByTagName('thing-id')
        for thing_id_el in thing_id_els:
            thing = self.getThingById(thing_id_el.firstChild.nodeValue)
            root = etree.fromstring(thing.toxml())
            self.person.gender = csss('gender')(root)[0].text
            self.person.birth_year = csss('birthyear')(root)[0].text

    def getWeightMeasurements(self):
        dom = self.getThings('3d34d87e-7fc1-4153-800f-f56592cb0d17')
        thing_id_els = dom.getElementsByTagName('thing-id')

        # clear weights
        self.person.weights = []

        for thing_id_el in thing_id_els:
            thing = self.getThingById(thing_id_el.firstChild.nodeValue)

            if DEBUG and LOG_XML:
                self._pretty_print_dom(thing)

            root = etree.fromstring(thing.toxml())
            y = csss('y')(root)[0].text
            m = csss('m')(root)[0].text
            d = csss('d')(root)[0].text
            # todo: add time
            date = datetime.date(int(y), int(m), int(d)).isoformat()
            weight_in_kg = csss('kg')(root)[0].text

    def createConnectRequest(self, external_id, friendly_name, secret_q, secret_a):
        header_tmpl = string.Template("""<header><method>CreateConnectRequest</method><method-version>1</method-version><auth-session><auth-token>$AUTH_TOKEN</auth-token></auth-session><language>en</language><country>US</country><msg-time>$NOW</msg-time><msg-ttl>$TTL</msg-ttl><version>$VERSION</version><info-hash><hash-data algName="SHA256">$HASH_DATA</hash-data></info-hash></header>""")

        info_tmpl = string.Template('<info><friendly-name>$FRIENDLY_NAME</friendly-name><question>$QUESTION</question><answer>$ANSWER</answer><external-id>$EXTERNAL_ID</external-id></info>')
        info_str = info_tmpl.substitute({
            'FRIENDLY_NAME': friendly_name,
            'QUESTION': secret_q,
            'ANSWER': secret_a,
            'EXTERNAL_ID': external_id
        })

        hash_data_str = base64.b64encode(hashlib.sha256(info_str).digest()).strip()

        header_str = header_tmpl.substitute({
            'AUTH_TOKEN': self._auth_token,
            'NOW': self._now_in_iso(),
            'TTL': self._ttl,
            'VERSION': self._version,
            'HASH_DATA': hash_data_str
        })

        # hmac the complete <header> (don't forget to b64 decode the secret)
        h = hmac.new(base64.b64decode(self._shared_secret),
                header_str,
                hashlib.sha256)
        hmac_data_str = base64.b64encode(h.digest())

        # build the final <request>
        req_tmpl = string.Template("""<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request"><auth><hmac-data algName="HMACSHA256">$HMAC</hmac-data></auth>$HEADER$INFO</wc-request:request>""")
        req_str = req_tmpl.substitute({
            'HMAC': hmac_data_str,
            'HEADER': header_str,
            'INFO': info_str
        })

        #print '---\n'+req_str+'\n---'
        response = self._send_request(req_str)

        dom = minidom.parseString(response.read())
        if DEBUG:
            print self._pretty_print_dom(dom)

        el = dom.getElementsByTagName('code')[0]
        code = self._get_single_el_value(dom, 'code')
        if code != '0':
            raise # 'Non-zero return code
        else:
            root = etree.fromstring(dom.toxml())
            return csss('identity-code')(root)[0].text
