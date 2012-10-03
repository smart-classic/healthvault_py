# pyhv: A Pythonic Interface to the Microsoft HealthVault XML-over-HTTP API
#
# Arjun Sanyal <arjun.sanyal@childrens.harvard.edu>
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

        response = self._send_request(payload)
        auth_response = response.read()
        dom = minidom.parseString(auth_response)
        #if DEBUG:
            #self._pretty_print_dom(dom)
        # stop the unicode infection with str()!
        self._auth_token = str(self._get_single_el_value(dom, 'token'))
        self._shared_secret = str(self._get_single_el_value(dom, 'shared-secret'))

    def __init__(self, _user_auth_token):
        self._user_auth_token = str(_user_auth_token)
        self._init_private_key()
        self._authenticate()
        self.getPersonInfo()

    # note: method names match the HV API but with a leading lowercase letter
    def getPersonInfo(self):
        # create the complete <header>
        header_tmpl = string.Template("""<header><method>GetPersonInfo</method><method-version>1</method-version><auth-session><auth-token>$AUTH_TOKEN</auth-token><user-auth-token>$USER_AUTH_TOKEN</user-auth-token></auth-session><language>en</language><country>US</country><msg-time>$NOW</msg-time><msg-ttl>$TTL</msg-ttl><version>$VERSION</version><info-hash><hash-data algName="SHA256">$HASH_DATA</hash-data></info-hash></header>""")

        info_str = '<info></info>'
        hash_data_str = base64.b64encode(hashlib.sha256(info_str).digest()).strip()

        header_str = header_tmpl.substitute({
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
            raise 'Non-zero return code in getPersonInfo'
        else:
            self.person.person_id = self._get_single_el_value(dom, 'person-id')
            self.person.name = self._get_single_el_value(dom, 'name')
            # todo: extract more record data here
            self.person.selected_record_id = self._get_single_el_value(dom, 'selected-record-id')
            self._record_id = self.person.selected_record_id
        #if DEBUG:
            #print person.person_id
            #print person.name

    def getThings(self, type):
        # todo: hardcoding for now... refactor with above
        # need to supply some context here: either record, person or app id
        # potentially same has header_tmpl above then
        header_tmpl = string.Template("""<header><method>GetThings</method><method-version>1</method-version><record-id>$RECORD_ID</record-id><auth-session><auth-token>$AUTH_TOKEN</auth-token><user-auth-token>$USER_AUTH_TOKEN</user-auth-token></auth-session><language>en</language><country>US</country><msg-time>$NOW</msg-time><msg-ttl>$TTL</msg-ttl><version>$VERSION</version><info-hash><hash-data algName="SHA256">$HASH_DATA</hash-data></info-hash></header>""")

        # this is the query
        info_str = \
        '<info><group><filter><type-id>'+type+'</type-id></filter><format></format></group></info>'
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
            self.person.weights.append((date, weight_in_kg))
