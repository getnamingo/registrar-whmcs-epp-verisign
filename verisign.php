<?php
/**
 * Namingo EPP registrar module for WHMCS (https://www.whmcs.com/)
 *
 * Written in 2024 by Taras Kondratyuk (https://getpinga.com)
 * Based on Generic EPP with DNSsec Registrar Module for WHMCS written in 2019 by Lilian Rudenco (info@xpanel.com)
 * Work of Lilian Rudenco is under http://opensource.org/licenses/afl-3.0.php Academic Free License (AFL 3.0)
 *
 * @license MIT
 */
if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;
use WHMCS\Carbon;
use WHMCS\Domain\Registrar\Domain;

function verisign_MetaData()
{
    return array(
        'DisplayName' => 'VeriSign EPP Registry',
        'APIVersion' => '1.1',
    );
}

function _verisign_error_handler($errno, $errstr, $errfile, $errline)
{
    if (!preg_match("/epp/i", $errfile)) {
        return true;
    }

    _verisign_log("Error $errno:", "$errstr on line $errline in file $errfile");
}

set_error_handler('_verisign_error_handler');
_verisign_log('================= ' . date("Y-m-d H:i:s") . ' =================');

function verisign_getConfigArray($params = array())
{
    _verisign_log(__FUNCTION__, $params);

    $configarray = array(
        'FriendlyName' => array(
            'Type' => 'System',
            'Value' => 'VeriSign EPP',
        ),
        'Description' => array(
            'Type' => 'System',
            'Value' => 'This module supports all gTLDs that use the VeriSign platform.',
        ),
        'host' => array(
            'FriendlyName' => 'EPP Server',
            'Type' => 'text',
            'Size' => '32',
            'Description' => 'EPP Server Host.'
        ),
        'port' => array(
            'FriendlyName' => 'Server Port',
            'Type' => 'text',
            'Size' => '4',
            'Default' => '700',
            'Description' => 'System port number 700 has been assigned by the IANA for mapping EPP onto TCP.'
        ),
        'tls_version' => array(
            'FriendlyName' => 'Use TLS v1.3',
            'Type' => 'yesno',
            'Description' => 'Use more secure TLS v1.3 if the registry supports it.'
        ),
        'verify_peer' => array(
            'FriendlyName' => 'Verify Peer',
            'Type' => 'yesno',
            'Description' => 'Require verification of SSL certificate used.'
        ),
        'cafile' => array(
            'FriendlyName' => 'CA File',
            'Type' => 'text',
            'Default' => '',
            'Description' => 'Certificate Authority file which should be used with the verify_peer context option <br />to authenticate the identity of the remote peer.'
        ),
        'local_cert' => array(
            'FriendlyName' => 'Certificate',
            'Type' => 'text',
            'Default' => 'cert.pem',
            'Description' => 'Local certificate file. It must be a PEM encoded file.'
        ),
        'local_pk' => array(
            'FriendlyName' => 'Private Key',
            'Type' => 'text',
            'Default' => 'key.pem',
            'Description' => 'Private Key.'
        ),
        'passphrase' => array(
            'FriendlyName' => 'Pass Phrase',
            'Type' => 'password',
            'Size' => '32',
            'Description' => 'Enter pass phrase with which your certificate file was encoded.'
        ),
        'clid' => array(
            'FriendlyName' => 'Client ID',
            'Type' => 'text',
            'Size' => '20',
            'Description' => 'Client identifier.'
        ),
        'pw' => array(
            'FriendlyName' => 'Password',
            'Type' => 'password',
            'Size' => '20',
            'Description' => "Client's plain text password."
        ),
        'registrarprefix' => array(
            'FriendlyName' => 'Registrar Prefix',
            'Type' => 'text',
            'Size' => '4',
            'Description' => 'Registry assigns each registrar a unique prefix with which that registrar must create contact IDs.'
        )
    );
    return $configarray;
}

function _verisign_startEppClient($params = array())
{
    $s = new verisign_epp_client($params);
    $s->login($params['clid'], $params['pw'], $params['registrarprefix']);
    return $s;
}

function verisign_RegisterDomain($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ clTRID }}/';
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <domain:check
        xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:check>
    </check>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->chkData;
        $reason = (string)$r->cd[0]->reason;
        if (!$reason) {
            $reason = 'Domain is not available';
        }

        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            throw new exception($r->cd[0]->name . ' ' . $reason);
        }

        foreach(array(
            'ns1',
            'ns2',
            'ns3',
            'ns4',
            'ns5'
        ) as $ns) {
            if (empty($params["{$ns}"])) {
                continue;
            }

        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params["{$ns}"]);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <host:check
        xmlns:host="urn:ietf:params:xml:ns:host-1.0"
        xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
        <host:name>{{ name }}</host:name>
      </host:check>
    </check>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            continue;
        }

        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params["{$ns}"]);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <host:create
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:create>
    </create>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
}

        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ period }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ ns1 }}/';
        $to[] = htmlspecialchars($params['ns1']);
        $from[] = '/{{ ns2 }}/';
        $to[] = htmlspecialchars($params['ns2']);
        $from[] = '/{{ ns3 }}/';
        $to[] = htmlspecialchars($params['ns3']);
        $from[] = '/{{ ns4 }}/';
        $to[] = htmlspecialchars($params['ns4']);
        $from[] = '/{{ ns5 }}/';
        $to[] = htmlspecialchars($params['ns5']);
        $from[] = '/{{ authInfo }}/';
        $to[] = htmlspecialchars($s->generateObjectPW());
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-create-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <domain:create
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ period }}</domain:period>
        <domain:ns>
          <domain:hostObj>{{ ns1 }}</domain:hostObj>
          <domain:hostObj>{{ ns2 }}</domain:hostObj>
          <domain:hostObj>{{ ns3 }}</domain:hostObj>
          <domain:hostObj>{{ ns4 }}</domain:hostObj>
          <domain:hostObj>{{ ns5 }}</domain:hostObj>
        </domain:ns>
        <domain:authInfo>
          <domain:pw>{{ authInfo }}</domain:pw>
        </domain:authInfo>
      </domain:create>
    </create>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        
        // Check if the required module 'whmcs_registrar' is active
        if (!Capsule::table('tbladdonmodules')->where('module', 'whmcs_registrar')->exists()) {
            // Log an error if the module is not active
            _verisign_log('Error: Required module is not active.');
        }

        // Insert domain
        verisign_insertDomain($params, []);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_RenewDomain($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $expDate = (string)$r->exDate;
        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ regperiod }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ expDate }}/';
        $to[] = htmlspecialchars($expDate);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-renew-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <renew>
      <domain:renew
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:curExpDate>{{ expDate }}</domain:curExpDate>
        <domain:period unit="y">{{ regperiod }}</domain:period>
      </domain:renew>
    </renew>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_TransferDomain($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $from[] = '/{{ years }}/';
        $to[] = htmlspecialchars($params['regperiod']);
        $from[] = '/{{ authInfo_pw }}/';
        $to[] = htmlspecialchars($params['transfersecret']);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="request">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ years }}</domain:period>
        <domain:authInfo>
          <domain:pw>{{ authInfo_pw }}</domain:pw>
        </domain:authInfo>
      </domain:transfer>
    </transfer>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_GetNameservers($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $i = 0;
        foreach($r->ns->hostObj as $ns) {
            $i++;
            $return["ns{$i}"] = (string)$ns;
        }
        
        $whmcsDomainId = verisign_getWhmcsDomainIdFromNamingo($params['domainname']);

        $status = array();
        Capsule::table('namingo_domain_status')->where('domain_id', '=', $whmcsDomainId)->delete();
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if ($st == 'pendingDelete') {
                $updatedDomainStatus = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['status' => 'Cancelled']);
            }

            Capsule::table('namingo_domain_status')->insert(['domain_id' => $whmcsDomainId, 'status' => $st]);
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_SaveNameservers($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $add = $rem = array();
        $i = 0;
        foreach($r->ns->hostObj as $ns) {
            $i++;
            $ns = (string)$ns;
            if (!$ns) {
                continue;
            }

            $rem["ns{$i}"] = $ns;
        }

        foreach($params as $k => $v) {
            if (!$v) {
                continue;
            }

            if (!preg_match("/^ns\d$/i", $k)) {
                continue;
            }

            if ($k0 = array_search($v, $rem)) {
                unset($rem[$k0]);
            }
            else {
                $add[$k] = $v;
            }
        }

        if (!empty($add) || !empty($rem)) {
            $from = $to = array();
            $text = '';
            foreach($add as $k => $v) {
                $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
            }

            $from[] = '/{{ add }}/';
            $to[] = (empty($text) ? '' : "<domain:add><domain:ns>\n{$text}</domain:ns></domain:add>\n");
            $text = '';
            foreach($rem as $k => $v) {
                $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
            }

            $from[] = '/{{ rem }}/';
            $to[] = (empty($text) ? '' : "<domain:rem><domain:ns>\n{$text}</domain:ns></domain:rem>\n");
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
    {{ add }}
    {{ rem }}
      </domain:update>
    </update>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_GetRegistrarLock($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = 'unlocked';
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        foreach($r->status as $e) {
            $attr = $e->attributes();
            if (preg_match("/clientTransferProhibited/i", $attr['s'])) {
                $return = 'locked';
            }
        }
    }

    catch(exception $e) {
        $return = 'locked';
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_SaveRegistrarLock($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if (!preg_match("/^client.+Prohibited$/i", $st)) {
                continue;
            }

            $status[$st] = true;
        }

        $rem = $add = array();
        foreach(array(
            'clientDeleteProhibited',
            'clientTransferProhibited'
        ) as $st) {
            if ($params["lockenabled"] == 'locked') {
                if (!isset($status[$st])) {
                    $add[] = $st;
                }
            }
            else {
                if (isset($status[$st])) {
                    $rem[] = $st;
                }
            }
        }

        if (!empty($add) || !empty($rem)) {
            $text = '';
            foreach($add as $st) {
                $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
            }

            $from[] = '/{{ add }}/';
            $to[] = (empty($text) ? '' : "<domain:add>\n{$text}</domain:add>\n");
            $text = '';
            foreach($rem as $st) {
                $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
            }

            $from[] = '/{{ rem }}/';
            $to[] = (empty($text) ? '' : "<domain:rem>\n{$text}</domain:rem>\n");
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        {{ rem }}
        {{ add }}
      </domain:update>
    </update>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_GetContactDetails($params = array())
{
    return [];
}

function verisign_SaveContactDetails($params = array())
{
    return ['success' => true];
}

function verisign_IDProtectToggle($params = array())
{
    return ['success' => true];
}

function verisign_GetEPPCode($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $eppcode = (string)$r->authInfo->pw;

        // If EPP Code is returned, return it for display to the end user
        if (!empty($s)) {
            $s->logout($params['registrarprefix']);
        }
        return array('eppcode' => $eppcode);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_RegisterNameserver($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <host:check
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:check>
    </check>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;
        if (0 == (int)$r->cd[0]->name->attributes()->avail) {
            throw new exception($r->cd[0]->name . " " . $r->cd[0]->reason);
        }

        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ ip }}/';
        $to[] = htmlspecialchars($params['ipaddress']);
        $from[] = '/{{ v }}/';
        $to[] = (preg_match('/:/', $params['ipaddress']) ? 'v6' : 'v4');
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <create>
      <host:create
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
        <host:addr ip="{{ v }}">{{ ip }}</host:addr>
      </host:create>
    </create>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_ModifyNameserver($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $from[] = '/{{ ip1 }}/';
        $to[] = htmlspecialchars($params['currentipaddress']);
        $from[] = '/{{ v1 }}/';
        $to[] = (preg_match('/:/', $params['currentipaddress']) ? 'v6' : 'v4');
        $from[] = '/{{ ip2 }}/';
        $to[] = htmlspecialchars($params['newipaddress']);
        $from[] = '/{{ v2 }}/';
        $to[] = (preg_match('/:/', $params['newipaddress']) ? 'v6' : 'v4');
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-update-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <host:update
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
        <host:add>
          <host:addr ip="{{ v2 }}">{{ ip2 }}</host:addr>
        </host:add>
        <host:rem>
          <host:addr ip="{{ v1 }}">{{ ip1 }}</host:addr>
        </host:rem>
      </host:update>
    </update>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_DeleteNameserver($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['nameserver']);
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-host-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <delete>
      <host:delete
       xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{{ name }}</host:name>
      </host:delete>
    </delete>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_RequestDelete($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <delete>
      <domain:delete
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:delete>
    </delete>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_manageDNSSECDSRecords($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSadd')) {
            $keyTag = $_POST['keyTag'];
            $alg = $_POST['alg'];
            $digestType = $_POST['digestType'];
            $digest = $_POST['digest'];

            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));

            $from[] = '/{{ keyTag }}/';
            $to[] = htmlspecialchars($keyTag);

            $from[] = '/{{ alg }}/';
            $to[] = htmlspecialchars($alg);

            $from[] = '/{{ digestType }}/';
            $to[] = htmlspecialchars($digestType);

            $from[] = '/{{ digest }}/';
            $to[] = htmlspecialchars($digest);
            
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:update>
    </update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:add>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:add>
      </secDNS:update>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }

        if (isset($_POST['command']) && ($_POST['command'] === 'secDNSrem')) {
            $keyTag = $_POST['keyTag'];
            $alg = $_POST['alg'];
            $digestType = $_POST['digestType'];
            $digest = $_POST['digest'];

            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));

            $from[] = '/{{ keyTag }}/';
            $to[] = htmlspecialchars($keyTag);

            $from[] = '/{{ alg }}/';
            $to[] = htmlspecialchars($alg);

            $from[] = '/{{ digestType }}/';
            $to[] = htmlspecialchars($digestType);

            $from[] = '/{{ digest }}/';
            $to[] = htmlspecialchars($digest);
            
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;

            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:update>
    </update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:rem>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:rem>
      </secDNS:update>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }

        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);

        $secDNSdsData = array();
        if ($r->response->extension && $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData) {
            $DSRecords = 'YES';
            $i = 0;
            $r = $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData;
            foreach($r->dsData as $dsData) {
                $i++;
                $secDNSdsData[$i]["domainid"] = (int)$params['domainid'];
                $secDNSdsData[$i]["keyTag"] = (string)$dsData->keyTag;
                $secDNSdsData[$i]["alg"] = (int)$dsData->alg;
                $secDNSdsData[$i]["digestType"] = (int)$dsData->digestType;
                $secDNSdsData[$i]["digest"] = (string)$dsData->digest;
            }
        }
        else {
            $DSRecords = "You don't have any DS records";
        }

        $return = array(
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => array(
                'DSRecords' => $DSRecords,
                'DSRecordslist' => $secDNSdsData
            )
        );
    }

    catch(exception $e) {
        $return = array(
            'templatefile' => 'manageDNSSECDSRecords',
            'requirelogin' => true,
            'vars' => array(
                'error' => $e->getMessage()
            )
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_ClientAreaCustomButtonArray()
{
    $buttonarray = array(
        Lang::Trans('Manage DNSSEC DS Records') => 'manageDNSSECDSRecords'
    );
    
    return $buttonarray;
}

function verisign_AdminCustomButtonArray($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $domainid = verisign_getNamingoDomainId($params['domainid']);

    // $domain = Capsule::table('tbldomains')->where('id', $domainid)->first();

    $domain = Capsule::table('namingo_domain_status')->where('domain_id', '=', $domainid)->where('status', '=', 'clientHold')->first();

    if (isset($domain->status)) {
        return array(
            'Unhold Domain' => 'UnHoldDomain'
        );
    }
    else {
        return array(
            'Put Domain On Hold' => 'OnHoldDomain'
        );
    }
}

function verisign_OnHoldDomain($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        $existing_status = 'ok';
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if ($st == 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }

            if ($st == 'serverHold') {
                $existing_status = 'serverHold';
                break;
            }
        }

        if ($existing_status == 'ok') {
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
        <domain:add>
          <domain:status s="clientHold" lang="en">clientHold</domain:status>
        </domain:add>
      </domain:update>
    </update>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_UnHoldDomain($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $status = array();
        $existing_status = 'ok';
        foreach($r->status as $e) {
            $st = (string)$e->attributes()->s;
            if ($st == 'clientHold') {
                $existing_status = 'clientHold';
                break;
            }
        }

        if ($existing_status == 'clientHold') {
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
            $tld = strtoupper(str_replace('.', '', $params['tld']));
            $from[] = '/{{ tld }}/';
            $to[] = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <update>
      <domain:update
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
            <domain:rem>
                 <domain:status s="clientHold" lang="en">clientHold</domain:status>
               </domain:rem>
      </domain:update>
    </update>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $s->write($xml, __FUNCTION__);
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_TransferSync($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="query">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:transfer>
    </transfer>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
        $trStatus = (string)$r->trStatus;
        $expDate = (string)$r->exDate;

        Capsule::table('namingo_domain')
            ->where('name', $params['domain'])
            ->update(['trstatus' => $trStatus]);

        switch ($trStatus) {
            case 'pending':
                $return['completed'] = false;
            break;
            case 'clientApproved':
            case 'serverApproved':
                $return['completed'] = true;
                $return['expirydate'] = date('Y-m-d', is_numeric($expDate) ? $expDate : strtotime($expDate));
            break;
            case 'clientRejected':
            case 'clientCancelled':
            case 'serverCancelled':
                $return['failed'] = true;
                $return['reason'] = $trStatus;
            break;
            default:
                $return = array(
                    'error' => sprintf('invalid transfer status: %s', $trStatus)
                );
            break;
        }

        return $return;
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

function verisign_Sync($params = array())
{
    _verisign_log(__FUNCTION__, $params);
    $return = array();
    try {
        $s = _verisign_startEppClient($params);
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($params['sld'] . '.' . ltrim($params['tld'], '.'));
        $tld = strtoupper(str_replace('.', '', $params['tld']));
        $from[] = '/{{ tld }}/';
        $to[] = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ name }}</domain:name>
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $s->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
        $expDate = (string)$r->exDate;
        $roid = (string)$r->roid;
        $timestamp = strtotime($expDate);

        if ($timestamp === false) {
            return array(
                'error' => 'Empty expDate date for domain: ' . $params['domain']
            );
        }

        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);

        // Format `exDate` to `YYYY-MM-DD HH:MM:SS.000`
        $formattedExpDate = date('Y-m-d H:i:s.000', $timestamp);

        Capsule::table('namingo_domain')
            ->where('name', $params['domain'])
            ->update([
                'exdate' => $formattedExpDate,
                'registry_domain_id' => $roid
            ]);

        if ($timestamp < time()) {
            return array(
                'expirydate'    =>  $expDate,
                'expired'       =>  true
            );            
        }
        else {
            return array(
                'expirydate'    =>  $expDate,
                'active'        =>  true
            );
        }
    }

    catch(exception $e) {
        $return = array(
            'error' => $e->getMessage()
        );
    }

    if (!empty($s)) {
        $s->logout($params['registrarprefix']);
    }

    return $return;
}

class verisign_epp_client

{
    var $socket;
    var $isLogined = false;
    var $params;
    function __construct($params)
    {
        $this->params = $params;
        $verify_peer = false;
        if ($params['verify_peer'] == 'on') {
            $verify_peer = true;
        }
        $ssl = array(
            'verify_peer' => $verify_peer,
            'cafile' => $params['cafile'],
            'local_cert' => $params['local_cert'],
            'local_pk' => $params['local_pk'],
            'passphrase' => $params['passphrase']
        );
        $host = $params['host'];
        $port = $params['port'];

        if ($host) {
            $this->connect($host, $port, $ssl);
        }
    }

    function connect($host, $port = 700, $ssl, $timeout = 30)
    {
        ini_set('display_errors', true);
        error_reporting(E_ALL);

        // echo '<pre>';print_r($host);
        // print_r($this->params);
        // exit;

        if ($host != $this->params['host']) {
            throw new exception("Unknown EPP server '$host'");
        }
        
        $tls_version = '1.2';
        if ($this->params['tls_version'] == 'on') {
            $tls_version = '1.3';
        }
        
        $opts = array(
            'ssl' => array(
                'verify_peer' => $ssl['verify_peer'],
                'verify_peer_name' => false,
                'verify_host' => false,
                //'cafile' => __DIR__ . '/' . $ssl['cafile'],
                'local_cert' => __DIR__ . '/' . $ssl['local_cert'],
                'local_pk' => __DIR__ . '/' . $ssl['local_pk'],
                //'passphrase' => $ssl['passphrase'],
                'allow_self_signed' => true
            )
        );
        $context = stream_context_create($opts);
        $this->socket = stream_socket_client("tlsv{$tls_version}://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);


        if (!$this->socket) {
            throw new exception("Cannot connect to server '{$host}': {$errmsg}");
        }

        return $this->read();
    }

    function login($login, $pwd, $prefix)
    {
        $from = $to = array();
        $from[] = '/{{ clID }}/';
        $to[] = htmlspecialchars($login);
        $from[] = '/{{ pw }}/';
        $to[] = $pwd;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($prefix . '-login-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <login>
      <clID>{{ clID }}</clID>
      <pw><![CDATA[{{ pw }}]]></pw>
      <options>
        <version>1.0</version>
        <lang>en</lang>
      </options>
      <svcs>
        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
        <objURI>http://www.verisign.com/epp/registry-1.0</objURI>
        <objURI>http://www.verisign.com/epp/lowbalance-poll-1.0</objURI>
        <objURI>http://www.verisign.com/epp/rgp-poll-1.0</objURI>
        <svcExtension>
          <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
          <extURI>urn:ietf:params:xml:ns:epp:loginSec-1.0</extURI>
          <extURI>http://www.verisign.com/epp/whoisInf-1.0</extURI>
          <extURI>http://www.verisign.com/epp/idnLang-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:coa-1.0</extURI>
          <extURI>http://www.verisign-grs.com/epp/namestoreExt-1.1</extURI>
          <extURI>http://www.verisign.com/epp/sync-1.0</extURI>
          <extURI>http://www.verisign.com/epp/relatedDomain-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:verificationCode-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:changePoll-1.0</extURI>
        </svcExtension>
      </svcs>
    </login>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = true;
        return true;
    }

    function logout($prefix)
    {
        if (!$this->isLogined) {
            return true;
        }

        $from = $to = array();
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($prefix . '-logout-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <logout/>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = false;
        return true;
    }

    function read()
    {
        _verisign_log('================= read-this =================', $this);
        $hdr = stream_get_contents($this->socket, 4);
        if ($hdr === false) {
        throw new exception('Connection appears to have closed.');
        }
        if (strlen($hdr) < 4) {
        throw new exception('Failed to read header from the connection.');
        }
        $unpacked = unpack('N', $hdr);
        $xml = fread($this->socket, ($unpacked[1] - 4));
        $xml = preg_replace('/></', ">\n<", $xml); 
        _verisign_log('================= read =================', $xml);
        return $xml;
    }

    function write($xml, $action = 'Unknown')
    {
        _verisign_log('================= send-this =================', $this);
        _verisign_log('================= send =================', $xml);
        if (fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml) === false) {
        throw new exception('Error writing to the connection.');
        }
        $r = simplexml_load_string($this->read());
        _verisign_modulelog($xml, $r, $action);
            if (isset($r->response) && $r->response->result->attributes()->code >= 2000) {
                throw new exception($r->response->result->msg);
            }
        return $r;
    }

    function disconnect()
    {
        $result = fclose($this->socket);
        if (!$result) {
             throw new exception('Error closing the connection.');
        }
        $this->socket = null;
        return $result;
    }

    function generateObjectPW($objType = 'none')
    {
        $result = '';
        $uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        $numbers = "1234567890";
        $specialSymbols = "!=+-";
        $minLength = 16;
        $maxLength = 16;
        $length = mt_rand($minLength, $maxLength);

        // Include at least one character from each set
        $result .= $uppercaseChars[mt_rand(0, strlen($uppercaseChars) - 1)];
        $result .= $lowercaseChars[mt_rand(0, strlen($lowercaseChars) - 1)];
        $result .= $numbers[mt_rand(0, strlen($numbers) - 1)];
        $result .= $specialSymbols[mt_rand(0, strlen($specialSymbols) - 1)];

        // Append random characters to reach the desired length
        while (strlen($result) < $length) {
            $chars = $uppercaseChars . $lowercaseChars . $numbers . $specialSymbols;
            $result .= $chars[mt_rand(0, strlen($chars) - 1)];
        }

        return $result;
    }
    
    function generateRandomString() 
    {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $randomString = '';
        for ($i = 0; $i < 16; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }

}

function _verisign_modulelog($send, $responsedata, $action)
{
    $from = $to = array();
    $from[] = "/<clID>[^<]*<\/clID>/i";
    $to[] = '<clID>Not disclosed clID</clID>';
    $from[] = "/<pw>[^<]*<\/pw>/i";
    $to[] = '<pw>Not disclosed pw</pw>';
    $sendforlog = preg_replace($from, $to, $send);
    logModuleCall('epp',$action,$sendforlog,$responsedata);
}

function _verisign_log($func, $params = false)
{

    // comment line below to see logs
    //return true;

    $handle = fopen(dirname(__FILE__) . '/verisign.log', 'a');
    ob_start();
    echo "\n================= $func =================\n";
    print_r($params);
    $text = ob_get_contents();
    ob_end_clean();
    fwrite($handle, $text);
    fclose($handle);
}

function verisign_insertDomain($params, $contactIds) {
    // Calculate expiry date
    $crdate = date('Y-m-d H:i:s.u');
    $exdate = date('Y-m-d H:i:s.u', strtotime("+{$params['regperiod']} years"));

    // Insert into namingo_domain table
    $domainId = Capsule::table('namingo_domain')->insertGetId([
        'name' => $params['domainname'],
        'registry_domain_id' => '',
        'clid' => 1,
        'crid' => 1,
        'crdate' => $crdate,
        'exdate' => $exdate,
        'registrant' => $contactIds[0] ?? null,     // Registrant contact ID
        'admin' => $contactIds[1] ?? null,          // Admin contact ID
        'tech' => $contactIds[2] ?? null,           // Tech contact ID
        'billing' => $contactIds[3] ?? null,        // Billing contact ID
        'ns1' => $params['ns1'] ?? null,    // Name servers
        'ns2' => $params['ns2'] ?? null,
        'ns3' => $params['ns3'] ?? null,
        'ns4' => $params['ns4'] ?? null,
        'ns5' => $params['ns5'] ?? null
    ]);

    return $domainId;
}

function verisign_getNamingoDomainId($whmcsDomainId) {
    $result = Capsule::selectOne("
        SELECT namingo_domain.id
        FROM namingo_domain
        JOIN tbldomains ON LOWER(namingo_domain.name) = LOWER(tbldomains.domain)
        WHERE tbldomains.id = ?
        LIMIT 1
    ", [$whmcsDomainId]);

    return $result ? $result->id : null;
}

function verisign_getWhmcsDomainIdFromNamingo($namingoDomainName) {
    return Capsule::table('tbldomains')
        ->whereRaw('LOWER(domain) = ?', [strtolower($namingoDomainName)])
        ->value('id');
}