#!/usr/bin/env python3
"""Verify service-bound DNS delegation, issue TLS, publish gateway certificates.

Certificates live in a dedicated namespace. No user or DNS-provider secret is
read. Private TLS material is published only to the gateway's projected Secret.
"""
import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_BYTES=1024*1024
FINALIZER='domains.heterocloud.io/gateway-cleanup'
LABEL='domains.heterocloud.io/alias-uid'
WRITER='domains.heterocloud.io/writer'

def require(condition,message):
    if not condition:raise ValueError(message)

def hostname(value):
    require(isinstance(value,str) and 3<=len(value)<=253 and '.' in value and not value.startswith('*.'),'invalid public hostname')
    require(not value.endswith(('.internal','.local','.localhost')) and not re.fullmatch(r'[0-9.]+',value),'private hostname')
    require(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')),'noncanonical hostname')
    return value

def digest_name(host):return 'flash-domain-'+uuid.uuid5(uuid.NAMESPACE_DNS,host).hex

def validate_config(c):
    require(c.get('schema_version')==1,'unsupported configuration')
    for key in ['workload_namespace','certificate_namespace','bundle_namespace','bundle_name','state_name','issuer','acme_service_name','acme_service_namespace','dns_namespace','dns_resource']:
        require(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',c[key]),'invalid resource name')
    hostname(c['public_flash_domain'])
    for h in c['reserved_hostnames']:hostname(h)
    require(5<=c['interval_seconds']<=60 and 1<=c['max_domains']<=128,'invalid bounds')
    return c

class ApiError(Exception):
    def __init__(self,status):self.status=status
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
class Kubernetes:
    def __init__(self):
        root=Path('/var/run/secrets/kubernetes.io/serviceaccount');self.root=root
        host=os.environ['KUBERNETES_SERVICE_HOST'];port=os.environ['KUBERNETES_SERVICE_PORT_HTTPS']
        self.base=f'https://[{host}]:{port}' if ':' in host else f'https://{host}:{port}'
        ctx=ssl.create_default_context(cafile=str(root/'ca.crt'))
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ctx))
    def call(self,method,path,value=None,content='application/json'):
        data=None if value is None else json.dumps(value,separators=(',',':')).encode()
        headers={'Authorization':'Bearer '+(self.root/'token').read_text().strip(),'Content-Type':content}
        try:
            with self.opener.open(urllib.request.Request(self.base+path,method=method,headers=headers,data=data),timeout=5) as r:
                raw=r.read(MAX_BYTES+1);require(len(raw)<=MAX_BYTES,'oversized Kubernetes response');return json.loads(raw)
        except urllib.error.HTTPError as e:raise ApiError(e.code) from None
    def optional(self,path):
        try:return self.call('GET',path)
        except ApiError as e:
            if e.status==404:return None
            raise

def resource(group,ns,kind,name=''):
    base=f'/apis/{group}/namespaces/{ns}/{kind}' if group else f'/api/v1/namespaces/{ns}/{kind}'
    return base+('/'+name if name else '')
def core(ns,kind,name=''):return resource('',ns,kind,name)
def aliases(c,name=''):return resource('flash.heterocloud.io/v1alpha1',c['workload_namespace'],'flashdomains',name)
def certs(c,name=''):return resource('cert-manager.io/v1',c['certificate_namespace'],'certificates',name)
def mutate(api,path,current,changes):
    ops=[{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']},{'op':'test','path':'/metadata/uid','value':current['metadata']['uid']},*changes]
    return api.call('PATCH',path,ops,'application/json-patch+json')

def dns_answers(name,kind,resolver):
    uri=resolver+'?'+urllib.parse.urlencode({'name':name,'type':kind})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(urllib.request.Request(uri,headers={'Accept':'application/dns-json','User-Agent':'HeteroCloud-Custom-Domains/1.0'}),timeout=5) as r:
        raw=r.read(65537);require(len(raw)<=65536,'oversized DNS response');d=json.loads(raw)
    require(d.get('Status') in (0,3),'DNS resolver unavailable')
    return [x for x in d.get('Answer',[]) if x.get('name','').rstrip('.').lower()==name and x.get('type')==kind]

def delegated(spec,c,resolvers=None):
    resolvers=resolvers or ['https://cloudflare-dns.com/dns-query','https://dns.google/resolve']
    values=[]
    for resolver in resolvers:
        cname=dns_answers(spec['hostname'],5,resolver)
        if any(x['data'].rstrip('.').lower()==spec['cname_target'] for x in cname):values.append(True);continue
        txt=dns_answers('_heterocloud.'+spec['hostname'],16,resolver)
        proof=any(''.join(shlex.split(x['data']))==spec['verification_value'] for x in txt)
        if not proof:values.append(False);continue
        actual=set()
        for kind in [1,28]:
            for answer in dns_answers(spec['hostname'],kind,resolver):actual.add(str(ipaddress.ip_address(answer['data'])))
        expected=set()
        for kind in [1,28]:
            for answer in dns_answers(spec['cname_target'],kind,resolver):expected.add(str(ipaddress.ip_address(answer['data'])))
        values.append(bool(actual) and bool(expected) and actual<=expected and all(ipaddress.ip_address(x).is_global for x in actual))
    # Recursive resolvers can disagree while positive and negative caches
    # expire. An inconsistent answer never proves a new binding and must not
    # revoke a binding that was already verified by both resolvers.
    if any(values) and not all(values):raise ValueError('DNS resolvers disagree')
    return all(values)

def owned_alias(alias,service,c):
    s=alias['spec'];host=hostname(s['hostname'])
    require(alias['metadata']['name']==digest_name(host),'alias name differs')
    require(host not in c['reserved_hostnames'] and host!=c['public_flash_domain'] and not host.endswith('.'+c['public_flash_domain']),'reserved domain')
    require(service and service['metadata']['uid']==s['service_uid'],'service identity differs')
    spec=service['spec']
    for key in ['service_instance_id','organization_id','project_id']:require(s[key]==spec[key],'domain scope differs')
    require(any(r['uid']==s['service_uid'] and r['kind']=='FlashService' for r in alias['metadata'].get('ownerReferences',[])),'owner reference differs')
    require(s['cname_target']=='f-'+s['service_instance_id']+'.'+c['public_flash_domain'],'delegation target differs')
    require(spec['workload']['exposure'].get('endpoint_mode')=='web' and spec['workload']['exposure']['type']=='public','service is not public HTTP')
    return host

def certificate(alias,c):
    name=alias['metadata']['name'];uid=alias['metadata']['uid'];host=alias['spec']['hostname']
    labels={LABEL:uid,'domains.heterocloud.io/service':alias['spec']['service_instance_id']}
    return {'apiVersion':'cert-manager.io/v1','kind':'Certificate','metadata':{'name':name,'namespace':c['certificate_namespace'],'labels':labels},'spec':{'secretName':name,'dnsNames':[host],'issuerRef':{'name':c['issuer'],'kind':'ClusterIssuer','group':'cert-manager.io'},'privateKey':{'algorithm':'ECDSA','size':256,'rotationPolicy':'Always'},'renewBefore':'720h','secretTemplate':{'labels':labels}}}

def cert_material(api,alias,c):
    name=alias['metadata']['name'];desired=certificate(alias,c);current=api.optional(certs(c,name))
    if not current:api.call('POST',certs(c),desired);return None
    require(current['metadata'].get('labels',{}).get(LABEL)==alias['metadata']['uid'],'certificate owner differs')
    require(current['spec']['dnsNames']==desired['spec']['dnsNames'] and current['spec']['secretName']==name and current['spec']['issuerRef']==desired['spec']['issuerRef'],'certificate configuration differs')
    if not any(x.get('type')=='Ready' and x.get('status')=='True' and x.get('observedGeneration')==current['metadata'].get('generation') for x in current.get('status',{}).get('conditions',[])):return None
    secret=api.optional(core(c['certificate_namespace'],'secrets',name))
    if not secret:return None
    require(secret['metadata'].get('labels',{}).get(LABEL)==alias['metadata']['uid'] and secret.get('type')=='kubernetes.io/tls','TLS secret owner differs')
    cert=base64.b64decode(secret['data']['tls.crt'],validate=True).decode();key=base64.b64decode(secret['data']['tls.key'],validate=True).decode()
    require(len(cert)<=32768 and len(key)<=16384,'oversized certificate')
    first=cert.split('-----END CERTIFICATE-----')[0]+'-----END CERTIFICATE-----\n'
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(first)).hexdigest()
    return {'certificate':cert,'private_key':key,'fingerprint':fingerprint,'expires_at':current.get('status',{}).get('notAfter')}

def tls_loaded(host,address,expected):
    ctx=ssl.create_default_context()
    try:
        with socket.create_connection((address,443),timeout=2) as conn:
            with ctx.wrap_socket(conn,server_hostname=host) as tls:
                return expected is None or hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==expected
    except (OSError,ssl.SSLError):return False

def patch_status(api,alias,c,status):
    status['observed_generation']=alias['metadata'].get('generation',0)
    if alias.get('status')==status:return
    api.call('PATCH',aliases(c,alias['metadata']['name'])+'/status',{'metadata':{'resourceVersion':alias['metadata']['resourceVersion']},'status':status},'application/merge-patch+json')

def cleanup(api,alias,c):
    name=alias['metadata']['name'];uid=alias['metadata']['uid'];service_uid=alias['spec']['service_uid']
    for group,kind in [('gateway.networking.k8s.io/v1','httproutes'),('gateway.envoyproxy.io/v1alpha1','securitypolicies')]:
        path=resource(group,c['workload_namespace'],kind,name);value=api.optional(path)
        if value:
            require(any(r['uid']==service_uid for r in value['metadata'].get('ownerReferences',[])),'route owner differs')
            api.call('DELETE',path,{'preconditions':{'uid':value['metadata']['uid']}});return False
    for path in [certs(c,name),core(c['certificate_namespace'],'secrets',name)]:
        value=api.optional(path)
        if value:
            require(value['metadata'].get('labels',{}).get(LABEL)==uid,'TLS resource owner differs')
            api.call('DELETE',path,{'preconditions':{'uid':value['metadata']['uid']}});return False
    return True

def check_lease(api,c,identity):
    state=api.call('GET',core(c['certificate_namespace'],'configmaps',c['state_name']))
    lease=json.loads(state.get('data',{}).get('lease.json','{}'))
    require(lease.get('owner')==identity and lease.get('expires_at',0)-time.time()>6,'domain writer lease lost')

def claim_bundle(api,c,identity):
    path=core(c['bundle_namespace'],'secrets',c['bundle_name']);current=api.call('GET',path)
    require(current['metadata'].get('labels',{}).get('domains.heterocloud.io/bundle')=='true','bundle owner differs')
    check_lease(api,c,identity)
    annotations=current['metadata'].get('annotations',{})
    if annotations.get(WRITER)!=identity:
        mutate(api,path,current,[{'op':'add','path':'/metadata/annotations','value':{**annotations,WRITER:identity}}])

def publish_bundle(api,c,hosts,materials,upstream,identity):
    value={'schema_version':1,'hosts':sorted(hosts),'certificates':materials,'acme_upstream':upstream}
    encoded=json.dumps(value,sort_keys=True,separators=(',',':')).encode();require(len(encoded)<=768*1024,'TLS bundle capacity reached')
    name=c['bundle_name'];path=core(c['bundle_namespace'],'secrets',name);current=api.optional(path)
    wanted={'bundle.json':base64.b64encode(encoded).decode()}
    if current:
        require(current['metadata'].get('labels',{}).get('domains.heterocloud.io/bundle')=='true','bundle owner differs')
        require(current['metadata'].get('annotations',{}).get(WRITER)==identity,'bundle writer differs')
        check_lease(api,c,identity)
        if current.get('data')!=wanted:mutate(api,path,current,[{'op':'add','path':'/data','value':wanted}])
    else:raise ValueError('Gateway bundle Secret must be provisioned by IaC')

def reconcile(api,c):
    state_path=core(c['certificate_namespace'],'configmaps',c['state_name']);state=api.call('GET',state_path)
    lease=json.loads(state.get('data',{}).get('lease.json','{}'));identity=os.environ['POD_UID'];now=time.time()
    if lease.get('owner')!=identity and lease.get('expires_at',0)>now:return {'role':'standby'}
    mutate(api,state_path,state,[{'op':'add','path':'/data','value':{'lease.json':json.dumps({'owner':identity,'expires_at':now+120})}}])
    claim_bundle(api,c,identity)
    active=api.call('GET',resource('externaldns.k8s.io/v1alpha1',c['dns_namespace'],'dnsendpoints',c['dns_resource']))
    addresses=next(x['targets'] for x in active['spec']['endpoints'] if x['dnsName']=='*.'+c['public_flash_domain'])
    require(addresses and all(ipaddress.ip_address(x).is_global for x in addresses),'invalid public origins')
    acme=api.call('GET',core(c['acme_service_namespace'],'services',c['acme_service_name']))
    upstream=str(ipaddress.ip_address(acme['spec']['clusterIP']))+':80'
    require(ipaddress.ip_address(acme['spec']['clusterIP']).is_private,'invalid challenge proxy')
    values=api.call('GET',aliases(c)+'?limit=256')['items'];require(len(values)<=c['max_domains'],'domain capacity reached')
    hosts=[];materials={};pending=[];removals=[]
    def renew():
        Path('/tmp/loop-progress').touch()
        current=api.call('GET',state_path);held=json.loads(current['data']['lease.json'])
        require(held['owner']==identity and held['expires_at']>time.time(),'domain writer lease lost')
        mutate(api,state_path,current,[{'op':'add','path':'/data','value':{'lease.json':json.dumps({'owner':identity,'expires_at':time.time()+120})}}])
    for alias in values:
        renew()
        name=alias['metadata']['name'];path=aliases(c,name)
        finals=alias['metadata'].get('finalizers',[])
        if FINALIZER not in finals and not alias['metadata'].get('deletionTimestamp'):
            mutate(api,path,alias,[{'op':'add','path':'/metadata/finalizers','value':finals+[FINALIZER]}]);continue
        if alias['metadata'].get('deletionTimestamp'):
            if cleanup(api,alias,c):removals.append(alias)
            continue
        service=api.optional(resource('flash.heterocloud.io/v1alpha1',c['workload_namespace'],'flashservices','flash-'+alias['spec']['service_instance_id']))
        try:host=owned_alias(alias,service,c)
        except (ValueError,KeyError,TypeError):
            patch_status(api,alias,c,{'phase':'error','dns_verified':False,'tls_ready':False,'message':'Domain configuration does not match its service.','certificate_expires_at':None});continue
        try:verified=delegated(alias['spec'],c)
        except Exception:
            old=alias.get('status',{})
            if old.get('dns_verified'):
                hosts.append(host)
                material=cert_material(api,alias,c)
                if material:materials[host]=material
                pending.append((alias,material))
            continue
        if not verified:
            patch_status(api,alias,c,{'phase':'pending_dns','dns_verified':False,'tls_ready':False,'message':'Set the service CNAME, or the displayed TXT proof with matching public addresses. Use DNS-only records.','certificate_expires_at':None});continue
        hosts.append(host);material=cert_material(api,alias,c)
        if material:materials[host]=material
        pending.append((alias,material))
    renew()
    publish_bundle(api,c,hosts,materials,upstream,identity)
    for alias,material in pending:
        renew()
        loaded=bool(material) and all(tls_loaded(alias['spec']['hostname'],ip,material['fingerprint']) for ip in addresses)
        # A renewal must not withdraw a working route while gateways reload.
        # Previously ready aliases may keep routing only while every origin
        # still presents a currently valid, publicly trusted certificate.
        if material and not loaded and alias.get('status',{}).get('tls_ready'):
            loaded=all(tls_loaded(alias['spec']['hostname'],ip,None) for ip in addresses)
        patch_status(api,alias,c,{'phase':'ready' if loaded else 'pending_gateway' if material else 'pending_certificate','dns_verified':True,'tls_ready':loaded,'message':None,'certificate_expires_at':material['expires_at'] if material else None})
    for alias in removals:
        renew()
        current=api.optional(aliases(c,alias['metadata']['name']))
        if current:mutate(api,aliases(c,alias['metadata']['name']),current,[{'op':'add','path':'/metadata/finalizers','value':[x for x in current['metadata'].get('finalizers',[]) if x!=FINALIZER]}])
    return {'role':'active','domain_count':len(hosts),'certificates_ready':len(materials)}

def main():
    c=validate_config(json.loads(Path('/config/site.json').read_text()));api=Kubernetes()
    while True:
        Path('/tmp/loop-progress').touch()
        try:
            result=reconcile(api,c);Path('/tmp/last-success').touch();print(json.dumps(result),flush=True)
        except ApiError as e:print(json.dumps({'error':'kubernetes','status':e.status}),flush=True)
        except Exception:print(json.dumps({'error':'domain_reconciliation'}),flush=True)
        time.sleep(c['interval_seconds'])

if __name__=='__main__':main()
