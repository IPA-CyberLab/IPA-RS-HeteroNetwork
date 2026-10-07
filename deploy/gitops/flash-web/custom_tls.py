"""Gateway-local, bounded certificate publication for verified domain aliases."""
import hashlib
import datetime
import ipaddress
import json
from pathlib import Path
import re
import tempfile

BEGIN=b'# BEGIN managed Flash custom domains\n'
END=b'# END managed Flash custom domains\n'

def host(value):
    if not isinstance(value,str) or len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):raise ValueError('invalid custom hostname')
    return value

def bundle(path,base):
    p=Path(path)
    if not p.is_file():return {'schema_version':1,'hosts':[],'certificates':{},'acme_upstream':None}
    raw=p.read_bytes();base.require(len(raw)<=768*1024,'custom bundle too large');d=json.loads(raw)
    base.require(set(d)=={'schema_version','hosts','certificates','acme_upstream'} and d['schema_version']==1,'invalid custom bundle')
    base.require(isinstance(d['hosts'],list) and len(d['hosts'])<=128 and len(set(d['hosts']))==len(d['hosts']),'invalid hostname count')
    for name in d['hosts']:
        host(name);base.require(name not in base.PUBLIC_HOSTS and name!=base.HOST[2:] and not name.endswith('.'+base.HOST[2:]) and not name.endswith(('.internal','.local','.localhost')),'reserved custom hostname')
    base.require(isinstance(d['certificates'],dict) and set(d['certificates'])<=set(d['hosts']),'unknown certificate hostname')
    if d['hosts']:
        upstream=d['acme_upstream'];base.require(isinstance(upstream,str) and upstream.endswith(':80'),'invalid challenge proxy')
        addr=ipaddress.ip_address(upstream[:-3]);base.require(addr.is_private and not addr.is_loopback and not addr.is_unspecified and not addr.is_multicast,'invalid challenge proxy address')
    return d

def validate_pair(base,cert,key,name):
    base.require(isinstance(cert,str) and isinstance(key,str) and len(cert)<=32768 and len(key)<=16384,'invalid custom PEM size')
    with tempfile.TemporaryDirectory(prefix='custom-cert-',dir='/tmp') as directory:
        cert_path=Path(directory)/'cert.pem';key_path=Path(directory)/'key.pem'
        cert_path.write_text(cert);key_path.write_text(key);cert_path.chmod(0o600);key_path.chmod(0o600)
        base.openssl('x509','-in',str(cert_path),'-noout','-checkhost',name)
        base.openssl('x509','-in',str(cert_path),'-noout','-checkend','3600')
        dates=base.openssl('x509','-in',str(cert_path),'-noout','-startdate').decode().strip()
        starts=datetime.datetime.strptime(dates.split('=',1)[1],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
        base.require(starts<=datetime.datetime.now(datetime.timezone.utc),'custom certificate is not yet valid')
        pub=base.openssl('x509','-in',str(cert_path),'-pubkey','-noout')
        kp=base.openssl('pkey','-in',str(key_path),'-passin','pass:','-pubout')
        base.require(pub==kp,'custom certificate key differs')
        base.openssl('pkey','-in',str(key_path),'-passin','pass:','-check','-noout')
        base.openssl('crl2pkcs7','-nocrl','-certfile',str(cert_path))

def update(base,root,old,d,gid):
    base.require(old.count(BEGIN)==old.count(END)<=1,'ambiguous custom markers')
    if BEGIN in old:
        start=old.index(BEGIN);end=old.index(END);base.require(start<end,'invalid custom markers')
        unmanaged=old[:start]+old[end+len(END):]
    else:unmanaged=old
    blocks=[]
    for name in d['hosts']:
        pattern=rb'(?m)^\s*https?://'+re.escape(name.encode())+rb'(?::[0-9]+)?\s*\{'
        base.require(not re.search(pattern,unmanaged),'unmanaged custom hostname already configured')
        material=d['certificates'].get(name);redirect='respond "Domain is provisioning" 503'
        if material:
            validate_pair(base,material['certificate'],material['private_key'],name)
            cert=material['certificate'].encode();key=material['private_key'].encode()
            generation=hashlib.sha256(len(cert).to_bytes(8,'big')+cert+key).hexdigest();base.publish_pair(root,generation,cert,key,gid)
            parent=f'/etc/heteronetwork/{base.CERTDIR}/{generation}'
            blocks.append(f'https://{name}:443 {{\n    tls {parent}/tls.crt {parent}/tls.key\n    import heterocloud_envoy /api/v1/health/live {base.PUBLIC_HOSTS[0]}\n}}\n')
            redirect='redir https://{host}{uri} 308'
        blocks.append(f'http://{name}:80 {{\n    @custom_acme path /.well-known/acme-challenge/*\n    handle @custom_acme {{\n        reverse_proxy {d["acme_upstream"]}\n    }}\n    handle {{\n        {redirect}\n    }}\n}}\n')
    if not blocks:return unmanaged
    marker=('http://'+base.PUBLIC_HOSTS[0]+' {\n').encode();base.require(unmanaged.count(marker)==1,'canonical first site missing')
    result=unmanaged.replace(marker,BEGIN+''.join(blocks).encode()+END+marker)
    base.require(len(result)<=base.LIMIT,'custom configuration exceeds gateway limit');return result
