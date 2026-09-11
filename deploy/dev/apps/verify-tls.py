#!/usr/bin/env python3
"""DEV-only read-only PostgreSQL TLS probes; no login, SQL or workload mutation.

Run locally on DEV1 with its existing administrative kubeconfig. Public CA
certificates pass through stdin to OpenSSL inside the existing database Pod.
No credential values or CA private keys are emitted or persisted.
"""
import subprocess,json,pathlib,socket,base64
assert socket.gethostname().split(".")[0]=="hetero-dev-1"
assert pathlib.Path("/etc/machine-id").read_text().strip()=="381d1ae16f555c59b738d8d01dd14c94"
base=["kubectl","--kubeconfig=/etc/kubernetes/admin.conf","--request-timeout=10s"]
assert subprocess.check_output(base+["get","ns","kube-system","-o","jsonpath={.metadata.uid}"],text=True,timeout=15)=="a39281cb-d273-4c5f-b7a7-fca722fb417b"
namespaces=("heterocloud-dev","heterocloud-flow-dev","heterocloud-syouyu-dev")
cas={}
for ns in namespaces:
 obj=json.loads(subprocess.check_output(base+["-n",ns,"get","secret","dev-postgres-ca","-o","json"],timeout=15))
 cas[ns]=base64.b64decode(obj["data"]["ca.crt"],validate=True)
assert len(set(cas.values()))==3
for idx,ns in enumerate(namespaces):
 host="dev-postgres-rw."+ns+".svc.cluster.local"
 for case,ca,verifyhost in (("valid",cas[ns],host),("wrong-ca",cas[namespaces[(idx+1)%3]],host),("wrong-host",cas[ns],"not-the-database.invalid")):
  cmd=base+["-n",ns,"exec","-i","dev-postgres-1","-c","postgres","--","openssl","s_client","-starttls","postgres","-connect",host+":5432","-servername",host,"-verify_hostname",verifyhost,"-verify_return_error","-CAfile","/dev/stdin","-brief"]
  try: p=subprocess.run(cmd,input=ca,capture_output=True,timeout=20)
  except subprocess.TimeoutExpired: raise SystemExit("TLS probe timed out")
  output=p.stdout+p.stderr
  verified=p.returncode==0 and b"Verification: OK" in output
  rejected=p.returncode!=0 and b"certificate verify failed" in output
  passed=verified if case=="valid" else rejected
  print(json.dumps({"namespace":ns,"case":case,"passed":passed,"exit_code":p.returncode}),flush=True)
  if not passed:
   print(json.dumps({"diagnostic":output.decode("utf-8","replace")[-1200:]}))
   raise SystemExit("TLS verification did not match expectation")
