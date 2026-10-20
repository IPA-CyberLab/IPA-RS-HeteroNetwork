#!/usr/bin/env node
// Live console + CLI + CSI test. All mutations target newly created fixtures.
// No operator identity, stored user token, user disk or S3 credential is used.
import { chromium } from '@playwright/test';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.umask(0o077);
const args=process.argv.slice(2);
function argument(name, fallback) { const i=args.indexOf(name);return i>=0 ? args[i+1] : fallback; }
const base=new URL(argument('--endpoint'));
const accountFile=argument('--account-file');
const output=argument('--report');
const cliBinary=argument('--cli');
const kubeBinary=argument('--kubectl','kubectl');
const kubeconfig=argument('--kubeconfig');
const fixtureImage=argument('--image');
if (!accountFile || !output || !cliBinary || !kubeconfig || !fixtureImage || !['http:','https:'].includes(base.protocol)) throw new Error('explicit endpoint, account, CLI, kubeconfig, image and report required');
const run=randomUUID();
const prefix='operations-e2e-'+run.slice(0,8);
const namespace='heterocloud-flash-workloads';
const services=new Set();
const backups=new Set();
const claims=new Map();
const report={schema_version:1,mode:args.includes('--preflight')?'preflight':'live',run_id:run,result:'incomplete',checks:{},cleanup:{},errors:[]};
let stage='configuration', browser, context, token, org, project, csrf, temp;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function require(value,message) {if(!value) throw new Error(message);}
function unprivilegedEnvironment() {
  const env={...process.env};
  delete env.HNN_E2E_SUDO_PASSWORD;delete env.HNN_IAC_BECOME_PASSWORD;
  delete env.HETEROCLOUD_API_KEY;delete env.HETEROCLOUD_API_KEY_FILE;
  return env;
}
function kube(...args) {
  const result=spawnSync(kubeBinary,['--kubeconfig='+kubeconfig,'--request-timeout=15s',...args],{env:unprivilegedEnvironment(),encoding:'utf8',timeout:45000,maxBuffer:32*1024*1024});
  require(result.status===0,'kube_operation_failed');
  return result.stdout;
}
function get(kind,name,ns=namespace) {return JSON.parse(kube('-n',ns,'get',kind,name,'-o','json','--ignore-not-found=true')||'null');}
async function poll(name,condition,seconds=600) {
  stage=name; console.log(JSON.stringify({stage}));
  const deadline=Date.now()+seconds*1000;
  while(Date.now()<deadline) {const value=await condition();if(value)return value;await sleep(2000);}
  throw new Error('step_timeout');
}
async function api(method,pathname,body,allowed=[200]) {
  const response=await context.request.fetch(new URL(pathname,base).href,{method,data:body,headers:{Origin:base.origin,...(csrf?{'x-heterocloud-csrf':csrf}:{})},timeout:15000});
  require(allowed.includes(response.status()),'api_http_'+response.status());
  return response.status()===204?null:response.json();
}
function orgPath(suffix) {return `/api/v1/organizations/${org}/${suffix}`;}
function cliEnvironment() {
  return {...unprivilegedEnvironment(),HETEROCLOUD_ENDPOINT:base.href,HETEROCLOUD_ORGANIZATION_ID:org,HETEROCLOUD_CREDENTIALS_FILE:path.join(temp,'credentials.json'),HETEROCLOUD_NO_UPDATE_CHECK:'1',XDG_CONFIG_HOME:temp};
}
function cli(...args) {
  const env=cliEnvironment();
  const result=spawnSync(cliBinary,args,{env,encoding:'utf8',timeout:60000});
  if(result.status!==0) {
    const redact=value=>String(value??'').replaceAll(token??'__no_token__','[REDACTED]').replace(/hc[u]?_[A-Za-z0-9_-]+/g,'[REDACTED]');
    writeFileSync(path.join(path.dirname(output),'cli-failure-private.json'),JSON.stringify({operation:args.slice(0,2),status:result.status,stderr:redact(result.stderr).slice(0,4096),stdout:redact(result.stdout).slice(0,4096)},null,2),{mode:0o600});
    throw new Error('cli_'+args.slice(0,2).join('_').replace(/[^a-z0-9_]/g,'_')+'_failed');
  }
  return JSON.parse(result.stdout);
}
async function serviceReady(id,stopped) {
  return poll(stopped?'physical_restore_complete':'fixture_running',async()=>{
    const service=await api('GET',orgPath('flash/services/'+id));
    require(service.name.startsWith(prefix),'foreign_service_guard');
    if(service.state==='error')writeFileSync(path.join(path.dirname(output),'service-error-private.json'),JSON.stringify({id:service.id,state:service.state,status:service.status},null,2),{mode:0o600});
    require(service.state!=='error','fixture_service_error');
    return service.state==='ready' && (service.spec.stopped??false)===stopped ? service : null;
  });
}
async function disk(id) {
  const pvc=get('pvc',`flash-${id}-home`);
  require(pvc && pvc.metadata.labels?.['flash.heterocloud.io/instance']===id,'foreign_disk_guard');
  claims.set(id,{name:pvc.metadata.name,uid:pvc.metadata.uid,pv:pvc.spec.volumeName});
  return pvc;
}
function fixturePod(id) {
  require(services.has(id),'foreign_pod_guard');
  const items=JSON.parse(kube('-n',namespace,'get','pods','-l','flash.heterocloud.io/instance='+id,'-o','json')).items;
  return items.find(p=>p.status?.phase==='Running' && p.status?.containerStatuses?.some(c=>c.name==='workload'&&c.ready));
}
function exec(pod,command) {
  require(pod?.metadata?.labels?.['flash.heterocloud.io/instance'] && services.has(pod.metadata.labels['flash.heterocloud.io/instance']),'foreign_exec_guard');
  return kube('-n',namespace,'exec',pod.metadata.name,'-c','workload','--','/bin/sh','-ec',command).trim();
}
function releaseFixtureDisk(id) {
  const saved=claims.get(id);if(!saved)return;
  const pv=get('pv',saved.pv);if(!pv)return;
  require(pv.spec.claimRef.uid===saved.uid && pv.spec.claimRef.namespace===namespace && pv.spec.claimRef.name===saved.name,'foreign_volume_cleanup_guard');
  kube('patch','pv',saved.pv,'--type=merge','-p',JSON.stringify({metadata:{resourceVersion:pv.metadata.resourceVersion},spec:{persistentVolumeReclaimPolicy:'Delete'}}));
}
async function signIn() {
  const info=await fs.lstat(accountFile);
  require(info.isFile()&&!info.isSymbolicLink()&&(info.mode&0o077)===0,'private_account_file_required');
  const account=JSON.parse(await fs.readFile(accountFile,'utf8'));
  require(/^heterocloud-(?:browser-)?e2e(?:-|@)/.test(account.username)&&typeof account.password==='string','dedicated_test_account_required');
  browser=await chromium.launch({headless:true,env:unprivilegedEnvironment()});
  context=await browser.newContext({serviceWorkers:'block',viewport:{width:1440,height:1000}});
  const page=await context.newPage();page.setDefaultTimeout(20000);
  page.on('pageerror',()=>{report.browser_errors=(report.browser_errors??0)+1;});
  stage='public_oidc_login';
  await page.goto(new URL('/login',base).href,{waitUntil:'domcontentloaded'});
  await page.locator('a[href="/api/v1/auth/oidc/start"]').click();
  await page.locator('input[name="username"]').fill(account.username);
  await page.locator('input[name="password"]').fill(account.password);
  await page.locator('#kc-login, input[type="submit"], button[type="submit"]').first().click();
  const session=await poll('login_callback',async()=>{
    const response=await context.request.get(new URL('/api/v1/auth/session',base).href);
    return response.status()===200?response.json():null;
  },30);
  csrf=session.csrf_token;
  const memberships=session.memberships.filter(m=>m.role==='owner'&&/e2e|test|browser/i.test(m.organization_slug+' '+m.organization_name));
  require(memberships.length===1,'unique_dedicated_test_organization_required');
  org=memberships[0].organization_id;
  await context.addInitScript(id=>localStorage.setItem('heterocloud.active-organization',id),org);
  stage='fixture_project';report.organization_id=org;
  const projects=await api('GET',orgPath('projects'));
  let fixture=projects.items.find(p=>p.slug==='flash-backup-e2e');
  if(!fixture) {
    const created=await api('POST',orgPath('projects'),{slug:'flash-backup-e2e',name:'Flash backup E2E'},[201,409]);
    fixture=created?.id ? created : (await api('GET',orgPath('projects'))).items.find(p=>p.slug==='flash-backup-e2e');
  }
  require(fixture,'dedicated_test_project_required');project=fixture.id;
  report.cleanup.dedicated_fixture_project_retained_for_reuse=true;
  report.organization_id=org;report.project_id=project;report.checks.normal_public_oidc_login=true;
  return page;
}
async function authorizeCLI() {
  stage='cli_device_authorization';
  const login=spawn(cliBinary,['auth','login','--device-code'],{env:cliEnvironment(),stdio:['ignore','pipe','pipe']});
  let transcript='',loginError='';login.stderr.on('data',chunk=>{loginError=(loginError+chunk.toString()).slice(-4096);});login.stdout.on('data',chunk=>{transcript=(transcript+chunk.toString()).slice(-8192);});
  const finished=new Promise((resolve,reject)=>{login.once('exit',resolve);login.once('error',reject);});
  try {
    const code=await poll('cli_device_code',()=>{require(login.exitCode===null,'cli_device_login_failed');return /Verification code:\s+([A-Z0-9-]{12,20})/.exec(transcript)?.[1];},30);
    await api('POST','/api/v1/auth/cli/device/approve',{user_code:code},[204]);
    let timer;const status=await Promise.race([finished,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('cli_login_timeout')),60000);})]).finally(()=>clearTimeout(timer));
    require(status===0,'cli_device_login_failed');
    const credentials=JSON.parse(await fs.readFile(path.join(temp,'credentials.json'),'utf8'));
    token=credentials.profiles?.[base.href]?.access_token;
    require(token?.startsWith('hcu_'),'cli_device_token_required');
    report.checks.cli_uses_device_code_authentication=true;
  } catch(error) {
    const clean=value=>String(value).replace(/hc[du]?_[A-Za-z0-9_-]+/g,'[REDACTED]').replace(/Verification code:\s+[^\n]+/g,'Verification code: [REDACTED]').replace(/(https?:\/\/[^\s?]+)\?[^\s]+/g,'$1?[REDACTED]');
    writeFileSync(path.join(path.dirname(output),'auth-failure-private.json'),JSON.stringify({status:login.exitCode,stderr:clean(loginError),stdout:clean(transcript)},null,2),{mode:0o600});throw error;
  } finally {if(login.exitCode===null)login.kill('SIGTERM');}
}

const auxiliaries=[];
function applyFixture(object) {
  object.metadata.labels={...object.metadata.labels,'operations-e2e/run':run};
  auxiliaries.push({kind:object.kind,name:object.metadata.name});
  const result=spawnSync(kubeBinary,['--kubeconfig='+kubeconfig,'-n',namespace,'create','-f','-'],{env:unprivilegedEnvironment(),input:JSON.stringify(object),encoding:'utf8',timeout:30000});
  require(result.status===0,'create_isolated_probe_failed');
}
function rejectAdmission(object,reason,dry=false){
  object.metadata.labels={...object.metadata.labels,'operations-e2e/run':run};
  auxiliaries.push({kind:object.kind,name:object.metadata.name});
  const result=spawnSync(kubeBinary,['--kubeconfig='+kubeconfig,'-n',namespace,'create',...(dry?['--dry-run=server']:[]),'-f','-'],{env:unprivilegedEnvironment(),input:JSON.stringify(object),encoding:'utf8',timeout:30000});
  require(result.status!==0&&result.stderr.includes(reason),'capacity_admission_did_not_refuse');
  require(!get(object.kind,object.metadata.name),'rejected_resource_was_created');
}
const web=(value,delay=0)=>`import http.server,time
time.sleep(${delay})
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'${value}')
 def log_message(self,*a):pass
http.server.ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()`;
async function create(name,stateless=false,zero=false){
  const manifest={project_id:project,name:prefix+'-'+name,spec:{region:'heteronet-global',image:fixtureImage,replicas:1,stopped:false,cpu_millis:zero?500:200,memory_mib:256,ephemeral_storage_gib:3,...(zero?{autoscaling:{min_replicas:0,max_replicas:1,target_cpu_utilization_percent:80,idle_timeout_seconds:60}}:{}),...(!stateless?{persistent_storage_gib:1}:{}),ports:[{name:'http',protocol:'tcp',container_port:8080,service_port:8080}],
    exposure:zero?{type:'public',traffic_mode:'forwarded',endpoint_mode:'web'}:{type:'internal',traffic_mode:'forwarded'},egress:{mode:'disabled',allow_same_organization:false,allowed_destination_cidrs:[],denied_destination_cidrs:[]},env:{HOME:'/root'},command:['python3','-B','-c'],args:[web('v1')],metadata:{purpose:'isolated-operations-e2e',run_id:run},deployment:{strategy:'auto',stateless,deadline_seconds:zero?60:180,auto_rollback:true,health_check:{port:8080,path:'/healthz'}}}};
  const file=path.join(temp,name+'.json');await fs.writeFile(file,JSON.stringify(manifest),{mode:0o600});
  const service=cli('flash','create','--file',file,'--no-wait');
  require(service.id&&service.name===manifest.name,'fresh_fixture_required');services.add(service.id);
  await serviceReady(service.id,false);
  return api('GET',orgPath('flash/services/'+service.id));
}
async function update(service,spec){return api('PUT',orgPath('flash/services/'+service.id),{name:service.name,spec},[200,202]);}
const memoryInjections=new Map();
async function rollingTest(){
    const stateless=await create('stateless',true);
    require(!get('pvc',`flash-${stateless.id}-home`),'stateless_created_home_disk');
    const service=JSON.parse(kube('-n',namespace,'get','services','-l','flash.heterocloud.io/instance='+stateless.id,'-o','json')).items.find(s=>s.spec.clusterIP&&s.spec.clusterIP!=='None'&&s.spec.ports?.some(p=>(p.protocol??'TCP')==='TCP'));
    require(service,'stateless_cluster_endpoint_missing');
    const target=service.spec.clusterIP;const servicePort=service.spec.ports.find(p=>(p.protocol??'TCP')==='TCP').port;
    const probeName=prefix+'-http-probe';
    const cached=JSON.parse(kube('get','node','uc-k8sp4','-o','json')).status.images.some(i=>i.names.some(n=>n.endsWith(fixtureImage.split('@')[1])));
    require(cached,'isolated_probe_image_not_cached');
    const selector={'operations-e2e/probe':run};
    applyFixture({apiVersion:'networking.k8s.io/v1',kind:'NetworkPolicy',metadata:{name:probeName},spec:{podSelector:{matchLabels:selector},policyTypes:['Ingress','Egress'],ingress:[],egress:[{to:[{ipBlock:{cidr:target+'/32'}},{podSelector:{matchLabels:{'flash.heterocloud.io/instance':stateless.id}}}],ports:[{protocol:'TCP',port:8080}]}]}});
    const probeScript=`import time,urllib.request,json
end=time.time()+60;requests=0;errors=0;seen=set()
while time.time()<end:
 try:
  with urllib.request.urlopen('http://${target}:${servicePort}/healthz',timeout=1) as r:
   data=r.read(16).decode();seen.add(data);errors+=int(r.status!=200)
 except Exception:errors+=1
 requests+=1;time.sleep(.2)
print(json.dumps({'requests':requests,'errors':errors,'seen':sorted(seen)}),flush=True)`;
    applyFixture({apiVersion:'v1',kind:'Pod',metadata:{name:probeName,labels:{...selector,'flash.heterocloud.io/organization':org}},spec:{runtimeClassName:'gvisor',nodeSelector:{'kubernetes.io/hostname':'uc-k8sp4'},restartPolicy:'Never',automountServiceAccountToken:false,containers:[{name:'probe',image:fixtureImage,imagePullPolicy:'Never',command:['python3','-B','-c',probeScript],resources:{requests:{cpu:'20m',memory:'32Mi','ephemeral-storage':'32Mi'},limits:{cpu:'100m',memory:'64Mi','ephemeral-storage':'32Mi'}},securityContext:{readOnlyRootFilesystem:true,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}}}]}});
    await poll('probe_running',()=>get('pod',probeName)?.status?.phase==='Running',60);
    await sleep(2000);
    const rolling=await update(stateless,{...stateless.spec,args:[web('v2',10)]});
    await poll('rolling_update_healthy',async()=>{const s=await api('GET',orgPath('flash/services/'+stateless.id));return s.generation===rolling.generation&&s.state==='ready';},120);
    await poll('continuous_traffic_complete',()=>get('pod',probeName)?.status?.phase==='Succeeded',100);
    const traffic=JSON.parse(kube('-n',namespace,'logs',probeName));
    require(traffic.requests>100&&traffic.errors===0&&traffic.seen.includes('v1')&&traffic.seen.includes('v2'),'rolling_update_interrupted_http');
    report.checks.stateless_update_continuous_http=true;report.http_requests_during_update=traffic.requests;
}
async function memoryFailure(id) {
  require(services.has(id),'foreign_memory_probe_guard');
  const pods=JSON.parse(kube('-n',namespace,'get','pods','-l','flash.heterocloud.io/instance='+id,'-o','json')).items;
  const flash=get('flashservices','flash-'+id);
  writeFileSync(path.join(path.dirname(output),'fault-live-private.json'),JSON.stringify({service_id:id,desired_generation:flash?.spec?.desired_generation,requested_memory:flash?.spec?.workload?.memory_mib,phase:flash?.status?.phase,message:flash?.status?.message,pods:pods.map(p=>({name:p.metadata.name,memory:p.spec.containers.find(c=>c.name==='workload')?.resources?.limits?.memory,fault_command:p.spec.containers.some(c=>c.name==='workload'&&c.args?.some(a=>a.includes('range(128)'))),state:p.status?.containerStatuses?.find(c=>c.name==='workload')}))},null,2),{mode:0o600});
  for(const pod of pods) {
    const workload=pod.spec?.containers?.find(c=>c.name==='workload');
    if(workload?.resources?.limits?.memory!=='64Mi')continue;
    const state=pod.status?.containerStatuses?.find(c=>c.name==='workload');
    const termination=state?.state?.terminated??state?.lastState?.terminated;
    let evidence=null;
    if(workload.args?.some(arg=>arg.includes('/tmp/force-memory-pressure'))&&state?.state?.running) {
      require(process.env.HNN_E2E_SUDO_PASSWORD&&argument('--inventory')&&argument('--ssh-key'),'protected_fault_injection_credentials_required');
      const seen=memoryInjections.has(pod.metadata.uid);
      const probe=spawnSync('python3',[path.join(process.cwd(),'scripts','flash_oom_inject.py'),'--inventory',argument('--inventory'),'--key',argument('--ssh-key'),'--node',pod.spec.nodeName],
        {input:JSON.stringify({run_id:run,service_id:id,pod_uid:pod.metadata.uid,pod_name:pod.metadata.name,action:seen?'observe':'inject'}),env:process.env,encoding:'utf8',timeout:30000});
      require(probe.status===0,'owned_cgroup_fault_probe_failed');
      const receipt=JSON.parse(probe.stdout);
      if(!seen){memoryInjections.set(pod.metadata.uid,receipt);report.memory_fault_injections??=[];report.memory_fault_injections.push(receipt);try{exec(pod,'touch /tmp/force-memory-pressure');}catch{}}
      if(receipt.kernel_oom_kills>0)evidence={kind:'kernel_cgroup_oom',kernel_oom_kills:receipt.kernel_oom_kills};
    }

    if(termination?.reason==='OOMKilled'||(termination?.exitCode===137&&!memoryInjections.has(pod.metadata.uid)))evidence={kind:termination.reason,exit_code:termination.exitCode};
    if(!evidence&&termination?.exitCode===1) {
      try {const logs=kube('-n',namespace,'logs',pod.metadata.name,'-c','workload',...(state.state?.terminated?[]:['--previous']),'--tail=12');if(logs.includes('MemoryError'))evidence={kind:'python_memory_error',exit_code:1};}catch{}
    }
    if(!evidence&&pod.spec.nodeName) {
      const metrics=kube('get','--raw','/api/v1/nodes/'+pod.spec.nodeName+'/proxy/metrics/cadvisor');
      const counter=metrics.split('\n').filter(line=>line.startsWith('container_oom_events_total{')&&line.includes('pod="'+pod.metadata.name+'"')).reduce((sum,line)=>sum+Number(line.slice(line.lastIndexOf('}')+1).trim().split(/\s+/)[0]),0);
      if(counter>0)evidence={kind:'kubelet_cgroup_oom_counter',observed_counter:counter};
    }
    if(evidence){report.memory_failures??={};report.memory_failures[id]={...evidence,configured_limit_mib:64};return true;}
  }
  return false;
}
async function verifiedBackup(id){return poll('scheduled_backup_verified',async()=>{const b=await api('GET',orgPath('flash/backups/'+id));require(b.phase!=='error'&&b.status?.restore_verification?.phase!=='failed','restore_verification_failed');return b.phase==='ready'&&b.status?.restore_verification?.phase==='passed'&&b.status.restore_verification.cleanup_verified?b:null;},1800);}

try {
  temp=await fs.mkdtemp(path.join(os.tmpdir(),'flash-operations-live-'));
  const page=await signIn();
  if(!args.includes('--preflight')) {
    await authorizeCLI();
    if(!args.includes('--skip-admission')&&!args.includes('--cold-start-only')) {
    stage='capacity_refuses_before_pull';
    const label={'flash.heterocloud.io/instance':randomUUID()};
    rejectAdmission({apiVersion:'v1',kind:'Pod',metadata:{name:prefix+'-denied-pod',labels:label,annotations:{'flash.heterocloud.io/image-size-bytes':String(500*2**30)}},spec:{runtimeClassName:'gvisor',restartPolicy:'Never',automountServiceAccountToken:false,containers:[{name:'workload',image:'invalid.example/capacity-must-never-pull:'+run,resources:{requests:{cpu:'1m',memory:'16Mi','ephemeral-storage':'1Gi'},limits:{cpu:'10m',memory:'32Mi','ephemeral-storage':'1Gi'}}}]}},'insufficient_disk_capacity');
    rejectAdmission({apiVersion:'v1',kind:'PersistentVolumeClaim',metadata:{name:prefix+'-denied-disk',labels:label},spec:{storageClassName:'longhorn-static',accessModes:['ReadWriteMany'],resources:{requests:{storage:'100Ti'}}}},'insufficient_replicated_storage',true);
    report.checks.pod_denied_before_image_pull=true;report.checks.replica_storage_capacity_denied=true;
    }
    if(args.includes('--rolling-only'))await rollingTest();
    if(!args.includes('--admission-only')&&!args.includes('--cold-start-only')&&!args.includes('--rolling-only')) {
    const source=await create('stateful');const sourceDiskUID=(await disk(source.id)).metadata.uid;
    const sourcePod=await poll('source_pod_ready',()=>fixturePod(source.id));
    const hash=exec(sourcePod,`printf '%s' '${run}' > /root/operations-marker; dd if=/dev/urandom of=/root/operations-payload bs=1048576 count=2 2>/dev/null; sync; sha256sum /root/operations-payload`).split(/\s+/)[0];
    await poll('healthy_revision_recorded',async()=>cli('flash','revisions',source.id).items.some(r=>r.generation===source.generation&&r.phase==='ready'));
    if(!args.includes('--backups-only')) {
    stage='actual_cgroup_oom';
    let bad=await update(source,{...source.spec,cpu_millis:200,memory_mib:64,deployment:{...source.spec.deployment,deadline_seconds:180,auto_rollback:false},args:[`import os,time; blocks=[]; exec("while not os.path.exists('/tmp/force-memory-pressure'): time.sleep(.1)"); exec("for _ in range(128): b=bytearray(8*1024**2); b[::4096]=b'x'*(len(b)//4096); blocks.append(b)"); time.sleep(600)`]});
    await poll('memory_limit_failure_observed',()=>memoryFailure(source.id),180);
    bad=await update(bad,{...bad.spec,deployment:{...bad.spec.deployment,deadline_seconds:60,auto_rollback:true}});
    const recovered=await poll('automatic_rollback_after_deadline',async()=>{const s=await api('GET',orgPath('flash/services/'+source.id));return s.generation>bad.generation&&s.state==='ready'?s:null;},240);
    require(recovered.spec.args[0]===source.spec.args[0],'rollback_execution_not_restored');
    require((await disk(source.id)).metadata.uid===sourceDiskUID,'rollback_replaced_persistent_disk');
    const after=fixturePod(source.id);require(exec(after,'cat /root/operations-marker')===run,'rollback_lost_marker');require(exec(after,'sha256sum /root/operations-payload').split(/\s+/)[0]===hash,'rollback_lost_data');
    const events=cli('flash','events',source.id);require(events.items.some(e=>e.code==='deployment_rolled_back'),'rollback_notification_missing');
    report.checks.real_oom_auto_rollback_and_persistent_data=true;
    const manualRollback=cli('flash','rollback',source.id,'--generation',String(source.generation),'--expected-generation',String(recovered.generation),'--no-wait');
    await poll('manual_cli_rollback_healthy',async()=>{const s=await api('GET',orgPath('flash/services/'+source.id));return s.generation===manualRollback.generation&&s.state==='ready';},180);
    require((await disk(source.id)).metadata.uid===sourceDiskUID,'manual_rollback_replaced_disk');
    require(exec(fixturePod(source.id),'sha256sum /root/operations-payload').split(/\s+/)[0]===hash,'manual_rollback_changed_data');
    report.checks.manual_cli_rollback_retains_disk_data=true;

    const started=Date.now();await page.goto(new URL('/flash/services/'+source.id,base).href,{waitUntil:'domcontentloaded'});
    await page.getByRole('tab',{name:'更新履歴',exact:true}).waitFor({timeout:3000});
    report.console_ready_ms=Date.now()-started;require(report.console_ready_ms<=3000,'console_open_exceeded_three_seconds');
    await page.getByRole('tab',{name:'更新履歴',exact:true}).click();await page.getByText(/切り戻し済み/).first().waitFor();
    report.checks.real_console_revision_history=true;
    await rollingTest();
    }
    if(!args.includes('--rollout-only')) {
    if(args.includes('--backups-only')) {const start=Date.now();await page.goto(new URL('/flash/services/'+source.id,base).href,{waitUntil:'domcontentloaded'});await page.getByRole('tab',{name:'定期バックアップ',exact:true}).waitFor({timeout:3000});report.console_ready_ms=Date.now()-start;require(report.console_ready_ms<=3000,'console_open_exceeded_three_seconds');}
    const manual=cli('flash','backups','create',source.id,'--name',prefix+'-manual','--no-wait');backups.add(manual.id);
    await poll('manual_backup_uploaded',async()=>{const b=await api('GET',orgPath('flash/backups/'+manual.id));return b.phase==='ready';},1800);
    const policy={enabled:true,interval_seconds:3600,retention_count:1,verify_restore:true};
    const policyFile=path.join(temp,'policy.json');await fs.writeFile(policyFile,JSON.stringify(policy),{mode:0o600});
    cli('flash','backup-policy','set',source.id,'--file',policyFile);
    await page.getByRole('tab',{name:'定期バックアップ',exact:true}).click();
    await poll('real_policy_visible',()=>page.getByRole('checkbox',{name:'定期バックアップを有効にする'}).isChecked(),30);
    report.checks.real_console_scheduled_policy=true;
    const first=await poll('first_scheduled_backup',async()=>{const p=cli('flash','backup-policy','get',source.id);return p.last_backup_id;},180);
    backups.add(first);await verifiedBackup(first);
    cli('flash','backup-policy','run',source.id);
    const second=await poll('second_scheduled_backup',async()=>{const p=cli('flash','backup-policy','get',source.id);return p.last_backup_id&&p.last_backup_id!==first?p.last_backup_id:null;},180);
    backups.add(second);await verifiedBackup(second);
    await poll('verified_scheduled_retention',async()=>{const list=cli('flash','backups','list','--service-id',source.id).items;return !list.some(b=>b.id===first)&&list.some(b=>b.id===manual.id)&&list.some(b=>b.id===second);});
    cli('flash','backup-policy','set',source.id,'--file',await(async()=>{const f=path.join(temp,'disabled.json');await fs.writeFile(f,JSON.stringify({...policy,enabled:false}),{mode:0o600});return f;})());
    report.checks.scheduled_backups_verified_before_retention=true;report.checks.manual_backups_not_pruned=true;
    }
    require(!report.browser_errors,'browser_error');
    report.source_service_id=source.id;
    }
    if(!args.includes('--admission-only')&&!args.includes('--skip-cold-start')&&!args.includes('--rolling-only')) {
      const cold=await create('cold',true,true);
      const status=cold.status?.status??cold.status;
      const endpointValue=status.endpoints?.find(e=>e.url?.startsWith('https://')||(e.host&&e.port===443));
      const endpoint=endpointValue?.url??(endpointValue?.host?'https://'+endpointValue.host:null);
      require(endpoint,'cold_endpoint_missing');
      async function requestCold(seconds=120) {
        const url=new URL(endpoint);url.searchParams.set('e2e',run+'-'+Date.now());
        const response=await fetch(url,{signal:AbortSignal.timeout(seconds*1000)});
        return response.status===200?(await response.text()).trim():null;
      }
      require(await requestCold()==='v1','initial_cold_start_failed');
      await poll('cold_revision_actually_verified',()=>cli('flash','revisions',cold.id).items.some(r=>r.generation===cold.generation&&r.phase==='ready'&&r.ready_at),60);
      await poll('cold_service_scales_to_zero',async()=>{
        const s=await api('GET',orgPath('flash/services/'+cold.id));
        const pods=JSON.parse(kube('-n',namespace,'get','pods','-l','flash.heterocloud.io/instance='+cold.id,'-o','json')).items;
        return (s.status?.status??s.status).desired_replicas===0&&pods.length===0;
      },150);
      // Test a cold-start health failure independently of the separate OOM test.
      // This process stays alive but never opens the configured health port.
      const bad=await update(cold,{...cold.spec,cpu_millis:500,memory_mib:64,args:['import time; time.sleep(600)']});
      await poll('idle_revision_not_falsely_healthy',()=>{const r=cli('flash','revisions',cold.id).items.find(r=>r.generation===bad.generation);return r&&r.phase!=='ready'&&!r.ready_at;},30);
      await sleep(75000);
      const idle=await api('GET',orgPath('flash/services/'+cold.id));require(idle.generation===bad.generation,'idle_time_consumed_activation_deadline');
      require((idle.status?.status??idle.status).desired_replicas===0,'idle_update_woke_the_service');
      require(JSON.parse(kube('-n',namespace,'get','pods','-l','flash.heterocloud.io/instance='+cold.id,'-o','json')).items.length===0,'idle_update_created_a_pod');
      report.checks.idle_time_not_counted_as_deployment_failure=true;
      requestCold(5).catch(()=>{});
      await poll('cold_readiness_failure_observed',async()=>{
        const s=await api('GET',orgPath('flash/services/'+cold.id));const status=s.status?.status??s.status;
        const pods=JSON.parse(kube('-n',namespace,'get','pods','-l','flash.heterocloud.io/instance='+cold.id,'-o','json')).items;
        return s.generation===bad.generation&&status.desired_replicas>0&&status.ready_replicas===0&&pods.some(p=>
          p.status?.phase==='Running'&&p.spec.containers.some(c=>c.name==='workload'&&c.resources?.limits?.memory==='64Mi')&&
          p.status?.containerStatuses?.some(c=>c.name==='workload'&&!c.ready));
      },90);
      report.checks.cold_start_readiness_failure_observed=true;
      await poll('cold_start_failure_rolls_back',async()=>{const s=await api('GET',orgPath('flash/services/'+cold.id));return s.generation>bad.generation&&s.spec.memory_mib===256;},180);
      await poll('cold_rollback_recovered_http',async()=>{
        try{return await requestCold(10)==='v1';}catch{return false;}
      },180);
      report.checks.cold_start_failure_rollback_to_runtime_verified_revision=true;
      report.cold_service_id=cold.id;
    }
  }
  report.result='passed';
} catch(error) {
  // Playwright error messages can contain filled credentials or OIDC URLs.
  // Keep reports to bounded operation codes, never exception stacks/bodies.
  report.result='failed';report.errors.push({stage,code:/^[a-z0-9_]+$/.test(error.message)?error.message:'operation_failed'});
} finally {
  for(const item of auxiliaries){try{const v=get(item.kind,item.name);if(v){require(v.metadata.labels?.['operations-e2e/run']===run,'foreign_auxiliary_cleanup');kube('-n',namespace,'delete',item.kind,item.name,'--wait=false');}}catch{report.errors.push({stage:'cleanup_auxiliary'});}}
  if(context&&org) {
    for(const id of services) {
      try {const policy=await api('GET',orgPath('flash/services/'+id+'/backup-policy'),undefined,[200,404]);if(policy?.enabled)await api('PUT',orgPath('flash/services/'+id+'/backup-policy'),{enabled:false,interval_seconds:86400,retention_count:1,verify_restore:true});const list=await api('GET',orgPath('flash/backups?service_instance_id='+id));for(const b of list.items??[])backups.add(b.id);}catch{}
      try {if(!claims.has(id)){const p=get('pvc',`flash-${id}-home`);if(p)await disk(id);}releaseFixtureDisk(id);await api('DELETE',orgPath('flash/services/'+id),undefined,[200,202,204,404]);}
      catch{report.errors.push({stage:'cleanup_service',id});}
    }
    for(const id of backups) {try{await api('DELETE',orgPath('flash/backups/'+id),undefined,[200,202,204,404]);}catch{report.errors.push({stage:'cleanup_backup',id});}}
    try {
      await poll('verify_fixture_cleanup',async()=>{
        for(const id of services){const r=await context.request.get(new URL(orgPath('flash/services/'+id),base).href);if(r.status()!==404)return false;}
        for(const id of backups){const r=await context.request.get(new URL(orgPath('flash/backups/'+id),base).href);if(r.status()!==404)return false;}
        for(const saved of claims.values()){if(get('pv',saved.pv)!==null)return false;}
        return true;
      });report.cleanup.all_new_services_backups_and_volumes_removed=true;
    } catch{report.errors.push({stage:'cleanup_incomplete'});}
    if(token) {try{const r=await fetch(new URL('/api/v1/auth/cli/logout',base),{method:'POST',headers:{Authorization:'Bearer '+token}});require(r.status===204,'revoke_failed');report.cleanup.cli_token_revoked=true;}catch{report.errors.push({stage:'revoke_cli_token'});}}
    try{await api('POST','/api/v1/auth/logout',undefined,[204]);report.cleanup.browser_session_revoked=true;}catch{report.errors.push({stage:'revoke_browser_session'});}
  }
  if(context)await context.close().catch(()=>{});if(browser)await browser.close().catch(()=>{});
  if(temp)await fs.rm(temp,{recursive:true,force:true});
  if(report.errors.length)report.result='failed';
  await fs.writeFile(output,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  console.log(JSON.stringify(report));process.exitCode=report.result==='passed'?0:1;
}
