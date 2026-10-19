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
const prefix='backup-e2e-'+run.slice(0,8);
const namespace='heterocloud-flash-workloads';
const services=new Set();
const backups=new Set();
const claims=new Map();
const report={schema_version:1,mode:args.includes('--preflight')?'preflight':'live',run_id:run,result:'incomplete',checks:{},cleanup:{},errors:[]};
let stage='configuration', browser, context, token, org, project, csrf, temp;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function require(value,message) {if(!value) throw new Error(message);}
function kube(...args) {
  const result=spawnSync(kubeBinary,['--kubeconfig='+kubeconfig,'--request-timeout=15s',...args],{encoding:'utf8',timeout:45000});
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
  const env={...process.env,HETEROCLOUD_ENDPOINT:base.href,HETEROCLOUD_ORGANIZATION_ID:org,HETEROCLOUD_CREDENTIALS_FILE:path.join(temp,'credentials.json'),HETEROCLOUD_NO_UPDATE_CHECK:'1',XDG_CONFIG_HOME:temp};
  delete env.HETEROCLOUD_API_KEY;delete env.HETEROCLOUD_API_KEY_FILE;return env;
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
  browser=await chromium.launch({headless:true});
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
    const status=await Promise.race([finished,sleep(60000).then(()=>{throw new Error('cli_login_timeout');})]);
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

try {
  temp=await fs.mkdtemp(path.join(os.tmpdir(),'flash-backup-live-'));
  const page=await signIn();
  if(!args.includes('--preflight')) {
    await authorizeCLI();
    stage='create_isolated_source';
    const manifest={project_id:project,name:prefix+'-source',spec:{region:'heteronet-global',image:fixtureImage,replicas:1,stopped:false,cpu_millis:100,memory_mib:128,ephemeral_storage_gib:3,persistent_storage_gib:1,ports:[],
      exposure:{type:'internal',traffic_mode:'forwarded'},egress:{mode:'disabled',allow_same_organization:false,allowed_destination_cidrs:[],denied_destination_cidrs:[]},env:{HOME:'/root',BACKUP_TEST_ENV:'must-not-clone'},command:['/bin/sh'],args:['-ec','sleep infinity'],metadata:{purpose:'isolated-backup-e2e',run_id:run}}};
    const manifestFile=path.join(temp,'source.json');await fs.writeFile(manifestFile,JSON.stringify(manifest),{mode:0o600});
    const source=cli('flash','create','--file',manifestFile,'--no-wait');
    require(source.id&&source.name===manifest.name&&source.project_id===project,'fresh_source_identity_required');services.add(source.id);
    await serviceReady(source.id,false);await disk(source.id);
    const originalPod=await poll('source_pod_ready',()=>fixturePod(source.id));
    const hash=exec(originalPod,`printf '%s' '${run}' > /root/backup-marker; printf '%s' '${run}' > /root/.bashrc; dd if=/dev/urandom of=/root/backup-payload bs=1048576 count=2 2>/dev/null; chmod 640 /root/backup-payload; ln -s backup-payload /root/backup-link; sync; sha256sum /root/backup-payload`).split(/\s+/)[0];
    const backupName=prefix+'-checkpoint',requestId=randomUUID();
    const backup=cli('flash','backups','create',source.id,'--name',backupName,'--request-id',requestId,'--no-wait');backups.add(backup.id);
    const repeated=cli('flash','backups','create',source.id,'--name',backupName,'--request-id',requestId,'--no-wait');
    require(repeated.id===backup.id,'backup_retry_created_duplicate');report.checks.backup_create_idempotent=true;
    await poll('backup_upload_complete',async()=>{const b=await api('GET',orgPath('flash/backups/'+backup.id));require(b.phase!=='error','backup_failed');return b.phase==='ready';},1800);
    const afterBackup=fixturePod(source.id);require(afterBackup?.metadata.uid===originalPod.metadata.uid,'backup_restarted_source');
    require(afterBackup.status.containerStatuses.find(c=>c.name==='workload').containerID===originalPod.status.containerStatuses.find(c=>c.name==='workload').containerID,'backup_restarted_container');
    report.checks.backup_does_not_restart_source=true;
    exec(afterBackup,'printf later-state > /root/backup-marker; printf later-state > /root/.bashrc; printf changed > /root/backup-payload; sync');
    releaseFixtureDisk(source.id);cli('flash','delete',source.id,'--yes','--no-wait');
    await poll('delete_only_fixture_source_volume',()=>get('pv',claims.get(source.id).pv)===null);
    const retained=cli('flash','backups','list','--service-id',source.id);require(retained.items.some(b=>b.id===backup.id),'backup_lost_with_source');
    report.checks.backup_survives_source_service_and_volume_deletion=true;
    const started=Date.now();await page.goto(new URL('/flash/backups',base).href,{waitUntil:'domcontentloaded'});
    const row=page.getByRole('row').filter({hasText:backupName});await row.getByRole('button',{name:'復元',exact:true}).waitFor({timeout:3000});
    report.console_ready_ms=Date.now()-started;require(report.console_ready_ms<=3000,'console_open_exceeded_three_seconds');
    await row.getByRole('button',{name:'復元',exact:true}).click();
    await page.getByRole('textbox',{name:'復元先サービス名'}).fill(prefix+'-restored');
    const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname===orgPath('flash/backups/'+backup.id+'/restore'));
    await page.getByRole('button',{name:'新しいサービスへ復元'}).click();
    const restoredResponse=await responsePromise;require(restoredResponse.status()===202,'console_restore_rejected');
    const restored=await restoredResponse.json();services.add(restored.id);
    const restoreRequest=restoredResponse.request().postDataJSON();
    require(restored.id!==source.id && restored.spec.stopped && restored.spec.exposure.type==='internal' && restored.spec.egress.mode==='disabled' && Object.keys(restored.spec.env).length===0,'unsafe_restore_defaults');
    const again=cli('flash','backups','restore',backup.id,'--project-id',project,'--name',prefix+'-restored','--request-id',restoreRequest.request_id,'--no-wait');
    require(again.id===restored.id,'restore_retry_created_duplicate');report.checks.console_restore_and_cli_retry=true;
    await serviceReady(restored.id,true);const restoredPVC=await disk(restored.id);
    require(restoredPVC.metadata.uid!==claims.get(source.id).uid,'restore_reused_source_disk');
    require(!fixturePod(restored.id),'restored_workload_started_implicitly');
    const pv=get('pv',claims.get(restored.id).pv),volume=get('volumes.longhorn.io',pv.spec.csi.volumeHandle,'longhorn-system');
    require(volume.status.restoreInitiated===true&&volume.status.restoreRequired===false,'physical_data_copy_not_complete');
    report.checks.restored_disk_copied_before_workload_start=true;
    releaseFixtureDisk(restored.id);
    cli('flash','backups','delete',backup.id,'--yes','--no-wait');
    await poll('delete_backup_before_starting_restored_service',async()=>{const r=await context.request.get(new URL(orgPath('flash/backups/'+backup.id),base).href);return r.status()===404;});
    cli('flash','start',restored.id,'--no-wait');await serviceReady(restored.id,false);
    const restoredPod=await poll('restored_pod_ready',()=>fixturePod(restored.id));
    require(exec(restoredPod,'cat /root/backup-marker')===run,'restored_marker_mismatch');
    require(exec(restoredPod,'sha256sum /root/backup-payload').split(/\s+/)[0]===hash,'restored_payload_hash_mismatch');
    require(exec(restoredPod,'cat /root/.bashrc')===run,'restored_hidden_file_mismatch');
    require(exec(restoredPod,'stat -c %a /root/backup-payload')==='640','restored_mode_mismatch');
    require(exec(restoredPod,'readlink /root/backup-link')==='backup-payload','restored_symlink_mismatch');
    report.checks.hidden_files_modes_and_symlinks_preserved=true;
    report.checks.restored_original_files_after_source_and_backup_deletion=true;
    report.checks.new_disk_identity=true;report.source_service_id=source.id;report.restored_service_id=restored.id;
    await page.getByRole('button',{name:'停止',exact:true}).waitFor({timeout:10000});
    require(!report.browser_errors,'browser_error');
    await page.screenshot({path:path.join(path.dirname(output),'console-restored-service.png'),fullPage:true});
  }
  report.result='passed';
} catch(error) {
  // Playwright error messages can contain filled credentials or OIDC URLs.
  // Keep reports to bounded operation codes, never exception stacks/bodies.
  report.result='failed';report.errors.push({stage,code:/^[a-z0-9_]+$/.test(error.message)?error.message:'operation_failed'});
} finally {
  if(context&&org) {
    for(const id of services) {
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
