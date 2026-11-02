"""Temporary local Vault ACL and custody lifecycle proof; no production access."""
import json, os, secrets, subprocess, time, urllib.request, urllib.error, hashlib
from pathlib import Path
name='csign-custody-proof-'+secrets.token_hex(4)
plugin=Path(__file__).resolve().parents[2] / 'dist' / 'chain-signer-plugin'
root=secrets.token_hex(32)
env=dict(os.environ,VAULT_DEV_ROOT_TOKEN_ID=root)

def docker(*args):
 return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.DEVNULL).strip()

def call(path,data=None,token=None,method=None,expected=200):
 payload=None if data is None else json.dumps(data).encode()
 request=urllib.request.Request(base+'/v1/'+path,data=payload,headers={'X-Vault-Token':token or root,'Content-Type':'application/json'},method=method or ('POST' if data is not None else 'GET'))
 try:
  with urllib.request.urlopen(request,timeout=20) as response:
   status=response.status; raw=response.read()
 except urllib.error.HTTPError as error:
  status=error.code;raw=error.read()
 assert status==expected, f'{path}: expected {expected}, got {status}; errors={json.loads(raw).get("errors",[])}'
 return json.loads(raw) if raw else {}

try:
 subprocess.run(['docker','run','--detach','--name',name,'--cap-add=IPC_LOCK','-e','VAULT_DEV_ROOT_TOKEN_ID','-p','127.0.0.1::8200','-v',str(plugin.parent)+':/plugins:ro','hashicorp/vault:latest','server','-dev','-dev-listen-address=0.0.0.0:8200','-dev-plugin-dir=/plugins'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
 base='http://'+docker('port',name,'8200/tcp')
 for _ in range(100):
  try:
   with urllib.request.urlopen(base+'/v1/sys/health',timeout=2) as response:
    if response.status==200:break
  except (OSError,urllib.error.URLError):time.sleep(.2)
 else:raise RuntimeError('local validation Vault did not become ready')
 call('sys/plugins/catalog/secret/csign-transfer',{'sha256':hashlib.sha256(plugin.read_bytes()).hexdigest(),'command':'chain-signer-plugin'},expected=204)
 for mount in ['source','target']:
  call('sys/mounts/'+mount,{'type':'plugin','plugin_name':'csign-transfer'},expected=204)
 call('source/v1/keys',{'key_id':'key-1','chain_family':'tron','custody_mode':'mvp'})
 policy='path "target/v1/custody/*" { capabilities = ["create", "update", "read"] }\npath "source/v1/custody/*" { capabilities = ["create", "update", "read"] }'
 call('sys/policies/acl/custody-no-sudo',{'policy':policy},expected=204)
 ordinary=call('auth/token/create',{'policies':['custody-no-sudo'],'no_default_policy':True})['auth']['client_token']
 # Every route including trailing slash must reject even an explicit update ACL.
 denied=0
 for mount in ['source','target']:
  for action in ['prepare','export','import','activate','abort','status']:
   for suffix in ['','/']:
    call(mount+'/v1/custody/'+action+suffix,{},token=ordinary,expected=400 if suffix else 403);denied+=1
 call('sys/policies/acl/custody-operator',{'policy':policy.replace('["create", "update", "read"]','["create", "update", "read", "sudo"]')},expected=204)
 operator=call('auth/token/create',{'policies':['custody-operator'],'no_default_policy':True})['auth']['client_token']
 selection={'transfer_id':'local-proof','checkpoint':'a'*64,'key_ids':['key-1']}
 receiver=call('target/v1/custody/prepare',selection,token=operator)['data']
 assert 'private' not in json.dumps(receiver) and 'AGE-SECRET' not in json.dumps(receiver)
 exported=call('source/v1/custody/export',{'selection':selection,'recipient':receiver['recipient']},token=operator)['data']
 request={'transfer_id':'local-proof','ciphertext':exported['ciphertext'],'digest':exported['digest']}
 staged=call('target/v1/custody/import',request,token=operator)['data']
 assert staged['phase']=='staged'
 assert call('target/v1/keys/key-1')['data']['active'] is False
 call('target/v1/key-status/key-1',{'active':True},expected=409)
 assert call('source/v1/keys/key-1')['data']['active'] is True
 # Restart the plugin without replacing the Vault or the mount's persisted state.
 call('sys/plugins/reload/backend',{'plugin':'csign-transfer'},expected=200)
 assert call('target/v1/keys/key-1')['data']['active'] is False
 assert call('target/v1/custody/import',request,token=operator)['data']==staged
 active=call('target/v1/custody/activate',{'transfer_id':'local-proof','digest':exported['digest'],'fence':'b'*64},token=operator)['data']
 assert active['phase']=='active' and call('target/v1/keys/key-1')['data']['active'] is True
 print(json.dumps({'local_vault_only':True,'ordinary_token_denials':denied//2,'trailing_slash_rejections':denied//2,'sudo_operator_transfer':'PASS','inactive_import':'PASS','status_bypass_rejected':'PASS','plugin_reload_replay':'PASS','explicit_activation':'PASS','source_unchanged':'PASS'}))
finally:
 subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
