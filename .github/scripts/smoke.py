import html,json,os,re,subprocess,sys,tempfile,threading,queue,urllib.request,urllib.parse
from pathlib import Path
from offline_env import offline_environment
executable=sys.argv[1]
def launch(env):
 p=subprocess.Popen([str(Path(executable).resolve())],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8');q=queue.Queue();threading.Thread(target=lambda:q.put(p.stdout.readline()),daemon=True).start()
 try:line=q.get(timeout=30)
 except queue.Empty:p.kill();p.wait();raise RuntimeError('no launcher URL')
 match=re.search(r'http://\S+',line)
 if not match:p.kill();p.wait();raise RuntimeError('launcher failed before opening the UI')
 return p,match.group(0)
def get(url):return urllib.request.urlopen(url,timeout=30).read().decode()
def post(url,fields):
 data=urllib.parse.urlencode(fields).encode()
 return urllib.request.urlopen(urllib.request.Request(url,data=data,headers={'Content-Type':'application/x-www-form-urlencoded'}),timeout=30).read().decode()
with tempfile.TemporaryDirectory(prefix='s3-auditor-',dir=os.environ.get('S3_AUDITOR_SMOKE_TEMP')) as root:
 env=offline_environment(root)
 env['S3_AUDITOR_DATA_DIR']=str(Path(root,'S3Auditor'))
 p,url=launch(env)
 try:
  page=get(url);assert 'Try the guided demo' in page and 'Use my data' in page and 'ZgotmplZ' not in page
  token=urllib.parse.parse_qs(urllib.parse.urlparse(url).query)['token'][0]
  def route(path):return urllib.parse.urljoin(url,path)+'?'+urllib.parse.urlencode({'token':token})
  setup=get(route('/setup'));assert 'Set up your first task' in setup
  assert not list(Path(root).glob('*/onboarding.json')), 'viewing setup marked guide complete'
  assert 'AWS profile' in setup and 'AWS region' in setup and 'Optional bucket names' in setup
  assert 'Check AWS identity without scanning' in setup
  check=post(route('/setup/check'),{'check':'input','profile':'example-profile','region':''})
  assert 'Choose an AWS region' in check and not Path(root,'S3Auditor','history.json').exists()
  page=post(url+'&onboarding=demo',{'action':'demo'})
  assert 'id="results"' in page and 'href="#results"' in page
  assert 'Your first result is ready' in page and 'Guided demo - synthetic data' in page and 'ZgotmplZ' not in page
  assert 'demo-access-denied' in page and 'Unknown' in page
  link=re.search(r'href="(/export[^\"]+)"',page);assert link,'missing export'
  payload=get(urllib.parse.urljoin(url,html.unescape(link.group(1))));value=json.loads(payload)
  assert value['Demo'] and len(value['Reports'])==4 and value['Scope']=='SYNTHETIC DEMO'
  denied=next(row for row in value['Reports'] if row['Name']=='demo-access-denied')
  assert denied['PolicyState']=='unknown' and denied['Errors']
  assert sum(row['PublicPolicy'] or row['IncompleteBlock'] for row in value['Reports'])==2
  blocked=post(url,{'action':'ticket','id':value['ID'],'bucket':'demo-public-policy'})
  assert 'synthetic data cannot create real Jira issues' in blocked
  assert list(Path(root).glob('*/onboarding.json')),'completion not remembered'
  assert 'Try the guided demo' in get(route('/welcome'))
  assert json.loads(get(urllib.parse.urljoin(url,html.unescape(link.group(1)))))==value,'restart guide modified results'
  try:get(url.split('?')[0]);raise AssertionError('missing token allowed')
  except urllib.error.HTTPError as e:assert e.code==403
 finally:p.terminate();p.wait(timeout=15)
 for lock in Path(root).glob('*/application.lock'):lock.unlink()
 p,url=launch(env)
 try:
  page=get(url);assert 'Try the guided demo' not in page and 'Welcome back' in page
  assert 'demo-access-denied' in page
  token=urllib.parse.parse_qs(urllib.parse.urlparse(url).query)['token'][0]
  scans=re.findall(r'href="(/\?token=[^\"]+&scan=[^\"]+)"',page)
  assert len(scans)==1,'restart duplicated a scan'
  restored=json.loads(get(route('/export')+'&id='+value['ID']))
  assert restored==value,'restart changed saved observation time or evidence'
  invalid=post(url,{'action':'scan','region':''})
  assert 'Choose the AWS region first' in invalid
  assert json.loads(get(route('/export')+'&id='+value['ID']))==value
  page=post(url+'&onboarding=demo',{'action':'demo'})
  assert len(re.findall(r'href="(/\?token=[^\"]+&scan=[^\"]+)"',page))==2
  assert json.loads(get(route('/export')+'&id='+value['ID']))==value,'new demo overwrote prior history'
  page=post(url,{'action':'demo-verification'})
  assert 'Remediation verification' in page and 'Controls verified clear' in page
  history=json.loads(Path(root,'S3Auditor','history.json').read_text())
  stages=history['Scans'][-4:]
  assert len(history['Scans'])==6 and all(s['Demo'] and s['Scope']=='SYNTHETIC VERIFICATION DEMO' for s in stages)
  records=[]
  for index,stage in enumerate(stages):
   record=json.loads(get(route('/verification')+'&id='+stage['ID']))
   records.append(record)
   bucket=record['Buckets'][0]
   assert record['Version']==1 and record['Scan']==stage
   assert bucket['OpenConcerns']==(2 if index<3 else 0)
   policy=bucket['Controls'][0]
   assert len(policy['Timeline'])==index+1
   assert policy['Episodes'][0]['FirstObserved']['ScanID']==stages[0]['ID']
   assert (policy['Episodes'][0]['VerifiedClear'] is None)==(index<3)
   if index in (1,2): assert policy['LastKnown']['ScanID']==stages[0]['ID']
   selected=get(route('/')+'&scan='+stage['ID'])
   assert 'Remediation verification' in selected and 'Jira handoff' not in selected
  assert [e['State'] for e in records[-1]['Buckets'][0]['Controls'][0]['Timeline']]==['concern','unknown','not_assessed','clear']
  assert records[-1]['Buckets'][0]['Controls'][4]['Change']=='disabled → enabled'
  assert json.loads(get(route('/export')+'&id='+value['ID']))==value
 finally:p.terminate();p.wait(timeout=15)
 for lock in Path(root).glob('*/application.lock'):lock.unlink()
 p,url=launch(env)
 try:
  token=urllib.parse.parse_qs(urllib.parse.urlparse(url).query)['token'][0]
  for stage,record in zip(stages,records):
   assert json.loads(get(route('/verification')+'&id='+stage['ID']))==record,'restart changed verification history'
 finally:p.terminate();p.wait(timeout=15)
 print('S3 Auditor: packaged welcome, setup, guided demo, four-stage verification, as-of exports and restart persistence PASS')
