// Headless isolated page acceptance requested by the B handoff. No main DB or cloud call.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('playwright');
const base=process.argv[2] || 'http://127.0.0.1:8036';
const output=path.resolve('output/member-b-collector-recovery-20261006/screenshots');
await fs.mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const page=await browser.newPage({viewport:{width:1365,height:960}});
const errors=[];page.on('pageerror',error=>errors.push(error.message));
const steps=[];
async function scenario(name){const r=await page.request.post(`${base}/__fixture/scenario/${name}`);assert.equal(r.status(),200);steps.push({scenario:name,result:await r.json()});}
async function shot(name){await page.evaluate(()=>{let b=document.getElementById('fixture-banner');if(!b){b=document.createElement('p');b.id='fixture-banner';document.body.prepend(b);}b.style='background:#fff4dd;padding:8px;text-align:center;font-size:13px';b.textContent='隔离页面验收 使用虚构资料和模拟状态 未调用云模型';});await page.screenshot({path:path.join(output,name+'.png'),fullPage:true});const selector=name.includes('answer')?'section.week6-panel':name.includes('catalog')?'main':'#monitoring';await page.locator(selector).screenshot({path:path.join(output,name+'-focus.png')});}
async function answer(){
  if(await page.locator('.rag-options').getAttribute('open')===null) await page.locator('.rag-options > summary').click();
  await page.locator('#rag-key').fill('isolated-review-key');
  await page.locator('#rag-question').fill('GHSA-aaaa-bbbb-cccc 是什么问题？');
  await page.locator('#rag-query').fill('GHSA-aaaa-bbbb-cccc');
  await page.locator('#rag-mode').selectOption('lexical');
  await page.locator('#rag-generation').selectOption('extractive');
  const received=page.waitForResponse(r=>r.url().endsWith('/api/v1/rag/answers') && r.request().method()==='POST');
  await page.locator('#rag-submit').click();const response=await received;assert.equal(response.status(),200);
  const body=await response.json();assert.ok(body.citations.length);await page.waitForFunction(()=>document.querySelectorAll('#rag-output .source-freshness').length>0);
  return body;
}
try {
  await scenario('failure');await page.goto(base+'/');
  await page.waitForFunction(()=>document.getElementById('monitor-counts').textContent.includes('成功 9 · 失败 1 · 当前超期 1'));
  assert.ok((await page.locator('#monitor-targets').innerText()).includes('ConnectTimeout'));
  assert.ok(!(await page.locator('body').innerText()).includes('private proxy'));
  await page.locator('#monitor-windows > details').first().locator('summary').first().click();
  assert.ok((await page.locator('#monitor-windows').innerText()).includes('publication_latency_sla_proven=false'));
  await shot('01-network-failure-desktop');
  await scenario('recovered');await page.reload();
  await page.waitForFunction(()=>document.getElementById('monitor-counts').textContent.includes('成功 10 · 失败 0 · 当前超期 0'));
  await page.waitForFunction(()=>document.getElementById('monitor-windows').textContent.includes('仍有历史断档'));
  await shot('02-recovered-desktop');
  await page.setViewportSize({width:375,height:900});await page.goto(base+'/#monitoring');
  await page.waitForFunction(()=>document.getElementById('monitor-counts').textContent.includes('成功 10'));
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  await shot('03-recovered-mobile');
  await page.setViewportSize({width:1365,height:960});await scenario('stale');await page.goto(base+'/workspace');
  await page.waitForFunction(()=>document.getElementById('research-monitor-summary').textContent.includes('当前超期 10'));
  const stale=await answer();await page.waitForFunction(()=>document.getElementById('rag-output').textContent.includes('资料截至上次成功采集；最新状态未验证'));
  const stored=(await (await page.request.get(base+'/api/v1/rag/runs?limit=1')).json())[0].result.citations;
  assert.deepEqual(stored.map(c=>c.sha256),stale.citations.map(c=>c.sha256));
  await shot('04-api-ready-source-stale-answer');
  await scenario('recovered');await page.locator('#week6-refresh').click();
  await page.waitForFunction(()=>document.getElementById('research-monitor-summary').textContent.includes('当前超期 0'));
  await answer();await page.waitForFunction(()=>document.getElementById('rag-output').textContent.includes('引用仅代表所示版本'));
  await shot('05-fresh-answer');
  await scenario('incomplete');await page.reload();
  await page.waitForFunction(()=>document.getElementById('rag-index-warning').textContent.includes('混合检索当前不可用'));
  const lexical=await answer();assert.equal(lexical.reason,'source_excerpts');
  await shot('06-index-incomplete-lexical-answer');
  await page.goto(base+'/catalog');await page.waitForFunction(()=>document.getElementById('count').textContent.includes('不代表独立漏洞数量'));
  await page.locator('#items details').first().locator('summary').click();await shot('07-catalog-live-replay-boundary');
  assert.deepEqual(errors,[]);
  await fs.writeFile(path.resolve('docs/member-b-collector-recovery-page-tests-20261006.json'),JSON.stringify({checked_at:new Date().toISOString(),status:'passed',isolated:true,cloud_generation:false,real_embedding_inference:false,steps,screenshots:await fs.readdir(output),js_errors:errors},null,2)+'\n');
  console.log('isolated page tests passed');
} finally {await browser.close();}
