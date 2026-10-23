// Read-only browser check of the deployed main service. No answers, sync or mutations.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('playwright');
const base='http://127.0.0.1:8010';
const output=path.resolve('output/member-b-collector-recovery-20261007/live-screenshots');
await fs.mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const page=await browser.newPage({viewport:{width:1365,height:960}});
const errors=[],writes=[];
page.on('pageerror',e=>errors.push(e.message));
page.on('request',r=>{if(!['GET','HEAD','OPTIONS'].includes(r.method()))writes.push(r.method());});
try{
 await page.goto(base+'/workspace');
 await page.waitForFunction(()=>document.getElementById('research-monitor-summary').textContent.includes('10 个目标'));
 const summary=await page.locator('#research-monitor-summary').innerText();
 await page.locator('.monitor-compact').screenshot({path:path.join(output,'01-research-status.png')});
 await page.locator('.monitor-compact a').click();
 assert.ok(page.url().endsWith('/#monitoring'));
 await page.waitForFunction(()=>document.getElementById('monitor-counts').textContent.includes('10 个目标'));
 await page.waitForFunction(()=>document.getElementById('monitor-worker').textContent.includes('独立进程心跳检查'));
 const details=await page.locator('#monitor-targets').innerText();
 assert.match(details,/上次成功/);assert.match(details,/下次计划/);assert.match(details,/连续失败/);
 await page.locator('#monitoring').screenshot({path:path.join(output,'02-main-targets-desktop.png')});
 await page.waitForFunction(()=>document.querySelectorAll('#monitor-windows > details').length===2);
 await page.locator('#monitor-windows > details').first().locator('summary').first().click();
 assert.match(await page.locator('#monitor-windows').innerText(),/publication_latency_sla_proven=false/);
 await page.locator('#monitor-windows').screenshot({path:path.join(output,'03-main-window.png')});
 await page.setViewportSize({width:375,height:900});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 await page.locator('#monitoring').screenshot({path:path.join(output,'04-main-targets-mobile.png')});
 assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);
 await fs.writeFile('docs/member-b-collector-recovery-live-pages-20261007.json',JSON.stringify({checked_at:new Date().toISOString(),status:'passed',isolated:false,main_database_mutated:false,cloud_generation:false,source_summary_at_research:summary,detail_navigation_clicks:1,desktop_width:1365,mobile_width:375,js_errors:errors,write_requests:writes,screenshots:await fs.readdir(output)},null,2)+'\n');
 console.log('deployed main pages passed (GET only)');
}finally{await browser.close();}
