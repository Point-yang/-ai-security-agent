import {overview, overviewText, sourceNotices} from './monitoring-ui.js';
const $=id=>document.getElementById(id);
const text=(tag,value)=>{const node=document.createElement(tag);node.textContent=value;return node;};
async function load(){
  const state=await overview();$('catalog-monitor-summary').textContent=overviewText(state);
  const p=new URLSearchParams({limit:'100'});
  if($('source').value)p.set('source_id',$('source').value);
  const response=await fetch('/api/v1/catalog/items?'+p);
  if(!response.ok)throw new Error('目录读取失败：'+response.status);
  const data=await response.json();$('count').textContent=`共 ${data.total} 条已保存元数据目录行；不代表独立漏洞数量。`;
  $('items').replaceChildren();
  if(!data.items.length)$('items').append(text('p','当前没有可展示的目录记录。'));
  for(const item of data.items){
    const section=text('details','');const heading=text('summary',`${item.title} · ${item.kind}`);
    section.append(heading,text('p',item.description||'仅有索引标题，未采集全文。'));
    const source=text('a','查看来源页面 ↗');source.href=item.source_url;source.target='_blank';source.rel='noopener noreferrer';
    const raw=text('a','查看保存的来源字节 ↗');raw.href=`/api/v1/raw-documents/${item.raw_document_id}/content`;raw.target='_blank';raw.rel='noopener noreferrer';
    section.append(source,text('p',`来源 ${item.source_id} · ${item.origin==='live'?'联网采集':'离线回放'} · 版本 ${item.revision} · 证据位置 ${item.evidence_locator} · SHA-256 ${item.raw_sha256}`),raw);
    for(const notice of sourceNotices([item],state.monitoring,state.operations)) {
      const line=text('p',notice.text);line.className='source-freshness'+(notice.warning?' attention':'');section.append(line);
    }
    $('items').append(section);
  }
}
$('source').addEventListener('change',()=>load().catch(error=>{$('message').textContent=error.message;}));
load().catch(error=>{$('message').textContent=error.message;});
