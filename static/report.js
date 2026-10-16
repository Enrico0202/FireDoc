/* FireDoc report JS — magazine layout.
   Same interactivity as the classic report (search, object usage, collapsible
   policy/vpn/finding cards) adapted to the new .section / .sec-head structure. */
function toggleSection(header){
 var sec=header.closest('.section');
 var collapsed=sec.dataset.collapsed==='true';
 sec.dataset.collapsed=collapsed?'false':'true';
 var caret=header.querySelector('.sec-caret');
 if(caret)caret.textContent=collapsed?'▼':'▶';
}
function toggleSub(header){
 var sub=header.closest('.section-sub');
 var collapsed=sub.dataset.collapsed==='true';
 sub.dataset.collapsed=collapsed?'false':'true';
 setSubState(header, sub.dataset.collapsed);
 setSubVpnCards(sub, sub.dataset.collapsed==='false');
}
function setSubState(header, val){
 /* val = the data-collapsed value: 'false' = open, 'true' = collapsed */
 var state=header.querySelector('.subhead-state');
 if(state)state.textContent=val==='true'?'COLLAPSED':'EXPANDED';
 header.setAttribute('aria-expanded',val==='true'?'false':'true');
}
function setSubVpnCards(sub, open){
 sub.querySelectorAll('.vpn-collapsible').forEach(function(c){
  if(open){
   c.classList.remove('collapsed');
   var caret=c.querySelector('.vpn-caret');if(caret)caret.textContent='▼';
  }else{
   c.classList.add('collapsed');
   var caret2=c.querySelector('.vpn-caret');if(caret2)caret2.textContent='▶';
  }
 });
}
function toggleVpn(header){
 var card=header.closest('.vpn-collapsible');
 card.classList.toggle('collapsed');
 var caret=header.querySelector('.vpn-caret');
 if(caret){caret.textContent=card.classList.contains('collapsed')?'▶':'▼';}
}
function toggleFindings(header){
 var group=header.closest('.finding-group');
 var on=group.classList.toggle('open');
 var state=header.querySelector('.fg-state');
 if(state)state.textContent=on?'EXPANDED':'COLLAPSED';
 header.setAttribute('aria-expanded',on?'true':'false');
}
function togglePolicy(header){
 var card=header.closest('.policy-card');
 var body=card.querySelector('.policy-body');
 if(body.style.display==='none'){body.style.display='block';var c=header.querySelector('.policy-caret');if(c)c.textContent='▼';}
 else{body.style.display='none';var c2=header.querySelector('.policy-caret');if(c2)c2.textContent='▶';}
}
function showObjectUsage(name,ev){
 ev&&ev.stopPropagation();
 clearUsageHighlight();
 // Expand policies section
 var polSec=document.getElementById('policies');
 if(polSec&&polSec.dataset.collapsed==='true'){
  polSec.dataset.collapsed='false';
  var ch=polSec.querySelector('.sec-caret');if(ch)ch.textContent='▼';
 }
 // Expand all policy cards, highlight matches
 var cards=document.querySelectorAll('#policies .policy-card');
 var firstMatch=null;
 cards.forEach(function(card){
  var body=card.querySelector('.policy-body');
  if(body&&body.style.display==='none'){body.style.display='block';var pc=card.querySelector('.policy-caret');if(pc)pc.textContent='▼';}
  var links=card.querySelectorAll('.obj-link');
  var found=false;
  links.forEach(function(l){if(l.textContent.trim()===name)found=true;});
  if(found){
   card.classList.add('pol-usage-hl');
   card.style.boxShadow='0 0 0 2px var(--accent)';
   card.style.borderColor='var(--accent)';
   if(!firstMatch)firstMatch=card;
  }else{
   card.style.opacity='0.35';
  }
 });
 // Show floating close button
 var btn=document.getElementById('usage-close-btn');
 if(!btn){
  btn=document.createElement('div');
  btn.id='usage-close-btn';
  btn.innerHTML='<span class="usage-name"></span> <span class="usage-close-x">✕</span>';
  document.body.appendChild(btn);
 }
 btn.onclick=clearUsageHighlight;
 btn.style.display='flex';
 btn.querySelector('.usage-name').textContent='"'+name+'"';
 if(firstMatch)setTimeout(function(){firstMatch.scrollIntoView({behavior:'smooth',block:'center'});},150);
}
function clearUsageHighlight(){
 document.querySelectorAll('#policies .policy-card').forEach(function(e){e.classList.remove('pol-usage-hl');e.style.opacity='';e.style.boxShadow='';e.style.borderColor='';});
 var btn=document.getElementById('usage-close-btn');
 if(btn)btn.style.display='none';
}

var _searchResults=[],_searchIdx=-1;
function searchReport(){
 var q=document.getElementById('searchInput').value.toLowerCase();
 _searchResults=[];_searchIdx=-1;
 document.querySelectorAll('.sr-hl,.sr-active').forEach(function(e){e.classList.remove('sr-hl','sr-active');});
 if(!q){document.getElementById('searchCount').textContent='0 matches';return;}
 var cells=document.querySelectorAll('td, .finding-title, .poldata-val, .sec-title, .pol-services-list, .pol-services-box, .policy-name, .poldata-bar, .obj-link, .kv span, .mono-list, .stat .val, .big');
 cells.forEach(function(c){
  if(c.textContent.toLowerCase().includes(q)){
   var children=Array.from(c.children);
   var childMatches=children.some(function(ch){return ch.textContent.toLowerCase().includes(q);});
   if(!childMatches){
    c.classList.add('sr-hl');_searchResults.push(c);
   }
   var sub=c.closest('.section-sub');
   if(sub&&sub.dataset.collapsed==='true'){
    sub.dataset.collapsed='false';
    setSubState(sub.querySelector('.subhead'),'false');
    setSubVpnCards(sub,true);
   }
   var fg=c.closest('.finding-group');
   if(fg&&!fg.classList.contains('open')){
    fg.classList.add('open');
    var st=fg.querySelector('.fg-state');if(st)st.textContent='EXPANDED';
    var hd=fg.querySelector('.finding-group-header');if(hd)hd.setAttribute('aria-expanded','true');
   }
   var sec=c.closest('.section');
   if(sec&&sec.dataset.collapsed==='true'){
    sec.dataset.collapsed='false';
    var caret=sec.querySelector('.sec-caret');
    if(caret)caret.textContent='▼';
   }
  }
 });
 var n=_searchResults.length;
 document.getElementById('searchCount').textContent=n+' matches';
}
function searchNext(dir){
 if(!_searchResults.length)return;
 var old=_searchIdx;
 _searchIdx+=dir;
 if(_searchIdx<0)_searchIdx=_searchResults.length-1;
 if(_searchIdx>=_searchResults.length)_searchIdx=0;
 if(old>=0&&_searchResults[old])_searchResults[old].classList.remove('sr-active');
 var el=_searchResults[_searchIdx];
 el.classList.add('sr-active');
 el.scrollIntoView({behavior:'smooth',block:'center'});
 document.getElementById('searchCount').textContent=(_searchIdx+1)+'/'+_searchResults.length+' matches';
}
document.addEventListener('keydown',function(e){
 if(document.activeElement&&document.activeElement.id==='searchInput'){
  if(e.key==='Enter'){e.preventDefault();searchNext(1);}
  if(e.key==='ArrowDown'){e.preventDefault();searchNext(1);}
  if(e.key==='ArrowUp'){e.preventDefault();searchNext(-1);}
 }
});
function scrollToTarget(id){
 var el=document.getElementById(id);
 if(!el)return;
 var fg=el.closest('.finding-group');
  if(fg&&!fg.classList.contains('open')){
   fg.classList.add('open');
   var st=fg.querySelector('.fg-state');if(st)st.textContent='EXPANDED';
   var hd=fg.querySelector('.finding-group-header');if(hd)hd.setAttribute('aria-expanded','true');
  }
  var sub=el.closest('.section-sub');
 if(sub&&sub.dataset.collapsed==='true'){
  sub.dataset.collapsed='false';
  setSubState(sub.querySelector('.subhead'),'false');
  setSubVpnCards(sub,true);
 }
 var sec=el.closest('.section');
 if(sec&&sec.dataset.collapsed==='true'){
  sec.dataset.collapsed='false';
  var caret=sec.querySelector('.sec-caret');
  if(caret)caret.textContent='▼';
 }
 var rect=el.getBoundingClientRect();
 window.scrollTo({top:rect.top+window.scrollY-24,behavior:'smooth'});
 setTimeout(function(){
  el.classList.remove('obj-highlight');
  void el.offsetWidth;
  el.classList.add('obj-highlight');
  setTimeout(function(){el.classList.remove('obj-highlight');},3100);
 },350);
}
// Intercept all internal links (object refs + nav + any #hash)
document.addEventListener('click',function(e){
 var link=e.target.closest('a[href^="#"]');
 if(!link)return;
 var href=link.getAttribute('href');
 if(!href||href==='#')return;
 e.preventDefault();
 scrollToTarget(href.substring(1));
});
// Scroll-spy: highlight the TOC chip for the section in view, keep it in the
// visible part of the chip row.
(function(){
 var sections=Array.prototype.slice.call(document.querySelectorAll('.section'));
 var chips={};
 document.querySelectorAll('.toc a[href^="#"]').forEach(function(a){chips[a.getAttribute('href').slice(1)]=a;});
 var active=null;
 function setActive(id){
  if(active&&chips[active])chips[active].classList.remove('active');
  active=id;
  if(!id||!chips[id])return;
  var a=chips[id];
  a.classList.add('active');
  var bar=a.closest('.toc');
  if(!bar)return;
  var vertical=bar.scrollHeight>bar.clientHeight;
  if(vertical){
   var aT=a.offsetTop,barT=bar.scrollTop,barH=bar.clientHeight;
   if(aT<barT)bar.scrollTop=aT-10;
   else if(aT+a.offsetHeight>barT+barH)bar.scrollTop=aT+a.offsetHeight-barH+10;
  }else{
   var aL=a.offsetLeft,barL=bar.scrollLeft,barW=bar.clientWidth;
   if(aL<barL)bar.scrollLeft=aL-12;
   else if(aL+a.offsetWidth>barL+barW)bar.scrollLeft=aL+a.offsetWidth-barW+12;
  }
 }
 function spy(){
  var y=window.scrollY||document.documentElement.scrollTop;
  var current=null;
  for(var i=0;i<sections.length;i++){
   if(sections[i].offsetTop<=y+90)current=sections[i].id;else break;
  }
  if(current)setActive(current);
 }
 window.addEventListener('scroll',spy,{passive:true});
 spy();
})();
// Start with VPN detail cards collapsed
setTimeout(function(){
 document.querySelectorAll('.vpn-collapsible').forEach(function(c){c.classList.add('collapsed');});
 document.querySelectorAll('.vpn-collapsible .vpn-caret').forEach(function(c){c.textContent='▶';});
}, 100);
