const $ = (q, root = document) => root.querySelector(q);
const $$ = (q, root = document) => [...root.querySelectorAll(q)];
let state = null, lastScanning = false;
let detailAction = null;
let scanStartedAt = 0, renderedBlips = 0;
let selectedDeviceIp = null;
let findingDeviceFilter = null;
let sessionToken = "";
let historyData = null;
let historySubnet = "";
let settingsInitialized = false;
const pageText = {
  dashboard: ["Dashboard", "Übersicht über dein lokales Netzwerk"],
  devices: ["Geräte", "Erkannte Hosts durchsuchen und untersuchen"],
  risks: ["Schwachstellen", "Befunde nach Schweregrad und Gerät"],
  statistics: ["Statistik", "Lokaler Verlauf und Veränderungen deiner Scans"],
  reports: ["Berichte", "Ergebnisse dokumentieren und exportieren"],
  settings: ["Einstellungen", "Scan-Bereich und Prüfprofil konfigurieren"]
};
const riskColors = {Sicher:"var(--green)",Niedrig:"#d4aa00",Mittel:"var(--orange)",Hoch:"var(--red)",Kritisch:"var(--critical)"};

$$(".nav").forEach(button => button.addEventListener("click", () => {
  $$(".nav").forEach(x => x.classList.toggle("active", x === button));
  $$(".page").forEach(x => x.classList.toggle("active", x.id === button.dataset.page));
  $("#page-title").textContent = pageText[button.dataset.page][0];
  $("#page-subtitle").textContent = pageText[button.dataset.page][1];
  if(button.dataset.page === "statistics") loadHistory();
}));
function goToPage(name) { document.querySelector(`.nav[data-page="${name}"]`)?.click(); }
function activateByKeyboard(element, action) {
  element.addEventListener("click", action);
  element.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); action(); }
  });
}
$("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme === "dark" || (!root.dataset.theme && matchMedia("(prefers-color-scheme:dark)").matches);
  root.dataset.theme = dark ? "light" : "dark";
  localStorage.setItem("theme", root.dataset.theme);
});
if (localStorage.getItem("theme")) document.documentElement.dataset.theme = localStorage.getItem("theme");

$("#support-button").addEventListener("click", () => $("#support-dialog").showModal());
$("#support-close").addEventListener("click", () => $("#support-dialog").close());
$("#support-dialog").addEventListener("click", event => {
  if (event.target === $("#support-dialog")) $("#support-dialog").close();
});

function toast(message) {
  const element = $("#toast"); element.textContent = message; element.classList.add("show");
  setTimeout(() => element.classList.remove("show"), 2800);
}
function escapeHtml(value="") {
  const node = document.createElement("span"); node.textContent = String(value); return node.innerHTML;
}
function openDetail(title, html, options={}) {
  $("#detail-kicker").textContent=options.kicker||"AUSWERTUNG";
  $("#detail-title").textContent=title;
  $("#detail-content").innerHTML=html;
  detailAction=options.action||null;
  const secondary=$("#detail-secondary");
  secondary.hidden=!detailAction;
  secondary.textContent=options.actionLabel||"Zur Ansicht";
  $("#detail-dialog").showModal();
}
function closeDetail(){ $("#detail-dialog").close(); }
$("#detail-close").addEventListener("click",closeDetail);
$("#detail-ok").addEventListener("click",closeDetail);
$("#detail-secondary").addEventListener("click",()=>{ closeDetail(); detailAction?.(); });
function summaryData(){ return state?.result?.security_summary||{}; }
function devicesData(){ return state?.result?.devices||[]; }
function detailHealth(){
  const s=summaryData(), devices=devicesData(), sorted=[...devices].sort((a,b)=>b.risk_score-a.risk_score);
  const avg=devices.length?Math.round(devices.reduce((n,d)=>n+d.risk_score,0)/devices.length):0;
  const top3=sorted.length?Math.round(sorted.slice(0,3).reduce((n,d)=>n+d.risk_score,0)/Math.min(3,sorted.length)):0;
  openDetail("So entsteht der Netzwerkzustand",`<p class="detail-copy">Der Netzwerkzustand ist 100 minus dem gewichteten Gesamtrisiko. Ein kritisches Gerät kann dadurch nicht von vielen unauffälligen Geräten verdeckt werden.</p><div class="detail-grid"><div class="detail-stat"><span>Netzwerkzustand</span><strong>${s.health_score??100}/100</strong></div><div class="detail-stat"><span>Gesamtrisiko</span><strong>${s.overall_risk??0}/100</strong></div><div class="detail-stat"><span>Top-3-Durchschnitt</span><strong>${top3}/100</strong></div><div class="detail-stat"><span>Netzdurchschnitt</span><strong>${avg}/100</strong></div></div><div class="detail-formula">55 % kritischstes Gerät + 25 % Top-3 + 20 % Netzdurchschnitt</div>`,{action:()=>goToPage("devices"),actionLabel:"Geräte ansehen"});
}
function navigateToDevice(device){
  goToPage("devices");
  $("#device-search").value=device.ip;
  $("#risk-filter").value="Alle Risiken";
  $("#service-filter").value="all";
  renderDevices(devicesData());
  document.querySelector(`#devices-body tr[data-ip="${CSS.escape(device.ip)}"]`)?.click();
}
function openRisksForDevice(device){
  findingDeviceFilter=device.ip;
  goToPage("risks");
  renderRisks(devicesData());
}
function detailHighest(){
  const s=summaryData(), device=[...devicesData()].sort((a,b)=>b.risk_score-a.risk_score)[0];
  if(!device){openDetail("Noch kein Gerät vorhanden",`<p class="detail-copy">Führe zuerst einen Scan aus.</p>`);return;}
  openDetail("Kritischstes Gerät",`<div class="detail-grid"><div class="detail-stat"><span>Gerät</span><strong>${escapeHtml(device.hostname||device.ip)}</strong></div><div class="detail-stat"><span>Risiko</span><strong>${device.risk_score}/100</strong></div><div class="detail-stat"><span>IP-Adresse</span><strong>${escapeHtml(device.ip)}</strong></div><div class="detail-stat"><span>Befunde</span><strong>${device.findings.length}</strong></div></div><ul class="detail-list">${device.findings.slice(0,6).map(f=>`<li><span>${escapeHtml(f.severity.toUpperCase())}</span><strong>${escapeHtml(f.title)}</strong></li>`).join("")||"<li>Keine Befunde</li>"}</ul>`,{action:()=>navigateToDevice(device),actionLabel:"Gerät öffnen"});
}
function coverageCounts(){const values=devicesData().flatMap(d=>Object.values(d.audit_coverage||{}));return values.reduce((a,v)=>(a[v]=(a[v]||0)+1,a),{});}
function detailCoverage(){
  const s=summaryData(), counts=coverageCounts();
  openDetail("Prüfabdeckung",`<p class="detail-copy">Die Abdeckung berücksichtigt nur tatsächlich anwendbare Prüfungen. Bewusst ausgeschlossene oder technisch nicht belastbare Checks werden separat ausgewiesen.</p><div class="detail-grid"><div class="detail-stat"><span>Abgeschlossen</span><strong>${(counts.completed||0)+(counts.passed||0)}</strong></div><div class="detail-stat"><span>Unklar</span><strong>${counts.inconclusive||0}</strong></div><div class="detail-stat"><span>Nicht anwendbar</span><strong>${counts.not_applicable||0}</strong></div><div class="detail-stat"><span>Bewusst begrenzt</span><strong>${s.limited_checks||0}</strong></div></div><div class="detail-formula">Prüfabdeckung: ${s.coverage_percent||0} %</div>`,{action:()=>goToPage("devices"),actionLabel:"Abdeckung je Gerät"});
}
function detailConfidence(){
  const findings=devicesData().flatMap(d=>d.findings), count=k=>findings.filter(f=>(f.confidence||"medium")===k).length, s=summaryData();
  openDetail("Ergebnisvertrauen",`<p class="detail-copy">Das Vertrauen bewertet die Qualität der Nachweise, nicht die Sicherheit des Netzwerks. Eine hohe Konfidenz bedeutet, dass Befunde direkt beobachtet wurden.</p><div class="detail-grid"><div class="detail-stat"><span>Hohe Konfidenz</span><strong>${count("high")}</strong></div><div class="detail-stat"><span>Mittlere Konfidenz</span><strong>${count("medium")}</strong></div><div class="detail-stat"><span>Niedrige Konfidenz</span><strong>${count("low")}</strong></div><div class="detail-stat"><span>Nachweisqualität</span><strong>${s.confidence_percent||0}%</strong></div></div>`,{action:()=>goToPage("risks"),actionLabel:"Nachweise ansehen"});
}
function detailBoundaries(kind){
  const rows=devicesData().flatMap(d=>(d.audit_log||[]).filter(x=>kind==="unclear"?x.status==="inconclusive":!["completed","passed","not_applicable","inconclusive"].includes(x.status)).map(x=>({...x,device:d.ip})));
  openDetail(kind==="unclear"?"Unklare Prüfungen":"Bewusst begrenzte Prüfungen",`<p class="detail-copy">${kind==="unclear"?"Diese Prüfungen liefen, lieferten aber kein eindeutiges Ergebnis.":"Diese Prüfungen benötigen Inventardaten, Spezialwerkzeuge, ein Opt-in oder sind aus Sicherheitsgründen ausgeschlossen."}</p><ul class="detail-list">${rows.slice(0,80).map(x=>`<li><span>${escapeHtml(x.device)} · ${escapeHtml(x.status)}</span><strong>${escapeHtml(x.check)}</strong></li>`).join("")||"<li>Keine Einträge vorhanden</li>"}</ul>`);
}
$$("[data-detail]").forEach(card=>activateByKeyboard(card,()=>({health:detailHealth,highest:detailHighest,coverage:detailCoverage,confidence:detailConfidence,unclear:()=>detailBoundaries("unclear"),limitations:()=>detailBoundaries("limitations")}[card.dataset.detail]?.())));
function showPorts(){
  const devices=devicesData().filter(d=>d.open_ports.length);
  openDetail("Offene Ports",`<p class="detail-copy">Ein offener Port zeigt einen erreichbaren Dienst, aber nicht automatisch eine Schwachstelle.</p><ul class="detail-list">${devices.map(d=>`<li><span>${escapeHtml(d.hostname||d.ip)}</span><strong>${escapeHtml(d.open_ports.join(", "))}</strong></li>`).join("")||"<li>Keine offenen Ports erkannt</li>"}</ul>`,{action:()=>goToPage("devices"),actionLabel:"Geräte ansehen"});
}
function showFindingType(type){
  const findings=devicesData().flatMap(d=>d.findings.filter(f=>f.finding_type===type).map(f=>({...f,device:d.ip})));
  const label=type==="confirmed"?"Bestätigte Befunde":"Expositionen";
  openDetail(label,`<p class="detail-copy">${type==="confirmed"?"Diese Zustände wurden durch eine konkrete Antwort oder Messung nachgewiesen.":"Diese Dienste sind erreichbar; das allein bestätigt noch keine Verwundbarkeit."}</p><ul class="detail-list">${findings.slice(0,80).map(f=>`<li><span>${escapeHtml(f.device)}</span><strong>${escapeHtml(f.title)}</strong></li>`).join("")||"<li>Keine Einträge vorhanden</li>"}</ul>`,{action:()=>goToPage("risks"),actionLabel:"Befunde ansehen"});
}
$$("[data-jump]").forEach(element=>activateByKeyboard(element,()=>{
  const target=element.dataset.jump;
  if(target==="devices"||target==="risk-chart")goToPage("devices");
  else if(target==="ports")showPorts();
  else if(target==="confirmed"||target==="exposure")showFindingType(target);
}));
function feed(title, detail) {
  const item = document.createElement("div");
  item.innerHTML = `<i></i><p><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></p>`;
  $("#feed").prepend(item);
  while ($("#feed").children.length > 6) $("#feed").lastElementChild.remove();
}
const scanPhases={
  starting:["Scanner wird aktiviert","Netzwerkadapter und Prüfprofil werden vorbereitet."],
  discovery:["Geräte werden entdeckt","ARP-, ICMP- und Namensinformationen werden zusammengeführt."],
  ports:["Dienste werden analysiert","Erreichbare TCP-Dienste und Protokollbanner werden geprüft."],
  audit:["Sicherheits-Audit läuft","TLS, HTTP, Klartextdienste und sichere Protokollchecks werden ausgewertet."],
  assessment:["Risiko wird berechnet","Evidenz, Prüfabdeckung und Gerätewerte werden zusammengeführt."],
  complete:["Scan abgeschlossen","Die Auswertung ist bereit."]
};
function addRadarBlips(target){
  const host=$("#radar-blips");
  while(renderedBlips<target && renderedBlips<42){
    const index=renderedBlips++, angle=(index*137.508)*Math.PI/180;
    const radius=18+((index*37)%76), x=50+Math.cos(angle)*radius*.48, y=50+Math.sin(angle)*radius*.48;
    const blip=document.createElement("i"); blip.className="radar-blip";
    blip.style.left=`${x}%`;blip.style.top=`${y}%`;blip.style.animationDelay=`${(index%7)*.08}s`;
    host.appendChild(blip);
  }
}
function updateScanStage(data){
  const active=data.scanning;
  $(".app").classList.toggle("is-scanning",active);
  $("#scan-stage").hidden=!active;
  if(!active)return;
  if(!scanStartedAt)scanStartedAt=Date.now();
  const phase=scanPhases[data.phase]||scanPhases.starting;
  $("#scan-phase").textContent=phase[0];$("#scan-phase-detail").textContent=phase[1];
  $("#scan-found").textContent=data.discovered||0;
  $("#scan-target").textContent=data.config?.subnet||"—";
  const elapsed=Math.max(0,Math.floor((Date.now()-scanStartedAt)/1000));
  $("#scan-elapsed").textContent=`${Math.floor(elapsed/60)}:${String(elapsed%60).padStart(2,"0")}`;
  $("#phase-progress").style.width=`${Math.max(5,data.progress||5)}%`;
  addRadarBlips(data.discovered||0);
}
async function api(path, options={}) {
  const headers={"Content-Type":"application/json",...(options.headers||{})};
  if(options.method&&options.method!=="GET"&&sessionToken)headers["X-Network-Sentinel-Token"]=sessionToken;
  const response = await fetch(path, {...options,headers});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "Unbekannter Fehler");
  return value;
}
function openConsent() { $("#consent").showModal(); }
$("#scan-top").addEventListener("click", openConsent);
$("#authorized").addEventListener("change", event => $("#confirm-scan").disabled = !event.target.checked);
$("#consent").addEventListener("close", async () => {
  if ($("#consent").returnValue !== "default" || !$("#authorized").checked) return;
  $("#authorized").checked = false; $("#confirm-scan").disabled = true;
  try {
    await api("/api/scan", {method:"POST", body:JSON.stringify({
      authorized:true, subnet:$("#subnet").value, scan_type:$("#scan-type").value,
      ports:$("#ports").value, timeout:$("#timeout").value,
      security_audit:$("#security-audit").checked
    })});
    $("#feed").innerHTML = ""; feed("Scan gestartet", $("#subnet").value); poll();
  } catch (error) { toast(error.message); }
});
function render(data) {
  state = data;
  if(data.session_token)sessionToken=data.session_token;
  if(data.build){$("#app-version").textContent=data.build.display||`v${data.build.version}`;$("#app-version").title=data.build.source==="git"?`Git-Commit ${data.build.commit}${data.build.dirty?" · Arbeitsstand geändert":""}`:"Installierte Paketversion";}
  if(data.config){
    $("#dashboard-subnet").textContent=data.config.subnet||"—";
    $("#local-ip-label").textContent=`Eigene IPv4: ${data.config.local_ip||"nicht erkannt"} · Standardbereich: ${data.config.subnet||"—"}`;
    if(!settingsInitialized){
      $("#subnet").value=data.config.subnet||"";
      $("#scan-type").value=data.config.scan_type||"arp";
      $("#ports").value=(data.config.ports||[]).join(",");
      $("#timeout").value=data.config.timeout||1;
      $("#security-audit").checked=Boolean(data.config.security_audit_enabled);
      settingsInitialized=true;
    }
  }
  const supportButton=$("#support-button"),sponsorLink=$("#sponsor-link");
  if(data.sponsor_url){supportButton.hidden=false;sponsorLink.href=data.sponsor_url;}else{supportButton.hidden=true;sponsorLink.removeAttribute("href");}
  const result = data.result, devices = result?.devices || [];
  $(".status-dot").style.background = data.error ? "var(--red)" : data.scanning ? "var(--orange)" : "var(--green)";
  $("#status-title").textContent = data.message;
  $("#status-detail").textContent = data.error || (result ? `${devices.length} Geräte · ${result.finished_at.slice(0,19)}` : "Nur eigene oder autorisierte Netzwerke prüfen");
  $(".loader").hidden = !data.scanning;
  $("#scan-top").disabled = data.scanning;
  $("#scan-top span").textContent = data.scanning ? "Scan läuft …" : result ? "Erneut scannen" : "Scan starten";
  if (data.scanning && !lastScanning) {scanStartedAt=Date.now();renderedBlips=0;$("#radar-blips").innerHTML="";feed("Scan aktiv", data.message);}
  if (!data.scanning && lastScanning) {feed(data.error ? "Scan fehlgeschlagen" : "Scan abgeschlossen", data.message);loadHistory();}
  updateScanStage(data);
  if(!data.scanning&&lastScanning)scanStartedAt=0;
  lastScanning = data.scanning;
  if (!result) return;
  const summary=result.security_summary||{};
  $("#health").textContent=summary.health_score??100;
  $("#overall-risk").textContent=`Gesamtrisiko ${summary.overall_risk??0}/100`;
  $("#highest-risk").textContent=summary.highest_risk??0;
  $("#highest-device").textContent=summary.highest_risk_device||"Noch keine Daten";
  $("#coverage").textContent=`${summary.coverage_percent??0}%`;
  $("#coverage-detail").textContent=`${summary.inconclusive_checks??0} Prüfungen unklar`;
  $("#confidence").textContent=summary.confidence_label||"—";
  $("#confidence-detail").textContent=`${summary.confidence_percent??0}% Nachweisqualität`;
  $("#device-count").textContent=summary.device_count??devices.length;
  $("#port-count").textContent=summary.open_port_count??devices.reduce((sum,d)=>sum+d.open_ports.length,0);
  $("#confirmed-count").textContent=summary.finding_counts?.confirmed??0;
  $("#exposure-count").textContent=summary.finding_counts?.exposure??0;
  $("#unclear-count").textContent=(summary.finding_counts?.inconclusive??0)+(summary.inconclusive_checks??0);
  $("#limited-count").textContent=summary.limited_checks??0;
  renderChart(devices); renderDevices(devices); renderRisks(devices);
  $("#report-status").textContent = `Scan vom ${result.finished_at.slice(0,19)} · ${devices.length} Geräte verfügbar.`;
}
function renderChart(devices) {
  const counts = Object.fromEntries(Object.keys(riskColors).map(k=>[k,devices.filter(d=>d.risk_category===k).length]));
  let cursor=0; const stops=[];
  for (const [key,color] of Object.entries(riskColors)) { const next=cursor+(counts[key]/Math.max(devices.length,1))*100; stops.push(`${color} ${cursor}% ${next}%`); cursor=next; }
  $("#donut").style.background = devices.length ? `conic-gradient(${stops.join(",")})` : "var(--line)";
  $("#donut strong").textContent=devices.length;
  $("#legend").innerHTML=Object.entries(riskColors).map(([key,color])=>`<button class="legend-row" data-risk="${key}"><i style="background:${color}"></i><span>${key}</span><strong>${counts[key]}</strong></button>`).join("");
  $$("#legend [data-risk]").forEach(button=>button.addEventListener("click",event=>{event.stopPropagation();goToPage("devices");$("#risk-filter").value=button.dataset.risk;renderDevices(devicesData());}));
}
function filteredDevices(devices) {
  const q=$("#device-search").value.toLowerCase(), risk=$("#risk-filter").value;
  const service=$("#service-filter").value, sort=$("#device-sort").value;
  const groups={web:[80,443,8080,8443],remote:[22,23,3389,445],database:[1433,3306,5432,6379,27017],infrastructure:[53,389,502,1883,8883]};
  const filtered=devices.filter(d=>{
    const matchesQuery=!q||`${d.ip} ${d.mac} ${d.hostname} ${d.vendor} ${d.open_ports.join(" ")}`.toLowerCase().includes(q);
    const matchesRisk=risk==="Alle Risiken"||d.risk_category===risk;
    const matchesService=service==="all"||(service==="none"?!d.open_ports.length:(groups[service]||[]).some(port=>d.open_ports.includes(port)));
    return matchesQuery&&matchesRisk&&matchesService;
  });
  return filtered.sort((a,b)=>sort==="ip"?a.ip.localeCompare(b.ip,undefined,{numeric:true}):sort==="name"?(a.hostname||a.ip).localeCompare(b.hostname||b.ip):sort==="ports-desc"?b.open_ports.length-a.open_ports.length:b.risk_score-a.risk_score);
}
function devicePresentation(device){
  const ports=new Set(device.open_ports);
  if(ports.has(502)||ports.has(1883)||ports.has(8883))return ["◇","IoT / Infrastruktur"];
  if(ports.has(3306)||ports.has(5432)||ports.has(6379)||ports.has(27017)||ports.has(1433))return ["▥","Datenbankserver"];
  if(ports.has(445)||ports.has(3389))return ["▣","Windows-Gerät"];
  if((ports.has(80)||ports.has(443))&&(ports.has(53)||device.ip.endsWith(".1")))return ["◉","Netzwerkgerät"];
  if(ports.has(80)||ports.has(443)||ports.has(8080)||ports.has(8443))return ["▤","Webgerät"];
  if(ports.has(22))return ["⌘","Server"];
  return ["⌁","Netzwerkgerät"];
}
function renderDevices(devices) {
  const filtered=filteredDevices(devices);
  $("#devices-online").textContent=devices.length;
  $("#devices-risky").textContent=devices.filter(d=>d.risk_score>30).length;
  $("#devices-unknown").textContent=devices.filter(d=>!d.hostname).length;
  $("#devices-services").textContent=devices.filter(d=>d.open_ports.length).length;
  $("#device-result-count").textContent=`${filtered.length} von ${devices.length} Geräten`;
  $("#devices-empty").hidden=filtered.length>0;
  $("#devices-body").innerHTML=filtered.map(d=>{const [icon,type]=devicePresentation(d),ports=d.open_ports.slice(0,4).map(p=>`<span class="port-chip">${p}</span>`).join("")+ (d.open_ports.length>4?`<span class="port-chip more">+${d.open_ports.length-4}</span>`:"");return `<tr data-ip="${escapeHtml(d.ip)}" tabindex="0" role="button" aria-label="Details zu ${escapeHtml(d.hostname||d.ip)} öffnen" class="${d.ip===selectedDeviceIp?"selected":""}"><td><div class="device-identity"><span class="device-type-icon">${icon}</span><div><strong>${escapeHtml(d.hostname||"Unbekanntes Gerät")}</strong><small><i class="status-online"></i>${type}</small></div></div></td><td>${escapeHtml(d.ip)}</td><td><div class="mac-vendor"><span>${escapeHtml(d.mac||"Nicht ermittelt")}</span><small>${escapeHtml(d.vendor||"Hersteller unbekannt")}</small></div></td><td><div class="port-list">${ports||'<span class="port-chip">Keine</span>'}</div></td><td><span class="risk-badge" style="background:${riskColors[d.risk_category]}">${d.risk_score} · ${escapeHtml(d.risk_category)}</span></td></tr>`}).join("");
  $$("#devices-body tr").forEach(row=>activateByKeyboard(row,()=>showDevice(devices.find(d=>d.ip===row.dataset.ip))));
}
function showDevice(d) {
  if(!d)return;
  selectedDeviceIp=d.ip; renderDevices(devicesData());
  const [icon,type]=devicePresentation(d);
  $("#device-detail").innerHTML=`<div class="device-detail-head"><div class="device-detail-top"><span class="device-type-icon">${icon}</span><div class="device-detail-title"><h2>${escapeHtml(d.hostname||"Unbekanntes Gerät")}</h2><p>${escapeHtml(type)} · <i class="status-online"></i>Online</p></div><button class="copy-ip" id="copy-device-ip" title="IP-Adresse kopieren">⧉</button><button class="copy-ip" id="close-device-detail" title="Details schließen">×</button></div><div class="device-risk-line"><span class="risk-badge" style="background:${riskColors[d.risk_category]}">${d.risk_score}/100 · ${escapeHtml(d.risk_category)}</span><small>${d.findings.length} Befunde</small></div></div><div class="device-tabs"><button class="active" data-device-tab="overview">Übersicht</button><button data-device-tab="security">Sicherheit</button><button data-device-tab="audit">Prüfungen</button></div><div class="device-tab-content" id="device-tab-content"></div>`;
  $("#copy-device-ip").addEventListener("click",async()=>{try{await navigator.clipboard.writeText(d.ip);toast("IP-Adresse kopiert");}catch{toast(d.ip);}});
  $("#close-device-detail").addEventListener("click",()=>{selectedDeviceIp=null;renderDevices(devicesData());$("#device-detail").innerHTML='<div class="empty-detail"><span>⌁</span><strong>Gerät auswählen</strong><p>Ports, Befunde und Empfehlungen erscheinen hier.</p></div>';});
  $$("[data-device-tab]").forEach(button=>button.addEventListener("click",()=>{$$("[data-device-tab]").forEach(x=>x.classList.toggle("active",x===button));renderDeviceTab(d,button.dataset.deviceTab);}));
  renderDeviceTab(d,"overview");
}
function renderDeviceTab(device,tab){
  const host=$("#device-tab-content"); if(!host)return;
  if(tab==="overview"){
    const services=device.open_ports.map(port=>`<span class="service-badge"><strong>${port}</strong> · ${escapeHtml(device.services[port]||"tcp")}</span>`).join("")||'<span class="service-badge">Keine offenen Dienste</span>';
    host.innerHTML=`<div class="info-grid"><div class="info-box"><span>IP-Adresse</span><strong>${escapeHtml(device.ip)}</strong></div><div class="info-box"><span>Status</span><strong>Online</strong></div><div class="info-box"><span>MAC-Adresse</span><strong>${escapeHtml(device.mac||"Nicht ermittelt")}</strong></div><div class="info-box"><span>Hersteller</span><strong>${escapeHtml(device.vendor||"Unbekannt")}</strong></div><div class="info-box"><span>Hostname</span><strong>${escapeHtml(device.hostname||"Nicht ermittelt")}</strong></div><div class="info-box"><span>Letzte Aktivität</span><strong>${escapeHtml((device.last_seen||"").slice(0,19)||"—")}</strong></div></div><div class="detail-block"><h3>Erreichbare Dienste</h3><div class="service-list">${services}</div></div><div class="detail-action-row"><button class="secondary" id="overview-findings">Schwachstellen anzeigen</button></div>`;
    $("#overview-findings").addEventListener("click",()=>openRisksForDevice(device));
  }else if(tab==="security"){
    const color=f=>f.severity==="critical"?"var(--critical)":f.severity==="high"?"var(--red)":f.severity==="medium"?"var(--orange)":"var(--blue)";
    host.innerHTML=`<div class="detail-block"><h3>Gefundene Schwachstellen</h3>${device.findings.map((f,index)=>`<div class="finding-card" data-device-finding="${index}" style="--finding-color:${color(f)}"><strong>${escapeHtml(f.title)}</strong><small>${escapeHtml(f.severity.toUpperCase())} · ${escapeHtml(f.finding_type)} · ${f.points} Punkte</small></div>`).join("")||'<p class="detail-copy">Keine relevanten Befunde erkannt.</p>'}</div><div class="detail-block"><h3>Compliance</h3><div class="compliance-list">${Object.entries(device.compliance||{}).map(([name,passed])=>`<span class="compliance-chip ${passed?"pass":"fail"}">${escapeHtml(name.toUpperCase())}: ${passed?"OK":"NICHT ERFÜLLT"}</span>`).join("")||"Nicht bewertet"}</div></div>`;
    $$('[data-device-finding]').forEach(item=>item.addEventListener('click',()=>showFindingDetail({device:device.ip,...device.findings[Number(item.dataset.deviceFinding)]})));
  }else{
    const coverage=Object.entries(device.audit_coverage||{}),measurable=["completed","passed","inconclusive"];
    const passed=coverage.filter(([,status])=>["completed","passed"].includes(status)).length,total=coverage.filter(([,status])=>measurable.includes(status)).length,percent=total?Math.round(passed/total*100):0,limited=coverage.filter(([,status])=>![...measurable,"not_applicable"].includes(status)).length;
    host.innerHTML=`<div class="coverage-row"><div><strong>Ausgeführte Prüfungen</strong><span>${percent}% · ${limited} begrenzt</span></div><div class="coverage-bar"><i style="width:${percent}%"></i></div></div><div class="detail-block"><h3>Prüfstatus</h3>${coverage.map(([name,status])=>`<div class="audit-entry"><strong>${escapeHtml(name)}</strong><span>${escapeHtml(status)}</span></div>`).join("")||'<p class="detail-copy">Audit nicht aktiviert.</p>'}</div><div class="detail-block"><h3>Audit-Trail</h3>${(device.audit_log||[]).slice(-12).reverse().map(entry=>`<div class="audit-entry"><strong>${escapeHtml(entry.check)} · ${escapeHtml(entry.status)}</strong><span>${escapeHtml((entry.timestamp||"").slice(0,19))}${entry.detail?` · ${escapeHtml(entry.detail)}`:""}</span></div>`).join("")||'<p class="detail-copy">Keine Protokolleinträge.</p>'}</div>`;
  }
}
function showFindingDetail(finding){
  if(!finding)return;
  const device=devicesData().find(d=>d.ip===finding.device);
  const severityInfo={
    critical:["Kritisch","Unverzüglich prüfen und priorisiert behandeln.","var(--critical)"],
    high:["Hoch","Zeitnah untersuchen und beheben.","var(--red)"],
    medium:["Mittel","Im regulären Maßnahmenplan bearbeiten.","var(--orange)"],
    low:["Niedrig","Härtung bei nächster Wartung berücksichtigen.","var(--blue)"],
    info:["Information","Dokumentieren und bei Bedarf manuell prüfen.","var(--muted)"]
  }[finding.severity]||[finding.severity,"Manuell bewerten.","var(--muted)"];
  const typeText={confirmed:"Direkt durch eine Serverantwort oder Messung bestätigt.",exposure:"Ein Dienst ist erreichbar; eine konkrete Verwundbarkeit ist damit nicht bewiesen.",inconclusive:"Die Prüfung lieferte kein abschließendes Ergebnis."}[finding.finding_type]||"Technischer Sicherheitshinweis.";
  const confidenceText={high:"Eindeutiger technischer Nachweis",medium:"Plausibler Hinweis mit möglichem Kontextbedarf",low:"Schwacher Hinweis, manuelle Bestätigung empfohlen"}[finding.confidence]||"Konfidenz nicht bewertet";
  const compliance=device?Object.entries(device.compliance||{}).map(([name,passed])=>`<span class="compliance-chip ${passed?"pass":"fail"}">${escapeHtml(name.toUpperCase())}: ${passed?"OK":"NICHT ERFÜLLT"}</span>`).join(""):"";
  openDetail(finding.title,`<div class="vulnerability-hero"><span class="severity-orb" style="--severity-color:${severityInfo[2]}">!</span><div><span class="risk-badge" style="background:${severityInfo[2]}">${escapeHtml(severityInfo[0])}</span><p>${escapeHtml(severityInfo[1])}</p></div></div><div class="detail-grid"><div class="detail-stat"><span>Betroffenes Gerät</span><strong>${escapeHtml(device?.hostname||finding.device)}</strong><small>${escapeHtml(finding.device)}</small></div><div class="detail-stat"><span>Risikobeitrag</span><strong>+${finding.points||0} Punkte</strong><small>${escapeHtml(finding.code||"Ohne Regelcode")}</small></div><div class="detail-stat"><span>Befundtyp</span><strong>${escapeHtml(finding.finding_type||"exposure")}</strong><small>${escapeHtml(typeText)}</small></div><div class="detail-stat"><span>Konfidenz</span><strong>${escapeHtml(finding.confidence||"medium")}</strong><small>${escapeHtml(confidenceText)}</small></div></div><section class="finding-section"><h3>Beschreibung</h3><p>${escapeHtml(finding.description||"Keine zusätzliche Beschreibung vorhanden.")}</p></section><section class="finding-section evidence"><h3>Technischer Nachweis</h3><code>${escapeHtml(finding.evidence||"Kein zusätzlicher Nachweis verfügbar.")}</code></section><section class="finding-section recommendation"><h3>Empfohlene Maßnahme</h3><p>${escapeHtml(finding.recommendation||"Manuelle Bewertung durchführen.")}</p></section>${finding.cve?`<section class="finding-section"><h3>CVE-Referenz</h3><p>${escapeHtml(finding.cve)}</p></section>`:""}${compliance?`<section class="finding-section"><h3>Compliance des Geräts</h3><div class="compliance-list">${compliance}</div></section>`:""}`,{kicker:"SCHWACHSTELLENDETAIL",action:device?()=>navigateToDevice(device):null,actionLabel:"Betroffenes Gerät öffnen"});
}
function renderRisks(devices) {
  const rank={critical:0,high:1,medium:2,low:3,info:4};
  const filteredDevice=findingDeviceFilter?devices.find(d=>d.ip===findingDeviceFilter):null;
  if(findingDeviceFilter&&!filteredDevice)findingDeviceFilter=null;
  const sourceDevices=filteredDevice?[filteredDevice]:devices;
  const findings=sourceDevices.flatMap(d=>d.findings.map(f=>({device:d.ip,...f}))).sort((a,b)=>(rank[a.severity]??9)-(rank[b.severity]??9));
  $("#finding-count").textContent=filteredDevice?`${findings.length} Befunde auf ${filteredDevice.hostname||filteredDevice.ip}`:`${findings.length} offene Befunde`;
  $("#finding-subtitle").textContent=filteredDevice?`Nur ${filteredDevice.ip} · nach Schweregrad sortiert`:"Nach Schweregrad sortiert";
  $("#active-device-filter").hidden=!filteredDevice;
  $("#active-device-filter-name").textContent=filteredDevice?`${filteredDevice.hostname||filteredDevice.ip} · Filter aufheben`:"";
  $("#risks-empty").hidden=findings.length>0;
  $("#risks-body").innerHTML=findings.map((f,index)=>`<tr tabindex="0" role="button" data-finding-index="${index}" aria-label="Details zu ${escapeHtml(f.title)} öffnen"><td><span class="risk-badge" style="background:${f.severity==="critical"?"var(--critical)":f.severity==="high"?"var(--red)":f.severity==="medium"?"var(--orange)":"var(--blue)"}">${escapeHtml(f.severity.toUpperCase())}</span></td><td>${escapeHtml(f.title)}<br><small>${escapeHtml(f.finding_type||"exposure")}</small></td><td>${escapeHtml(f.device)}</td><td>${escapeHtml(f.evidence||"—")}<br><small>Konfidenz: ${escapeHtml(f.confidence||"medium")}</small></td><td>${escapeHtml(f.recommendation)}</td></tr>`).join("");
  $$("#risks-body [data-finding-index]").forEach(row=>activateByKeyboard(row,()=>showFindingDetail(findings[Number(row.dataset.findingIndex)])));
}
$("#active-device-filter").addEventListener("click",()=>{findingDeviceFilter=null;renderRisks(devicesData());});
$("#device-search").addEventListener("input",()=>state?.result&&renderDevices(state.result.devices));
$("#risk-filter").addEventListener("change",()=>state?.result&&renderDevices(state.result.devices));
$("#service-filter").addEventListener("change",()=>state?.result&&renderDevices(state.result.devices));
$("#device-sort").addEventListener("change",()=>state?.result&&renderDevices(state.result.devices));
function clearDeviceFilters(){
  $("#device-search").value="";$("#risk-filter").value="Alle Risiken";
  $("#service-filter").value="all";$("#device-sort").value="risk-desc";
  if(state?.result)renderDevices(state.result.devices);
}
$("#clear-device-filters").addEventListener("click",clearDeviceFilters);
$("#empty-clear-filters").addEventListener("click",clearDeviceFilters);
function formatHistoryDate(value){if(!value)return "—";const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString("de-DE",{dateStyle:"medium",timeStyle:"short"});}
function changeText(value,positiveIsGood=false){if(value===undefined)return ["Kein Vergleich","change-neutral"];if(value===0)return ["Unverändert zum letzten Scan","change-neutral"];const good=positiveIsGood?value>0:value<0;return [`${value>0?"+":""}${value} zum letzten Scan`,good?"change-good":"change-bad"];}
function setChange(selector,value,positiveIsGood=false){const [text,className]=changeText(value,positiveIsGood),node=$(selector);node.textContent=text;node.className=className;}
function renderTrend(scans){
  const chart=$("#trend-chart");if(!scans.length){chart.innerHTML='<div class="empty-chart">Nach dem ersten Scan erscheint hier der Verlauf.</div>';return;}
  const width=760,height=220,pad=24,count=Math.max(1,scans.length-1),point=(scan,key,index)=>`${pad+(index/count)*(width-pad*2)},${height-pad-(Number(scan[key]||0)/100)*(height-pad*2)}`;
  const health=scans.map((scan,index)=>point(scan,"health_score",index)).join(" "),risk=scans.map((scan,index)=>point(scan,"overall_risk",index)).join(" ");
  const grids=[0,25,50,75,100].map(value=>{const y=height-pad-(value/100)*(height-pad*2);return `<line class="chart-grid" x1="${pad}" y1="${y}" x2="${width-pad}" y2="${y}"/><text class="chart-label" x="0" y="${y+3}">${value}</text>`}).join("");
  const dots=(key,color)=>scans.map((scan,index)=>{const [x,y]=point(scan,key,index).split(",");return `<circle class="chart-dot" fill="${color}" cx="${x}" cy="${y}" r="4"><title>${formatHistoryDate(scan.timestamp)} · ${scan[key]}/100</title></circle>`}).join("");
  chart.innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Verlauf von Netzwerkzustand und Risiko">${grids}<polyline class="chart-health" points="${health}"/><polyline class="chart-risk" points="${risk}"/>${dots("health_score","var(--green)")}${dots("overall_risk","var(--red)")}</svg>`;
}
function renderHistory(data){
  historyData=data;historySubnet=data.selected_subnet||historySubnet;const latest=data.latest||{},changes=data.changes||{},scans=data.scans||[],networks=data.networks||[];
  const selector=$("#statistics-subnet");selector.innerHTML=networks.map(network=>`<option value="${escapeHtml(network.subnet)}">${escapeHtml(network.subnet)} · ${network.scan_count} ${network.scan_count===1?"Scan":"Scans"}</option>`).join("")||`<option value="${escapeHtml(historySubnet)}">${escapeHtml(historySubnet||"Noch keine Daten")}</option>`;selector.value=historySubnet;
  const tabs=$("#network-stat-tabs");tabs.hidden=networks.length<2;tabs.innerHTML=networks.map(network=>`<button class="${network.subnet===historySubnet?"active":""}" data-stat-subnet="${escapeHtml(network.subnet)}"><strong>${escapeHtml(network.subnet)}</strong><small>${network.scan_count} Scans · Zustand ${network.latest_health}/100</small></button>`).join("");
  $$("#network-stat-tabs [data-stat-subnet]").forEach(button=>button.addEventListener("click",()=>loadHistory(button.dataset.statSubnet)));
  $("#history-total").textContent=data.total_scans||0;$("#history-period").textContent=scans.length?`Seit ${formatHistoryDate(scans[scans.length-1].timestamp)}`:"Noch keine Daten";
  $("#history-health").textContent=data.latest?`${latest.health_score}/100`:"—";$("#history-risk").textContent=data.latest?`${latest.overall_risk}/100`:"—";$("#history-findings").textContent=data.latest?latest.findings:"—";
  setChange("#history-health-change",changes.health_score,true);setChange("#history-risk-change",changes.overall_risk);setChange("#history-findings-change",changes.findings);renderTrend(data.trend||[]);
  $("#history-insights").innerHTML=`<div class="insight-row"><span>Bester Netzwerkzustand</span><strong>${data.best_health||0}/100</strong></div><div class="insight-row"><span>Höchstes gemessenes Risiko</span><strong>${data.worst_risk||0}/100</strong></div><div class="insight-row"><span>Ø Geräte pro Scan</span><strong>${data.averages?.devices||0}</strong></div><div class="insight-row"><span>Ø Befunde pro Scan</span><strong>${data.averages?.findings||0}</strong></div>`;
  $("#history-count").textContent=`${scans.length} ${scans.length===1?"Scan":"Scans"}`;$("#history-empty").hidden=scans.length>0;
  $("#history-body").innerHTML=scans.map((scan,index)=>`<tr tabindex="0" role="button" data-history-index="${index}"><td>${escapeHtml(formatHistoryDate(scan.timestamp))}<br><small>${scan.duration_seconds}s Laufzeit</small></td><td>${escapeHtml(scan.subnet)}</td><td>${scan.devices}</td><td>${scan.open_ports}</td><td>${scan.findings}<br><small>${scan.critical_findings} kritisch · ${scan.high_findings} hoch</small></td><td><span class="risk-badge" style="background:${scan.overall_risk>=61?'var(--red)':scan.overall_risk>=31?'var(--orange)':'var(--green)'}">${scan.overall_risk}/100</span></td><td>${scan.health_score}/100</td></tr>`).join("");
  $$("#history-body [data-history-index]").forEach(row=>activateByKeyboard(row,()=>openHistoryDetail(scans[Number(row.dataset.historyIndex)])));
}
async function loadHistory(subnet=""){try{const requested=subnet||historySubnet||state?.config?.subnet||"";renderHistory(await api(`/api/history${requested?`?subnet=${encodeURIComponent(requested)}`:""}`));}catch(error){toast(`Historie: ${error.message}`);}}
async function openHistoryDetail(summary){
  try{const payload=await api(`/api/history/${encodeURIComponent(summary.id)}`),result=payload.result||{},devices=result.devices||[],findings=devices.flatMap(device=>(device.findings||[]).map(finding=>({...finding,device:device.hostname||device.ip})));
    openDetail(`Scan vom ${formatHistoryDate(summary.timestamp)}`,`<div class="detail-grid"><div class="detail-stat"><span>Netzwerkzustand</span><strong>${summary.health_score}/100</strong><small>Risiko ${summary.overall_risk}/100</small></div><div class="detail-stat"><span>Erkannte Geräte</span><strong>${summary.devices}</strong><small>${summary.scanned_hosts} Ziele geprüft</small></div><div class="detail-stat"><span>Offene Ports</span><strong>${summary.open_ports}</strong><small>${escapeHtml(summary.subnet)}</small></div><div class="detail-stat"><span>Sicherheitsbefunde</span><strong>${summary.findings}</strong><small>${summary.critical_findings} kritisch · ${summary.high_findings} hoch</small></div></div><section class="finding-section"><h3>Geräte dieses Scans</h3><ul class="detail-list">${devices.map(device=>`<li><span>${escapeHtml(device.hostname||device.ip)} · ${device.open_ports?.length||0} Ports</span><strong>${device.risk_score||0}/100</strong></li>`).join("")||"<li>Keine Geräte erkannt</li>"}</ul></section><section class="finding-section"><h3>Befunde</h3><ul class="detail-list">${findings.slice(0,20).map(finding=>`<li><span>${escapeHtml(finding.device)} · ${escapeHtml(finding.severity)}</span><strong>${escapeHtml(finding.title)}</strong></li>`).join("")||"<li>Keine Befunde</li>"}</ul></section>`,{kicker:"SCAN-DETAIL"});
  }catch(error){toast(error.message);}
}
$("#statistics-subnet").addEventListener("change",event=>loadHistory(event.target.value));
$("#export-statistics").addEventListener("click",async()=>{try{const value=await api("/api/history/export",{method:"POST",body:JSON.stringify({subnet:historySubnet})});$("#statistics-export-result").hidden=false;$("#statistics-export-result").textContent=`Statistikbericht für ${historySubnet} erstellt: ${value.path}`;toast("Statistikbericht erstellt");}catch(error){toast(error.message);}});
$$("[data-export]").forEach(button=>button.addEventListener("click",async()=>{
  const formats=button.dataset.export==="all"?["html","json","csv"]:[button.dataset.export];
  try { const value=await api("/api/export",{method:"POST",body:JSON.stringify({formats})}); $("#export-result").hidden=false; $("#export-result").textContent=`Erstellt: ${value.paths.join(" · ")}`; toast("Export abgeschlossen"); }
  catch(error){toast(error.message);}
}));
async function poll() {
  try { render(await api("/api/status")); } catch(error) { $("#status-title").textContent="Verbindung zum lokalen Server unterbrochen"; }
}
poll(); setInterval(poll,1000);
