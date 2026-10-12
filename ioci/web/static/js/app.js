/* InfraMapper web UI — shared helpers. */
(function () {
  'use strict';
  const IO = window.IO = {};

  IO.api = async function (method, url, data, isForm) {
    const opts = {method, headers: {'X-IOCI': '1', 'Accept': 'application/json'}, credentials: 'same-origin'};
    if (data !== undefined) {
      if (isForm) opts.body = data;
      else { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(data); }
    }
    const res = await fetch(url, opts);
    let payload = null;
    try { payload = await res.json(); } catch (e) {}
    if (res.status === 401) { location.assign('/login?next=' + encodeURIComponent(location.pathname)); throw new Error('signed out'); }
    if (!res.ok) { const e = new Error((payload && (payload.error || payload.message)) || 'HTTP ' + res.status); e.status = res.status; throw e; }
    return payload;
  };
  IO.get = u => IO.api('GET', u);
  IO.post = (u, d) => IO.api('POST', u, d || {});
  IO.qs = () => Object.fromEntries(new URLSearchParams(location.search));
  IO.params = o => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== '' && v != null)).toString();

  IO.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  IO.parse = ts => {
    if (ts == null || ts === '') return null;
    if (typeof ts === 'number' || /^\d{9,13}$/.test(String(ts))) { const n = Number(ts); return new Date(n > 1e12 ? n : n * 1000); }
    const d = new Date(String(ts).replace(' ', 'T')); return isNaN(d) ? null : d;
  };
  IO.fmt = ts => { const d = IO.parse(ts); return d ? d.toLocaleString(undefined, {year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'}) : '—'; };
  IO.date = ts => { const d = IO.parse(ts); return d ? d.toISOString().slice(0, 10) : '—'; };
  IO.ago = ts => {
    const d = IO.parse(ts); if (!d) return '—';
    const s = Math.floor((Date.now() - d) / 1000);
    if (s < 60) return s + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
  };
  IO.when = ts => ts ? `<span title="${IO.esc(IO.fmt(ts))}">${IO.ago(ts)}</span>` : '<span class="small-muted">—</span>';
  IO.num = n => (n == null ? '—' : Number(n).toLocaleString('en-US'));
  IO.trunc = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

  const PRI = {P1: 'CRITICAL', P2: 'HIGH', P3: 'MEDIUM', P4: 'LOW', 'lead-strong': 'MEDIUM'};
  IO.pri = p => p ? `<span class="bpb lv-${PRI[p] || 'LOW'}">${IO.esc(p)}</span>` : '';
  /* compact "P2 7 · P3 7 · leads 12" summary of a case's iocs.csv priorities */
  IO.priSummary = P => {
    const leads = Object.entries(P).filter(([k]) => k.startsWith('lead')).reduce((a, [, v]) => a + v, 0);
    const parts = ['P1', 'P2', 'P3', 'P4'].filter(k => P[k]).map(k => `${IO.pri(k)}&nbsp;${P[k]}`);
    if (leads) parts.push(`<span class="bpb">leads</span>&nbsp;${leads}`);
    return parts.length ? `<span style="white-space:nowrap">${parts.join(' &nbsp;')}</span>` : '<span class="small-muted">—</span>';
  };
  IO.jobState = s => `<span class="bpb ${s === 'done' ? 'sc-completed' : s === 'running' || s === 'queued' ? 'sc-pending' : s === 'cancelled' ? '' : 'sc-failed'}">${s === 'running' ? '<span class="spinner-border spinner-border-sm" style="width:.6rem;height:.6rem"></span> ' : ''}${IO.esc(s)}</span>`;
  IO.typeIcon = t => ({Domain: 'globe', IP: 'hdd-network', URL: 'link-45deg', File: 'file-earmark-binary', report: 'newspaper',
    Report: 'newspaper', Certificate: 'shield-lock', JARM: 'fingerprint', Favicon: 'image', Title: 'type', HtmlHash: 'filetype-html',
    Script: 'filetype-js', NameServer: 'diagram-2', MailServer: 'envelope', SoaEmail: 'envelope-at', ASN: 'bezier2', ThreatLabel: 'tag'})[t] || 'circle';
  IO.seedBadge = t => `<span class="bpb"><i class="bi bi-${IO.typeIcon(t)}"></i>${IO.esc(t || '?')}</span>`;

  IO.toast = function (msg, kind) {
    const box = document.getElementById('bp-toasts');
    const el = document.createElement('div');
    el.className = 'bp-toast ' + (kind || ''); el.textContent = msg;
    box.appendChild(el); setTimeout(() => el.remove(), kind === 'error' ? 9000 : 4500);
  };
  IO.err = e => IO.toast(e && e.message ? e.message : String(e), 'error');
  IO.copy = async t => { try { await navigator.clipboard.writeText(t); IO.toast('Copied', 'ok'); } catch (e) { IO.toast('Copy failed', 'error'); } };

  IO.modal = function (title, html, opts) {
    opts = opts || {};
    const w = document.createElement('div');
    w.className = 'modal fade'; w.tabIndex = -1;
    w.innerHTML = `<div class="modal-dialog modal-dialog-centered modal-dialog-scrollable ${opts.size || ''}"><div class="modal-content">
      <div class="modal-header py-2 px-3"><h5 class="modal-title">${IO.esc(title)}</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">${html}</div>${opts.footer ? `<div class="modal-footer py-2">${opts.footer}</div>` : ''}</div></div>`;
    document.body.appendChild(w);
    const m = new bootstrap.Modal(w); w.addEventListener('hidden.bs.modal', () => w.remove()); m.show();
    return {el: w, close: () => m.hide()};
  };
  IO.confirm = (title, text) => new Promise(resolve => {
    const m = IO.modal(title, `<p class="mb-0">${IO.esc(text)}</p>`, {footer: '<button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-sm btn-primary" data-ok>Confirm</button>'});
    let ok = false; m.el.querySelector('[data-ok]').onclick = () => { ok = true; m.close(); };
    m.el.addEventListener('hidden.bs.modal', () => resolve(ok));
  });

  /* ── scores: number + bar + band word; colour reinforces, never carries meaning alone ── */
  IO.bandOf = s => s == null ? 'insufficient' : s >= 75 ? 'high' : s >= 50 ? 'medium' : s >= 25 ? 'low' : 'very low';
  IO.score = (s, title) => {
    const b = IO.bandOf(s);
    return `<span class="score b-${b.replace(' ', '-')}" title="${IO.esc((title ? title + ': ' : '') + (s == null ? 'insufficient evidence' : s + '/100 · ' + b))}">` +
      `<span class="n">${s == null ? 'n/a' : s}</span><span class="bar" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${s == null ? 0 : s}" aria-label="${IO.esc(title || 'score')}"><i style="width:${s || 0}%"></i></span></span>`;
  };
  IO.scoreCell = (s, title) => `${IO.score(s, title)}<span class="score-lbl">${IO.esc(IO.bandOf(s))}</span>`;
  const FIC = {support: 'bi-plus-circle', conflict: 'bi-exclamation-triangle', limit: 'bi-hourglass-split', info: 'bi-info-circle', term: 'bi-dot'};
  IO.factors = list => (list || []).map(f => `<div class="factor ${f.kind}"><i class="bi ${FIC[f.kind] || 'bi-dot'} ic"></i>
    <div>${IO.esc(f.label)}${f.kind === 'term' ? `<div class="term-bar"><i style="width:${f.value}%"></i></div>` : ''}</div>
    <span class="pts">${f.kind === 'term' ? `${f.value} × ${f.weight} = <b>${f.points}</b>` : f.value != null ? f.value : ''}</span></div>`).join('') || '<div class="small-muted">No factors recorded.</div>';
  IO.epoch = t => t ? IO.date(t) : '—';

  /* ── loading / busy states ── */
  IO.busy = async (btn, fn) => {
    if (!btn || btn.disabled) return;
    const html = btn.innerHTML; btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border" role="status"></span>${btn.dataset.busy || 'Working…'}`;
    try { return await fn(); } finally { btn.disabled = false; btn.innerHTML = html; }
  };
  IO.skeletonRows = (cols, rows) => Array.from({length: rows || 5}, () => `<tr>${Array.from({length: cols}, () => '<td><span class="skel"></span></td>').join('')}</tr>`).join('');
  IO.loadingBox = text => `<div class="empty-state"><span class="spinner-border spinner-border-sm mb-2"></span><div>${IO.esc(text || 'Loading…')}</div></div>`;
  IO.errorBox = (e, retry) => `<div class="empty-state"><i class="bi bi-exclamation-octagon" style="color:var(--danger)"></i>${IO.esc(e && e.message ? e.message : String(e))}${retry ? '<div class="mt-2"><button class="btn btn-sm btn-outline-secondary" data-retry>Retry</button></div>' : ''}</div>`;

  /* ── right-hand drawer (evidence view) ── */
  IO.drawer = function (title, html, footer) {
    let d = document.getElementById('io-drawer');
    if (!d) {
      document.body.insertAdjacentHTML('beforeend', `<div class="drawer-backdrop" id="io-drawer-bd"></div><aside class="drawer" id="io-drawer" role="dialog" aria-modal="true" aria-labelledby="io-drawer-t">
        <div class="drawer-head"><h3 id="io-drawer-t"></h3><button class="btn-close ms-auto" aria-label="Close"></button></div><div class="drawer-body"></div><div class="drawer-foot"></div></aside>`);
      d = document.getElementById('io-drawer');
      const close = () => { d.classList.remove('open'); document.getElementById('io-drawer-bd').classList.remove('open'); };
      d.querySelector('.btn-close').onclick = close;
      document.getElementById('io-drawer-bd').onclick = close;
      document.addEventListener('keydown', e => { if (e.key === 'Escape' && d.classList.contains('open')) close(); });
      IO.closeDrawer = close;
    }
    d.querySelector('#io-drawer-t').innerHTML = title;
    d.querySelector('.drawer-body').innerHTML = html;
    const f = d.querySelector('.drawer-foot'); f.innerHTML = footer || ''; f.style.display = footer ? '' : 'none';
    d.classList.add('open'); document.getElementById('io-drawer-bd').classList.add('open');
    d.querySelector('.drawer-body').scrollTop = 0;
    d.querySelector('.btn-close').focus();
    return d;
  };

  /* quick-investigate box used on several pages */
  IO.quickInvestigate = async function (value) {
    value = (value || '').trim(); if (!value) return;
    try { const j = await IO.post('/api/investigate', {mode: 'ioc', iocs: value}); location.assign('/jobs/' + j.id); } catch (e) { IO.err(e); }
  };

  IO.toggleTheme = function () {
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', cur); document.documentElement.setAttribute('data-bs-theme', cur);
    try { localStorage.setItem('ioci-theme', cur); } catch (e) {}
    const ic = document.getElementById('theme-icon'); if (ic) ic.className = 'bi ' + (cur === 'light' ? 'bi-sun-fill' : 'bi-moon-fill');
  };
  IO.toggleSidebar = function () {
    if (window.innerWidth <= 900) document.body.classList.toggle('sidebar-open'); else document.body.classList.toggle('sidebar-collapsed');
  };
  document.addEventListener('DOMContentLoaded', () => {
    const ic = document.getElementById('theme-icon');
    if (ic && document.documentElement.getAttribute('data-theme') === 'light') ic.className = 'bi bi-sun-fill';
  });
})();
