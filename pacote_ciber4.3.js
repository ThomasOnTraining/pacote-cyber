// ==UserScript==
// @name        Pacotao CyberSec - Interceptador (v4.3)
// @namespace   http://tampermonkey.net/
// @version     4.3
// @description Painel para monitorar, editar, reenviar e copiar fetch/XHR e WebSockets. Agora com análise de JWT, editor de cookies e ferramentas de ataque.
// @author      ChatGPT
// @match       *://*/*
// @grant       none
// @run-at      document-start
// ==/UserScript==

(function () {
    'use strict';

    /************************************************************************
     * CONFIGURAÇÕES
     ************************************************************************/
    const CONFIG = {
        minWidth: 500,
        minHeight: 450,
        persistKey: 'tm_cybersec_panel_state_v4_3',
        showOnLoad: true,
    };

    /************************************************************************
     * UTILS
     ************************************************************************/
    function el(tag, props = {}, ...children) {
        const e = document.createElement(tag);
        Object.entries(props).forEach(([k, v]) => {
            if (k === 'style') Object.assign(e.style, v);
            else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.substring(2), v);
            else if (k === 'textContent') e.textContent = v;
            else if (k === 'html') e.innerHTML = v;
            else e.setAttribute(k, v);
        });
        for (const c of children) {
            if (typeof c === 'string') e.appendChild(document.createTextNode(c));
            else if (c instanceof Node) e.appendChild(c);
        }
        return e;
    }

    function saveState(obj) { try { localStorage.setItem(CONFIG.persistKey, JSON.stringify(obj)); } catch (e) { /* ignore */ } }
    function loadState() { try { return JSON.parse(localStorage.getItem(CONFIG.persistKey) || '{}'); } catch (e) { return {}; } }
    function shorten(s, n) { return s.length > n ? s.slice(0, n - 2) + '…' : s; }
    function headersToObj(h) {
        const obj = {};
        try {
            if (!h) return obj;
            if (typeof h.forEach === 'function') {
                h.forEach((v, k) => obj[k] = v);
            } else {
                for (const pair of h.entries ? h.entries() : []) { obj[pair[0]] = pair[1]; }
            }
        } catch (e) { /* ignore */ }
        return obj;
    }
    function objToCurl(request) {
        const { url, method, headers, body } = request.raw;
        let curl = `curl '${url}' \\\n`;
        curl += `  --request ${method} \\\n`;
        for (const [key, value] of Object.entries(headers)) {
            curl += `  --header '${key}: ${value}' \\\n`;
        }
        if (body) {
            try {
                const jsonBody = JSON.parse(body);
                curl += `  --data-raw '${JSON.stringify(jsonBody)}' \\\n`;
            } catch (e) {
                curl += `  --data-raw '${body}' \\\n`;
            }
        }
        return curl;
    }
    function decodeJwt(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return { header: null, payload: null };
            const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            return { header, payload };
        } catch (e) {
            return { header: null, payload: null };
        }
    }
    function parseJsonWithComments(str) {
        const noComments = str.replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');
        return JSON.parse(noComments);
    }
    function syntaxHighlight(json) {
        if (typeof json !== 'string') {
            json = JSON.stringify(json, undefined, 2);
        }
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) { cls = 'key'; }
                else { cls = 'string'; }
            } else if (/true|false/.test(match)) { cls = 'boolean'; }
            else if (/null/.test(match)) { cls = 'null'; }
            return `<span class="tm-cyber-syntax-${cls}">${match}</span>`;
        });
    }

    /************************************************************************
     * PAINEL GUI
     ************************************************************************/
    const style = `
        #tm-cyber-panel { position: fixed; background: #1a1e26; color: #e6eef8; z-index: 2147483647;
            border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.8); font-family: 'Inter', 'Roboto', 'Arial', sans-serif;
            font-size: 13px; display: flex; flex-direction: column; overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05); resize: both; overflow: auto; }
        #tm-cyber-panel header { display: flex; align-items: center; justify-content: space-between; padding: 10px 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1); cursor: move; }
        #tm-cyber-panel header:active { cursor: grabbing; }
        #tm-cyber-panel header strong { color: #fde047; }
        #tm-cyber-panel header span { font-size: 11px; opacity: 0.8; }
        #tm-cyber-panel .btn-group button { background: rgba(255,255,255,0.05); border: none; color: #cbd5e1;
            padding: 6px 10px; border-radius: 6px; cursor: pointer; transition: background 0.2s; font-weight: 500; }
        #tm-cyber-panel .btn-group button:hover { background: rgba(255,255,255,0.1); }
        #tm-cyber-panel .tabs { display: flex; border-bottom: 1px solid rgba(255,255,255,0.1); }
        #tm-cyber-panel .tab-button { padding: 10px 15px; cursor: pointer; opacity: 0.7; transition: opacity 0.2s; }
        #tm-cyber-panel .tab-button:hover { opacity: 1; }
        #tm-cyber-panel .tab-button.active { opacity: 1; border-bottom: 2px solid #fde047; }
        #tm-cyber-panel .tab-content { flex: 1; overflow: hidden; display: none; padding: 12px; }
        #tm-cyber-panel .tab-content.active { display: flex; flex-direction: row; gap: 12px; }
        #tm-cyber-panel .left-panel { width: 38%; display: flex; flex-direction: column; gap: 10px; min-width: 150px; }
        #tm-cyber-panel .right-panel { flex: 1 1 auto; display: flex; flex-direction: column; gap: 10px; overflow: hidden; min-width: 200px; }
        #tm-cyber-panel .request-list, #tm-cyber-panel .websocket-log { flex: 1 1 auto; overflow-y: auto; padding-right: 5px; background: rgba(255,255,255,0.02); border-radius: 8px; }
        #tm-cyber-panel .request-list-item, #tm-cyber-panel .ws-log-item { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.05); cursor: pointer; transition: background 0.1s; }
        #tm-cyber-panel .request-list-item:hover, #tm-cyber-panel .ws-log-item:hover { background: rgba(255,255,255,0.05); }
        #tm-cyber-panel .request-list-item.selected, #tm-cyber-panel .ws-log-item.selected { background: #334155; }
        #tm-cyber-panel .request-list-item .url { font-weight: 600; font-size: 12px; color: #dbeafe; }
        #tm-cyber-panel .request-list-item .meta, #tm-cyber-panel .ws-log-item .meta { font-size: 10px; opacity: 0.7; margin-top: 2px; }
        #tm-cyber-panel textarea, #tm-cyber-panel input { background: #0b1220; color: #dbeafe; font-family: monospace; border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; padding: 8px; font-size: 12px; }
        #tm-cyber-panel .editor-container { flex: 1; position: relative; overflow: hidden; border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; }
        #tm-cyber-panel .editor-container textarea, #tm-cyber-panel .editor-container pre { position: absolute; top: 0; left: 0; width: 100%; height: 100%; box-sizing: border-box; margin: 0; padding: 8px; font-size: 12px; line-height: 1.5; tab-size: 4; }
        #tm-cyber-panel .editor-container textarea { z-index: 1; background: transparent; color: transparent; caret-color: #fde047; resize: none; overflow: auto; }
        #tm-cyber-panel .editor-container pre { z-index: 0; pointer-events: none; background: #0b1220; overflow: auto; color: #dbeafe; white-space: pre-wrap; word-wrap: break-word; }
        #tm-cyber-panel .editor-container pre .tm-cyber-syntax-key { color: #81e695; }
        #tm-cyber-panel .editor-container pre .tm-cyber-syntax-string { color: #94b5ff; }
        #tm-cyber-panel .editor-container pre .tm-cyber-syntax-number { color: #fde047; }
        #tm-cyber-panel .editor-container pre .tm-cyber-syntax-boolean { color: #90ee90; }
        #tm-cyber-panel .editor-container pre .tm-cyber-syntax-null { color: #ff8b8b; }
        #tm-cyber-panel pre { white-space: pre-wrap; word-wrap: break-word; overflow: auto; }
        #tm-cyber-panel .response-box { max-height: 140px; background: #070e18; color: #86efac; font-size: 11px; }
        #tm-cyber-panel .ws-log-item .sent { color: #93c5fd; }
        #tm-cyber-panel .ws-log-item .recv { color: #fde68a; }
        .toggle-btn { position: fixed; right: 20px; bottom: 20px; width: 40px; height: 40px; background: #fde047;
            color: #1a1e26; border-radius: 50%; border: none; cursor: pointer; font-size: 20px; font-weight: bold;
            box-shadow: 0 4px 10px rgba(0,0,0,0.4); z-index: 2147483647; display: none; align-items: center; justify-content: center; }
        #tm-cyber-panel .footer-info { display: flex; gap: 12px; padding: 12px; border-top: 1px solid rgba(255,255,255,0.05); background: #0b1220; }
        #tm-cyber-panel .footer-info .section { flex: 1; display: flex; flex-direction: column; gap: 6px; }
        #tm-cyber-panel .footer-info .section-title { font-size: 11px; font-weight: 600; opacity: 0.9; color: #cbd5e1; }
        #tm-cyber-panel .footer-info-box { background: rgba(255,255,255,0.02); border-radius: 6px; padding: 8px; max-height: 100px; overflow: auto; font-size: 10px; }
        #tm-cyber-panel .footer-info-box div { padding: 2px 0; border-bottom: 1px dashed rgba(255,255,255,0.05); }
        #tm-cyber-panel .footer-info-box strong { color: #facc15; }
        #tm-cyber-panel .footer-info-box .secure { color: #86efac; }
        #tm-cyber-panel .footer-info-box .insecure { color: #f87171; }
        #tm-cyber-panel .jwt-panel { display: flex; flex-direction: column; gap: 10px; background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; }
        #tm-cyber-panel .jwt-input { width: 100%; box-sizing: border-box; }
        #tm-cyber-panel .attack-panel { display: flex; flex-direction: column; gap: 10px; background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; }
        #tm-cyber-panel .attack-panel h4 { margin: 0; font-size: 14px; color: #fde047; }
        #tm-cyber-panel .attack-panel-controls { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        #tm-cyber-panel .attack-panel-controls input, #tm-cyber-panel .attack-panel-controls label { font-size: 12px; }
    `;

    document.head.appendChild(el('style', { textContent: style }));
    const panel = el('div', { id: 'tm-cyber-panel' });
    const toggleBtn = el('button', { id: 'tm-toggle-btn', class: 'toggle-btn', textContent: 'C', onclick: () => togglePanel(true) });
    const header = el('header', {},
        el('div', { style: { display: 'flex', alignItems: 'center', gap: '10px' } },
            el('strong', {}, 'Pacotão CyberSec'),
            el('span', {}, 'Interceptador GUI v4.3')
        ),
        el('div', { class: 'btn-group' },
            el('button', { onclick: (e) => { e.stopPropagation(); togglePanel(false); }}, '—'),
            el('button', { onclick: (e) => { e.stopPropagation(); closePanel(); }}, '✕')
        )
    );
    const tabs = el('div', { class: 'tabs' },
        el('div', { class: 'tab-button active', id: 'requests-tab', onclick: () => switchTab('requests') }, 'Requests'),
        el('div', { class: 'tab-button', id: 'websockets-tab', onclick: () => switchTab('websockets') }, 'WebSockets'),
        el('div', { class: 'tab-button', id: 'tools-tab', onclick: () => switchTab('tools') }, 'Ferramentas')
    );
    const requestsTabContent = el('div', { class: 'tab-content active', id: 'requests-content' });
    const websocketsTabContent = el('div', { class: 'tab-content', id: 'websockets-content' });
    const toolsTabContent = el('div', { class: 'tab-content', id: 'tools-content' });
    const leftPanelReq = el('div', { class: 'left-panel' });
    const rightPanelReq = el('div', { class: 'right-panel' });
    const filtersReq = el('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } },
        el('input', { placeholder: 'filtrar por URL', oninput: (ev) => renderRequestList(ev.target.value) }),
        el('button', { onclick: () => { requestList = []; renderRequestList(); renderDetails(null); }, textContent: 'Limpar' })
    );
    const requestListWrap = el('div', { class: 'request-list' });
    leftPanelReq.appendChild(filtersReq);
    leftPanelReq.appendChild(requestListWrap);
    const detailHeaderReq = el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' }});
    const metaInfoReq = el('div', { style: { fontWeight: '600', fontSize: '13px', opacity: 0.9 } }, 'Detalhes da Requisição');
    const detailActionsReq = el('div', { class: 'btn-group' });
    detailActionsReq.appendChild(el('button', { onclick: onResendOriginal, textContent: 'Reenviar Original' }));
    detailActionsReq.appendChild(el('button', { onclick: onResendModified, textContent: 'Reenviar Modificado' }));
    detailActionsReq.appendChild(el('button', { onclick: onCopyCurl, textContent: 'Copiar cURL' }));
    detailActionsReq.appendChild(el('button', { onclick: onCopyPayload, textContent: 'Copiar Payload' }));
    detailHeaderReq.appendChild(metaInfoReq);
    detailHeaderReq.appendChild(detailActionsReq);
    const editorContainer = el('div', { class: 'editor-container' });
    const requestEditor = el('textarea', { onscroll: (e) => editorHighlight.scrollTop = e.target.scrollTop, oninput: onEditorInput, spellcheck: 'false' });
    const editorHighlight = el('pre', { html: 'Selecione uma requisição...' });
    editorContainer.appendChild(requestEditor);
    editorContainer.appendChild(editorHighlight);
    const responseBox = el('pre', { class: 'response-box', textContent: 'Selecione uma requisição à esquerda...' });
    const attackPanel = el('div', { class: 'attack-panel' },
      el('h4', {}, 'Ferramentas de Ataque'),
      el('div', { class: 'attack-panel-controls' },
        el('label', {}, 'Intervalo (ms):'),
        el('input', { type: 'number', id: 'attack-interval', value: 100, min: 10, style: { width: '60px' }}),
        el('label', {}, 'Payloads:'),
        el('input', { type: 'file', id: 'payload-file', style: { width: '150px' }, onchange: loadPayloads }),
        el('button', { id: 'start-attack-btn', onclick: startAttack, textContent: 'Iniciar Loop' }),
        el('button', { id: 'stop-attack-btn', onclick: stopAttack, textContent: 'Parar Loop', style: { display: 'none' } }),
      ),
      el('pre', { id: 'attack-status', textContent: 'Aguardando...' })
    );

    rightPanelReq.appendChild(detailHeaderReq);
    rightPanelReq.appendChild(editorContainer);
    rightPanelReq.appendChild(el('div', { style: { fontWeight: '600', fontSize: '12px', opacity: 0.9 } }, 'Resposta:'));
    rightPanelReq.appendChild(responseBox);
    rightPanelReq.appendChild(attackPanel);
    requestsTabContent.appendChild(leftPanelReq);
    requestsTabContent.appendChild(rightPanelReq);

    const leftPanelWS = el('div', { class: 'left-panel' });
    const rightPanelWS = el('div', { class: 'right-panel' });
    const filtersWS = el('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } },
        el('input', { placeholder: 'filtrar por URL', oninput: (ev) => renderWSList(ev.target.value) }),
        el('button', { onclick: () => { wsList = []; renderWSList(); renderWSDetails(null); }, textContent: 'Limpar' })
    );
    const wsListWrap = el('div', { class: 'websocket-log' });
    leftPanelWS.appendChild(filtersWS);
    leftPanelWS.appendChild(wsListWrap);
    const detailHeaderWS = el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' }});
    const metaInfoWS = el('div', { style: { fontWeight: '600', fontSize: '13px', opacity: 0.9 } }, 'Detalhes da Mensagem');
    const detailActionsWS = el('div', { class: 'btn-group' });
    detailActionsWS.appendChild(el('button', { onclick: onResendWS, textContent: 'Reenviar' }));
    detailHeaderWS.appendChild(metaInfoWS);
    detailHeaderWS.appendChild(detailActionsWS);
    const wsEditor = el('textarea', {});
    rightPanelWS.appendChild(detailHeaderWS);
    rightPanelWS.appendChild(wsEditor);
    websocketsTabContent.appendChild(leftPanelWS);
    websocketsTabContent.appendChild(rightPanelWS);

    // Tools Tab Content
    const toolsPanel = el('div', { style: { flex: '1', display: 'flex', flexDirection: 'column', gap: '15px' }});
    const jwtPanel = el('div', { class: 'jwt-panel' },
        el('div', { style: { fontWeight: '600', fontSize: '14px', opacity: 0.9 } }, 'Decodificador de JWT'),
        el('input', { id: 'jwt-input', class: 'jwt-input', placeholder: 'Cole o token JWT aqui...', oninput: onDecodeJwt }),
        el('pre', { id: 'jwt-output', textContent: 'O token decodificado aparecerá aqui.' })
    );
    const cookiesEditor = el('div', { style: { flex: '1', display: 'flex', flexDirection: 'column', gap: '10px' }},
        el('div', { style: { fontWeight: '600', fontSize: '14px', opacity: 0.9 } }, 'Editor de Cookies'),
        el('div', { id: 'cookies-editor-list', style: { flex: '1', overflowY: 'auto', paddingRight: '5px' }})
    );
    toolsPanel.appendChild(jwtPanel);
    toolsPanel.appendChild(cookiesEditor);
    toolsTabContent.appendChild(toolsPanel);

    const footer = el('div', { class: 'footer-info' });
    const cookiesSection = el('div', { class: 'section' }, el('div', { class: 'section-title' }, 'Cookies da página'), el('div', { class: 'footer-info-box', id: 'cookies-box' }));
    const scriptsSection = el('div', { class: 'section' }, el('div', { class: 'section-title' }, 'Scripts externos carregados'), el('div', { class: 'footer-info-box', id: 'scripts-box' }));
    footer.appendChild(cookiesSection);
    footer.appendChild(scriptsSection);

    panel.appendChild(header);
    panel.appendChild(tabs);
    panel.appendChild(requestsTabContent);
    panel.appendChild(websocketsTabContent);
    panel.appendChild(toolsTabContent);
    panel.appendChild(footer);
    document.documentElement.appendChild(panel);
    document.documentElement.appendChild(toggleBtn);

    function switchTab(tabId) {
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(`${tabId}-tab`).classList.add('active');
        document.getElementById(`${tabId}-content`).classList.add('active');
        saveState({...loadState(), activeTab: tabId});
        if (tabId === 'tools') {
            renderCookiesEditor();
        }
    }

    function togglePanel(visible) {
        if (visible === true) {
            panel.style.display = 'flex';
            toggleBtn.style.display = 'none';
            saveState({...loadState(), visible: true});
        } else {
            panel.style.display = 'none';
            toggleBtn.style.display = 'flex';
            saveState({...loadState(), visible: false});
        }
    }

    function closePanel() {
        panel.style.display = 'none';
        toggleBtn.style.display = 'flex';
        saveState({...loadState(), visible: false});
    }

    (function makeDraggable(node, handle) {
        let isDown = false, startX, startY;
        handle.addEventListener('mousedown', (e) => {
            if (e.target.tagName === 'BUTTON' || e.target.closest('.btn-group') || e.target.closest('.tabs')) return;
            isDown = true; startX = e.clientX; startY = e.clientY; e.preventDefault();
        });
        window.addEventListener('mousemove', (e) => {
            if (!isDown) return;
            const dx = startX - e.clientX;
            const dy = startY - e.clientY;
            node.style.right = (parseFloat(node.style.right || 20) + dx) + 'px';
            node.style.bottom = (parseFloat(node.style.bottom || 20) + dy) + 'px';
            startX = e.clientX; startY = e.clientY;
        });
        window.addEventListener('mouseup', () => { if (isDown) { isDown = false; }});
    })(panel, header);

    (function makeResizable(node) {
      let isResizing = false;
      const resizeHandle = el('div', { style: { position: 'absolute', bottom: '0', right: '0', width: '15px', height: '15px', cursor: 'nwse-resize', background: 'transparent', zIndex: 10 }});
      node.appendChild(resizeHandle);
      let startX, startY, startWidth, startHeight;
      resizeHandle.addEventListener('mousedown', (e) => {
        isResizing = true; startX = e.clientX; startY = e.clientY;
        startWidth = parseInt(document.defaultView.getComputedStyle(node).width, 10);
        startHeight = parseInt(document.defaultView.getComputedStyle(node).height, 10);
        e.preventDefault();
      });
      window.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const newWidth = startWidth + (e.clientX - startX);
        const newHeight = startHeight + (e.clientY - startY);
        node.style.width = Math.max(CONFIG.minWidth, newWidth) + 'px';
        node.style.height = Math.max(CONFIG.minHeight, newHeight) + 'px';
      });
      window.addEventListener('mouseup', () => {
        if (isResizing) {
          isResizing = false;
          saveState({ ...loadState(), width: panel.style.width, height: panel.style.height, visible: true });
        }
      });
    })(panel);

    /************************************************************************
     * ESTADO E DADOS
     ************************************************************************/
    let requestList = [];
    let currentRequest = null;
    let wsList = [];
    let currentWS = null;
    const wsConnections = new Map();

    // Estado do ataque de loop
    let attackTimer = null;
    let payloads = [];
    let payloadIndex = 0;
    let attackCounter = 0;

    function addRequest(obj) {
        requestList.unshift(obj);
        if (requestList.length > 400) requestList.pop();
        renderRequestList();
    }
    function addWSMessage(obj) {
        wsList.unshift(obj);
        if (wsList.length > 400) wsList.pop();
        renderWSList();
    }
    function renderRequestList(filter = '') {
        requestListWrap.innerHTML = '';
        const f = filter.trim().toLowerCase();
        for (const r of requestList) {
            const url = r.raw.url || '';
            if (f && !url.toLowerCase().includes(f)) continue;
            const item = el('div', {
                class: `request-list-item ${currentRequest && currentRequest.id === r.id ? 'selected' : ''}`,
                onclick: () => { renderDetails(r); }
            },
                el('div', { class: 'url', textContent: `[${r.raw.method}] ${shorten(url, 45)}` }),
                el('div', { class: 'meta', textContent: `${r.type} • ${new Date(r.time).toLocaleTimeString()}` })
            );
            requestListWrap.appendChild(item);
        }
        if (!requestListWrap.firstChild) requestListWrap.appendChild(el('div', { style: { padding: '10px', opacity: 0.6 } }, 'Nenhuma requisição capturada ainda.'));
    }
    function onEditorInput() {
        try {
            const content = requestEditor.value;
            editorHighlight.innerHTML = syntaxHighlight(content);
        } catch (e) {
            editorHighlight.textContent = requestEditor.value;
        }
    }
    function renderDetails(req) {
        currentRequest = req;
        const allItems = requestListWrap.querySelectorAll('.request-list-item');
        allItems.forEach(item => item.classList.remove('selected'));
        if (req) {
            const itemToSelect = Array.from(allItems).find(item => item.textContent.includes(shorten(req.raw.url || '', 45)));
            if (itemToSelect) itemToSelect.classList.add('selected');
        }
        if (!req) {
            metaInfoReq.textContent = 'Detalhes da Requisição';
            requestEditor.value = '';
            editorHighlight.textContent = 'Selecione uma requisição...';
            responseBox.textContent = 'Selecione uma requisição à esquerda...';
            return;
        }
        const r = req.raw;
        metaInfoReq.innerHTML = `URL: ${r.url || ''} &nbsp; • &nbsp; Método: ${r.method || 'N/A'}`;
        const editable = { url: r.url, method: r.method, headers: r.headers || {}, body: r.body || null };
        let pretty = '';
        try { pretty = JSON.stringify(editable, null, 2); } catch (e) { pretty = String(editable); }
        requestEditor.value = pretty;
        onEditorInput();
        responseBox.textContent = req.lastResponse ? `[${req.lastResponse.status}]\n\n${req.lastResponse.text}` : '(sem resposta ainda)';
    }

    function renderWSList(filter = '') {
        wsListWrap.innerHTML = '';
        const f = filter.trim().toLowerCase();
        for (const msg of wsList) {
            const url = msg.raw.url || '';
            const data = msg.raw.data || '';
            if (f && !url.toLowerCase().includes(f) && !data.toLowerCase().includes(f)) continue;
            const msgContent = data.slice(0, 40);
            const item = el('div', {
                class: `ws-log-item ${currentWS && currentWS.id === msg.id ? 'selected' : ''}`,
                onclick: () => { renderWSDetails(msg); }
            },
                el('div', { class: `${msg.type}`, textContent: `[${msg.type.toUpperCase()}] ${shorten(url, 40)}` }),
                el('div', { class: 'meta', textContent: `${new Date(msg.time).toLocaleTimeString()} • ${shorten(msgContent, 50)}...` })
            );
            wsListWrap.appendChild(item);
        }
        if (!wsListWrap.firstChild) wsListWrap.appendChild(el('div', { style: { padding: '10px', opacity: 0.6 } }, 'Nenhuma mensagem de WebSocket capturada ainda.'));
    }

    function renderWSDetails(msg) {
        currentWS = msg;
        const allItems = wsListWrap.querySelectorAll('.ws-log-item');
        allItems.forEach(item => item.classList.remove('selected'));
        if (msg) {
            const itemToSelect = Array.from(allItems).find(item => item.textContent.includes(shorten(msg.raw.url || '', 40)));
            if (itemToSelect) itemToSelect.classList.add('selected');
        }
        if (!msg) {
            metaInfoWS.textContent = 'Detalhes da Mensagem';
            wsEditor.value = '';
            return;
        }
        metaInfoWS.innerHTML = `URL: ${msg.raw.url || ''} &nbsp; • &nbsp; Direção: <span class="${msg.type}">${msg.type.toUpperCase()}</span>`;
        try { wsEditor.value = JSON.stringify(JSON.parse(msg.raw.data), null, 2); } catch (e) { wsEditor.value = msg.raw.data; }
    }

    /************************************************************************
     * EXTRAS: cookies, scripts, jwt decoder
     ************************************************************************/
    function renderCookies() {
        const cookiesBox = document.getElementById('cookies-box');
        if (!cookiesBox) return;
        cookiesBox.innerHTML = '';
        const cookies = document.cookie.split(';').map(s => s.trim()).filter(Boolean);
        for (const c of cookies) {
            const parts = c.split('=');
            const name = parts.shift();
            const val = parts.join('=');
            const insecure = /;?\s*secure/i.test(c) === false;
            cookiesBox.appendChild(el('div', {},
                el('strong', {}, name),
                el('span', { textContent: ` = ${shorten(val, 50)} ` }),
                el('span', { class: insecure ? 'insecure' : 'secure', textContent: insecure ? '(inseguro)' : '(secure)' })
            ));
        }
        if (!cookies.length) cookiesBox.textContent = '(sem cookies)';
    }

    function renderScripts() {
        const scriptsBox = document.getElementById('scripts-box');
        if (!scriptsBox) return;
        scriptsBox.innerHTML = '';
        const scripts = Array.from(document.scripts).map(s => s.src).filter(Boolean);
        for (const s of scripts) {
            scriptsBox.appendChild(el('div', { textContent: shorten(s, 60) }));
        }
        if (!scripts.length) scriptsBox.textContent = '(sem scripts externos)';
    }
    const domObserver = new MutationObserver(muts => {
        for (const m of muts) {
            for (const n of m.addedNodes) {
                if (n.nodeType === 1 && n.tagName === 'SCRIPT' && n.src) {
                    const src = n.src || '(inline)';
                    const scriptsBox = document.getElementById('scripts-box');
                    if (scriptsBox) {
                       scriptsBox.appendChild(el('div', { style: { color: '#fde68a' }, textContent: `Novo script: ${shorten(src, 60)}` }));
                    }
                }
            }
        }
    });
    domObserver.observe(document.documentElement, { childList: true, subtree: true });

    function onDecodeJwt(event) {
        const token = event.target.value.trim();
        const output = document.getElementById('jwt-output');
        if (!token) {
            output.textContent = 'O token decodificado aparecerá aqui.';
            return;
        }
        const { header, payload } = decodeJwt(token);
        if (header && payload) {
            output.textContent = `HEADER:\n${JSON.stringify(header, null, 2)}\n\nPAYLOAD:\n${JSON.stringify(payload, null, 2)}`;
        } else {
            output.textContent = 'Token inválido ou não é um JWT válido.';
        }
    }

    function renderCookiesEditor() {
        const editorList = document.getElementById('cookies-editor-list');
        editorList.innerHTML = '';
        const cookies = document.cookie.split(';').map(s => s.trim()).filter(Boolean);
        if (!cookies.length) {
            editorList.textContent = 'Nenhum cookie encontrado.';
            return;
        }

        cookies.forEach(c => {
            const [name, ...valParts] = c.split('=');
            const value = valParts.join('=');

            const item = el('div', { style: { display: 'flex', flexDirection: 'column', gap: '5px', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }},
                el('div', {}, el('strong', { textContent: name })),
                el('input', { type: 'text', value: value, style: { width: '100%', boxSizing: 'border-box' }}),
                el('div', { style: { display: 'flex', gap: '5px' }},
                    el('button', {
                        onclick: (e) => {
                            const newValue = e.target.previousElementSibling.value;
                            document.cookie = `${name}=${newValue}; path=/;`;
                            renderCookiesEditor();
                            renderCookies();
                            alert(`Cookie '${name}' atualizado! Recarregue a página para ver o efeito.`);
                        },
                        textContent: 'Salvar'
                    }),
                    el('button', {
                        onclick: () => {
                            document.cookie = `${name}=; Max-Age=0; path=/;`;
                            renderCookiesEditor();
                            renderCookies();
                            alert(`Cookie '${name}' removido!`);
                        },
                        textContent: 'Excluir'
                    })
                )
            );
            editorList.appendChild(item);
        });
    }

    /************************************************************************
     * INTERCEPTADORES: fetch, XHR e WebSocket
     ************************************************************************/
    const origFetch = window.fetch.bind(window);
    window.fetch = async function(input, init) {
        try {
            const time = Date.now();
            let url = (typeof input === 'string') ? input : (input && input.url) || '';
            let method = (init && init.method) || (input && input.method) || 'GET';
            let headers = headersToObj((init && init.headers) || (input && input.headers) || {});
            let body = init && init.body ? init.body : null;
            if (body && typeof body !== 'string') {
                try { body = JSON.stringify(body); } catch (e) { body = String(body); }
            }
            const record = { id: 'f-' + Math.random().toString(36).slice(2, 9), time, type: 'fetch', raw: { url, method, headers, body }, lastResponse: null };
            addRequest(record);
            const resp = await origFetch(input, init);
            const clone = resp.clone();
            let text;
            try { text = await clone.text(); } catch (e) { text = '[binary or no text]'; }
            record.lastResponse = { status: resp.status + ' ' + resp.statusText, text: (text || '').slice(0, 20000) };
            if (currentRequest && currentRequest.id === record.id) responseBox.textContent = record.lastResponse.text;
            return resp;
        } catch (err) {
            console.error('Intercept fetch error:', err);
            return origFetch(input, init);
        }
    };
    (function () {
        const OrigXHR = window.XMLHttpRequest;
        function WrappedXHR() {
            const xhr = new OrigXHR();
            let _url = '', _method = '', _headers = {};
            const origOpen = xhr.open;
            const origSend = xhr.send;
            const origSetHeader = xhr.setRequestHeader;
            xhr.open = function (method, url, ...rest) { _method = method ? method.toUpperCase() : 'GET'; _url = url; return origOpen.call(this, method, url, ...rest); };
            xhr.setRequestHeader = function (k, v) { _headers[k] = v; return origSetHeader.call(this, k, v); };
            xhr.send = function (body) {
                try {
                    const time = Date.now();
                    let bodyStr = body;
                    if (body && typeof body !== 'string') { try { bodyStr = JSON.stringify(body); } catch (e) { bodyStr = String(body); } }
                    const record = { id: 'x-' + Math.random().toString(36).slice(2, 9), time, type: 'xhr', raw: { url: _url, method: _method, headers: _headers, body: bodyStr }, lastResponse: null };
                    addRequest(record);
                    this.addEventListener('loadend', function () {
                        try {
                            const text = this.responseText;
                            record.lastResponse = { status: this.status + ' ' + this.statusText, text: (text || '').slice(0, 20000) };
                            if (currentRequest && currentRequest.id === record.id) responseBox.textContent = record.lastResponse.text;
                        } catch (e) { /* ignore */ }
                    });
                    return origSend.call(this, body);
                } catch (err) {
                    console.error('Intercept XHR send error:', err);
                    return origSend.call(this, body);
                }
            };
            return xhr;
        }
        WrappedXHR.prototype = OrigXHR.prototype;
        window.XMLHttpRequest = WrappedXHR;
    })();

    const origWS = window.WebSocket;
    window.WebSocket = function (url, protocols) {
        const ws = new origWS(url, protocols);
        const wsId = 'ws-' + Math.random().toString(36).slice(2, 9);
        ws.url = url; ws.tmId = wsId;
        wsConnections.set(wsId, ws);
        ws.addEventListener('message', function (event) {
            const record = { id: 'wsm-' + Math.random().toString(36).slice(2, 9), wsId: this.tmId, time: Date.now(), type: 'recv', raw: { url: this.url, data: event.data } };
            addWSMessage(record);
        });
        const origSend = ws.send.bind(ws);
        ws.send = function (data) {
            const record = { id: 'wsm-' + Math.random().toString(36).slice(2, 9), wsId: this.tmId, time: Date.now(), type: 'sent', raw: { url: this.url, data: data } };
            addWSMessage(record);
            origSend(data);
        };
        ws.addEventListener('close', function() { wsConnections.delete(this.tmId); });
        return ws;
    };

    /************************************************************************
     * AÇÕES DO USUÁRIO
     ************************************************************************/
    async function resendHttpRequest(requestDetails) {
        const { url, method, headers, body } = requestDetails;
        const opts = { method, headers: headers || {} };
        if (method !== 'GET' && method !== 'HEAD') opts.body = body;
        responseBox.textContent = `(Enviando ${method} para ${url || ''})`;
        try {
            const resp = await origFetch(url, opts);
            const text = await resp.clone().text();
            responseBox.textContent = `STATUS: ${resp.status} ${resp.statusText}\n\n${text.slice(0, 20000)}`;
            if (currentRequest) currentRequest.lastResponse = { status: resp.status + ' ' + resp.statusText, text: (text || '').slice(0, 20000) };
        } catch (err) {
            responseBox.textContent = `Erro ao reenviar: ${String(err)}`;
        }
    }
    function onResendOriginal() {
        if (!currentRequest) return alert('Selecione uma requisição para reenviar.');
        resendHttpRequest(currentRequest.raw);
    }
    function onResendModified() {
        if (!currentRequest) return alert('Selecione uma requisição para reenviar.');
        let parsed;
        try {
            parsed = parseJsonWithComments(requestEditor.value);
        } catch (e) {
            if (!confirm('JSON inválido no editor. Deseja tentar enviar o texto bruto mesmo assim?')) return;
            parsed = null;
        }
        const targetUrl = parsed?.url || currentRequest.raw.url || '';
        const method = (parsed?.method || currentRequest.raw.method || 'GET').toUpperCase();
        const headers = parsed?.headers || currentRequest.raw.headers || {};
        let body = parsed?.body ?? currentRequest.raw.body ?? null;
        try { if (typeof body !== 'string' && body !== null) body = JSON.stringify(body); } catch (e) { body = String(body); }
        resendHttpRequest({ url: targetUrl, method, headers, body });
    }
    function onCopyCurl() {
        if (!currentRequest) return alert('Selecione uma requisição para copiar.');
        const curl = objToCurl(currentRequest);
        navigator.clipboard.writeText(curl).then(() => { alert('Comando cURL copiado para a área de transferência!'); }).catch(err => { console.error('Erro ao copiar cURL:', err); alert('Falha ao copiar o cURL.'); });
    }
    function onCopyPayload() {
        if (!currentRequest || !currentRequest.raw.body) return alert('Selecione uma requisição com corpo (payload) para copiar.');
        navigator.clipboard.writeText(currentRequest.raw.body).then(() => { alert('Payload copiado para a área de transferência!'); }).catch(err => { console.error('Erro ao copiar payload:', err); alert('Falha ao copiar o payload.'); });
    }
    function onResendWS() {
        if (!currentWS) return alert('Selecione uma mensagem de WebSocket para reenviar.');
        const ws = wsConnections.get(currentWS.wsId);
        if (!ws || ws.readyState !== WebSocket.OPEN) return alert('Conexão WebSocket fechada ou não encontrada.');
        try {
            ws.send(wsEditor.value);
            alert('Mensagem enviada com sucesso!');
        } catch (err) {
            console.error('Erro ao reenviar mensagem WS:', err);
            alert('Falha ao enviar a mensagem.');
        }
    }

    /************************************************************************
     * FERRAMENTAS DE ATAQUE
     ************************************************************************/
    function loadPayloads(event) {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            payloads = e.target.result.split('\n').map(p => p.trim()).filter(Boolean);
            document.getElementById('attack-status').textContent = `Arquivo de payloads carregado. Total: ${payloads.length}.`;
        };
        reader.onerror = () => {
            document.getElementById('attack-status').textContent = 'Erro ao carregar o arquivo.';
        };
        reader.readAsText(file);
    }
    async function sendAttackRequest(payload) {
        if (!currentRequest) {
            stopAttack();
            return alert('Nenhuma requisição selecionada para atacar.');
        }
        let requestDetails;
        try {
            const parsed = parseJsonWithComments(requestEditor.value);
            requestDetails = {
                url: parsed.url || currentRequest.raw.url,
                method: parsed.method || currentRequest.raw.method,
                headers: parsed.headers || currentRequest.raw.headers,
                body: parsed.body || currentRequest.raw.body
            };
        } catch (e) {
            document.getElementById('attack-status').textContent = 'Erro: JSON inválido no editor. Parando ataque.';
            stopAttack();
            return;
        }

        // Substituir a string de injeção (ex: INJECT_HERE) pelo payload
        const placeholder = 'INJECT_HERE';
        const newBody = requestDetails.body.includes(placeholder) ? requestDetails.body.replace(placeholder, payload) : payload;

        const opts = { method: requestDetails.method, headers: requestDetails.headers, body: newBody };

        try {
            const resp = await origFetch(requestDetails.url, opts);
            const text = await resp.clone().text();
            document.getElementById('attack-status').textContent = `[${attackCounter}] Payload "${payload}" enviado. Status: ${resp.status}. Resposta: ${shorten(text, 50)}`;
        } catch (err) {
            document.getElementById('attack-status').textContent = `[${attackCounter}] Payload "${payload}" enviado. Erro: ${String(err)}`;
        }
    }
    function startAttack() {
        if (!currentRequest) return alert('Selecione uma requisição para iniciar o ataque.');
        if (!requestEditor.value.includes('INJECT_HERE') && payloads.length > 0) {
            if (!confirm('Nenhuma string "INJECT_HERE" encontrada no corpo da requisição. O payload substituirá todo o corpo. Continuar?')) return;
        }
        if (payloads.length === 0) {
            if (!confirm('Nenhum arquivo de payloads carregado. O ataque será um loop da requisição atual. Continuar?')) return;
        }
        const interval = document.getElementById('attack-interval').value;
        if (interval < 10) return alert('O intervalo deve ser de no mínimo 10ms.');

        attackCounter = 0;
        payloadIndex = 0;
        document.getElementById('start-attack-btn').style.display = 'none';
        document.getElementById('stop-attack-btn').style.display = 'inline-block';
        document.getElementById('attack-status').textContent = `Iniciando ataque... Intervalo: ${interval}ms`;

        attackTimer = setInterval(() => {
            attackCounter++;
            let payload = '';
            if (payloads.length > 0) {
                payload = payloads[payloadIndex];
                sendAttackRequest(payload);
                payloadIndex = (payloadIndex + 1) % payloads.length;
            } else {
                sendAttackRequest('');
            }
        }, interval);
    }
    function stopAttack() {
        if (attackTimer) {
            clearInterval(attackTimer);
            attackTimer = null;
            document.getElementById('start-attack-btn').style.display = 'inline-block';
            document.getElementById('stop-attack-btn').style.display = 'none';
            document.getElementById('attack-status').textContent = `Ataque parado. ${attackCounter} requisições enviadas.`;
        }
    }

    /************************************************************************
     * INICIALIZAÇÃO
     ************************************************************************/
    function init() {
        renderCookies();
        renderScripts();
        renderRequestList();
        renderWSList();
        const st = loadState();
        if (st.width) panel.style.width = st.width;
        if (st.height) panel.style.height = st.height;
        if (st.activeTab) switchTab(st.activeTab);
        if (st.visible === false) {
            panel.style.display = 'none';
            toggleBtn.style.display = 'flex';
        } else if (!CONFIG.showOnLoad) {
            panel.style.display = 'none';
            toggleBtn.style.display = 'flex';
        } else {
            panel.style.right = '20px';
            panel.style.bottom = '20px';
        }
        window.addEventListener('keydown', (e) => { if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'i') togglePanel(panel.style.display === 'none'); });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();