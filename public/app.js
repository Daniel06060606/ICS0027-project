const $ = id => document.getElementById(id);
let csrf = '';
let editingId = null;
let expiryTimer;

function message(text) {
  $('message').textContent = text;
}

function clearVault() {
  clearTimeout(expiryTimer);
  $('vault').hidden = true;
  $('auth').hidden = false;
  $('current-user').textContent = '';
  $('entries').replaceChildren();
  $('files').replaceChildren();
  $('file-form').reset();
  resetEntryForm();
}

function resetExpiryTimer() {
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => {
    clearVault();
    message('Session expired. Please log in.');
  }, 30 * 60 * 1000);
}

async function request(path, method = 'GET', data) {
  const headers = {};
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  let body;
  if (data instanceof FormData) body = data;
  else if (data !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(data);
  }
  const response = await fetch(path, { method, headers, body, cache: 'no-store' });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && !$('vault').hidden) {
      clearVault();
      await loadSession();
    }
    throw new Error(result.error || 'Request failed.');
  }
  if (!$('vault').hidden) resetExpiryTimer();
  return result;
}

async function loadSession() {
  const session = await request('/api/session');
  csrf = session.csrf;
  if (session.username) await openVault(session.username);
  else clearVault();
}

async function openVault(username) {
  $('auth').hidden = true;
  $('vault').hidden = false;
  $('current-user').textContent = username;
  resetExpiryTimer();
  await loadEntries();
  await loadFiles();
}

$('auth-form').addEventListener('submit', async event => {
  event.preventDefault();
  const buttons = [...$('auth-form').querySelectorAll('button')];
  const action = event.submitter?.value || 'login';
  buttons.forEach(button => { button.disabled = true; });
  try {
    const session = await request('/api/session');
    csrf = session.csrf;
    const result = await request(`/api/${action}`, 'POST', {
      username: $('auth-username').value,
      password: $('master-password').value
    });
    $('master-password').value = '';
    if (action === 'register') message('Account created. Enter your master password and log in.');
    else {
      csrf = result.csrf;
      await openVault(result.username);
      message('Logged in.');
    }
  } catch (error) {
    $('master-password').value = '';
    message(error.message);
  } finally {
    buttons.forEach(button => { button.disabled = false; });
  }
});

$('logout').addEventListener('click', async () => {
  try {
    await request('/api/logout', 'POST');
    clearVault();
    await loadSession();
    message('Logged out.');
  } catch (error) {
    message(error.message);
  }
});

function resetEntryForm() {
  editingId = null;
  $('entry-form').reset();
  $('entry-heading').textContent = 'Add a password';
  $('cancel-edit').hidden = true;
}

$('cancel-edit').addEventListener('click', resetEntryForm);

$('entry-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await request(editingId ? `/api/entries/${editingId}` : '/api/entries', editingId ? 'PUT' : 'POST', {
      website: $('website').value,
      username: $('entry-username').value,
      password: $('entry-password').value
    });
    resetEntryForm();
    await loadEntries();
    message('Password saved.');
  } catch (error) {
    message(error.message);
  }
});

function button(text, action) {
  const element = document.createElement('button');
  element.type = 'button';
  element.textContent = text;
  element.className = 'secondary';
  element.addEventListener('click', async () => {
    try { await action(element); }
    catch (error) { message(error.message); }
  });
  return element;
}

async function loadEntries() {
  const entries = await request('/api/entries');
  $('entries').replaceChildren();
  $('entries-table').hidden = entries.length === 0;
  $('empty-entries').hidden = entries.length !== 0;
  for (const entry of entries) {
    const row = document.createElement('tr');
    for (const value of [entry.website, entry.username]) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    const passwordCell = document.createElement('td');
    const password = document.createElement('input');
    password.type = 'password';
    password.value = entry.password;
    password.readOnly = true;
    password.setAttribute('aria-label', `Saved password for ${entry.website}`);
    passwordCell.append(password);
    row.append(passwordCell);
    const actions = document.createElement('td');
    actions.append(button('Show', element => {
      password.type = password.type === 'password' ? 'text' : 'password';
      element.textContent = password.type === 'password' ? 'Show' : 'Hide';
    }));
    actions.append(button('Edit', () => {
      editingId = entry.id;
      $('website').value = entry.website;
      $('entry-username').value = entry.username;
      $('entry-password').value = entry.password;
      $('entry-heading').textContent = 'Edit password';
      $('cancel-edit').hidden = false;
      $('website').focus();
    }));
    actions.append(button('Delete', async () => {
      if (!confirm('Delete this password?')) return;
      await request(`/api/entries/${entry.id}`, 'DELETE');
      resetEntryForm();
      await loadEntries();
      message('Password deleted.');
    }));
    row.append(actions);
    $('entries').append(row);
  }
}

$('file-form').addEventListener('submit', async event => {
  event.preventDefault();
  const file = $('file').files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) return message('Maximum file size is 1 MiB.');
  try {
    const data = new FormData();
    data.append('file', file);
    await request('/api/files', 'POST', data);
    $('file-form').reset();
    await loadFiles();
    message('File encrypted and saved.');
  } catch (error) {
    message(error.message);
  }
});

async function loadFiles() {
  const files = await request('/api/files');
  $('files').replaceChildren();
  $('empty-files').hidden = files.length !== 0;
  for (const file of files) {
    const item = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = `${file.name} `;
    const download = document.createElement('a');
    download.href = `/api/files/${file.id}`;
    download.textContent = 'Download';
    download.className = 'download';
    download.setAttribute('download', file.name);
    item.append(name, download, button('Delete', async () => {
      if (!confirm('Delete this file?')) return;
      await request(`/api/files/${file.id}`, 'DELETE');
      await loadFiles();
      message('File deleted.');
    }));
    $('files').append(item);
  }
}

loadSession().catch(error => message(error.message));
