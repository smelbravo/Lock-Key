/**
 * Lock & Key - Gestão de Notas Seguras
 */

'use strict';

const NotesState = {
  notes: [],
  currentNote: null,
  searchQuery: '',
  autoSaveTimer: null,
};

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initDashboardLayout();
  LKAutoLock.init();
  await loadNotes();
  initNotesEvents();
});

async function loadNotes() {
  const key = LKCrypto.getSessionKey();
  if (!key) return;

  try {
    const encNotes = await LKApi.getNotes();
    NotesState.notes = await LKCrypto.decryptAllNotes(encNotes, key);
    renderNotesList();
  } catch (err) {
    LKToast.error('Erro ao carregar notas: ' + err.message);
  }
}

function renderNotesList() {
  const listEl  = document.getElementById('notes-list');
  const emptyEl = document.getElementById('notes-empty');
  if (!listEl) return;

  const query = NotesState.searchQuery.toLowerCase();
  const filtered = query
    ? NotesState.notes.filter(n =>
        (n.title || '').toLowerCase().includes(query) ||
        (n.content || '').toLowerCase().includes(query)
      )
    : NotesState.notes;

  if (filtered.length === 0) {
    listEl.innerHTML = '';
    if (emptyEl) emptyEl.classList.remove('hidden');
    return;
  }

  if (emptyEl) emptyEl.classList.add('hidden');

  listEl.innerHTML = filtered.map(note => `
    <div class="note-item ${NotesState.currentNote?.uuid === note.uuid ? 'active' : ''}"
         data-uuid="${LKUtils.escapeHtml(note.uuid)}">
      <div class="note-item-title">${LKUtils.escapeHtml(note.title || 'Sem título')}</div>
      <div class="note-item-date">
        ${note.is_favourite ? '⭐ ' : ''}${LKUtils.formatDate(note.updated_at)}
      </div>
    </div>
  `).join('');

  // Event listeners
  listEl.querySelectorAll('.note-item').forEach(item => {
    item.addEventListener('click', () => {
      const note = NotesState.notes.find(n => n.uuid === item.dataset.uuid);
      if (note) openNote(note);
    });
  });
}

function openNote(note) {
  NotesState.currentNote = note;
  renderNotesList(); // Atualizar seleção

  const placeholder = document.getElementById('note-placeholder');
  const editArea    = document.getElementById('note-edit-area');
  if (placeholder) placeholder.style.display = 'none';
  if (editArea) editArea.style.display = 'flex';

  document.getElementById('note-title-input').value    = note.title || '';
  document.getElementById('note-content-input').value  = note.content || '';
  document.getElementById('note-category-input').value = note.category || '';
  document.getElementById('note-favourite').checked    = note.is_favourite || false;
  document.getElementById('note-char-count').textContent = `${(note.content || '').length} caracteres`;
  document.getElementById('note-last-saved').textContent = 'Guardado ' + LKUtils.formatDate(note.updated_at);
}

function newNote() {
  NotesState.currentNote = null;

  const placeholder = document.getElementById('note-placeholder');
  const editArea    = document.getElementById('note-edit-area');
  if (placeholder) placeholder.style.display = 'none';
  if (editArea) editArea.style.display = 'flex';

  document.getElementById('note-title-input').value    = '';
  document.getElementById('note-content-input').value  = '';
  document.getElementById('note-category-input').value = '';
  document.getElementById('note-favourite').checked    = false;
  document.getElementById('note-char-count').textContent = '0 caracteres';
  document.getElementById('note-last-saved').textContent = 'Não guardado';

  document.getElementById('note-title-input').focus();
  renderNotesList();
}

async function saveCurrentNote() {
  const key = LKCrypto.getSessionKey();
  if (!key) { LKToast.error('Sessão expirada.'); return; }

  const title    = document.getElementById('note-title-input').value.trim();
  const content  = document.getElementById('note-content-input').value;
  const category = document.getElementById('note-category-input').value.trim();
  const favourite = document.getElementById('note-favourite').checked;

  if (!title && !content) {
    LKToast.warning('Adiciona um título ou conteúdo antes de guardar.');
    return;
  }

  const saveBtn = document.getElementById('save-note-btn');
  LKUtils.setButtonLoading(saveBtn, true);

  try {
    const noteData = { title: title || 'Sem título', content, category, is_favourite: favourite };
    const encNote  = await LKCrypto.encryptNote(noteData, key);

    if (NotesState.currentNote) {
      encNote.uuid = NotesState.currentNote.uuid;
      await LKApi.updateNote(encNote);

      // Atualizar em memória
      const idx = NotesState.notes.findIndex(n => n.uuid === NotesState.currentNote.uuid);
      if (idx !== -1) {
        NotesState.notes[idx] = { ...noteData, uuid: NotesState.currentNote.uuid, updated_at: new Date().toISOString() };
        NotesState.currentNote = NotesState.notes[idx];
      }
    } else {
      const res = await LKApi.createNote(encNote);
      const newNote = { ...noteData, uuid: res.data.uuid, created_at: res.data.created_at, updated_at: res.data.created_at };
      NotesState.notes.unshift(newNote);
      NotesState.currentNote = newNote;
    }

    document.getElementById('note-last-saved').textContent = 'Guardado agora mesmo';
    renderNotesList();
    LKToast.success('Nota guardada!', 2000);

  } catch (err) {
    LKToast.error('Erro ao guardar nota: ' + err.message);
  } finally {
    LKUtils.setButtonLoading(saveBtn, false);
  }
}

async function deleteCurrentNote() {
  if (!NotesState.currentNote) return;

  if (!confirm('Tens a certeza que queres eliminar esta nota?')) return;

  try {
    await LKApi.deleteNote(NotesState.currentNote.uuid);
    NotesState.notes = NotesState.notes.filter(n => n.uuid !== NotesState.currentNote.uuid);
    NotesState.currentNote = null;

    const placeholder = document.getElementById('note-placeholder');
    const editArea    = document.getElementById('note-edit-area');
    if (placeholder) placeholder.style.display = 'flex';
    if (editArea) editArea.style.display = 'none';

    renderNotesList();
    LKToast.success('Nota eliminada.');
  } catch (err) {
    LKToast.error('Erro ao eliminar nota: ' + err.message);
  }
}

function initNotesEvents() {
  document.getElementById('new-note-btn')?.addEventListener('click', newNote);
  document.getElementById('empty-note-btn')?.addEventListener('click', newNote);
  document.getElementById('save-note-btn')?.addEventListener('click', saveCurrentNote);
  document.getElementById('delete-note-btn')?.addEventListener('click', deleteCurrentNote);

  // Contador de caracteres
  const contentArea = document.getElementById('note-content-input');
  if (contentArea) {
    contentArea.addEventListener('input', () => {
      document.getElementById('note-char-count').textContent = `${contentArea.value.length} caracteres`;
      // Auto-guardar após 2s de inatividade
      clearTimeout(NotesState.autoSaveTimer);
      if (NotesState.currentNote) {
        NotesState.autoSaveTimer = setTimeout(() => saveCurrentNote(), 2000);
      }
    });
  }

  // Pesquisa de notas
  const notesSearch = document.getElementById('notes-search');
  if (notesSearch) {
    notesSearch.addEventListener('input', LKUtils.debounce((e) => {
      NotesState.searchQuery = e.target.value.trim();
      renderNotesList();
    }, 200));
  }

  // Ctrl+S para guardar
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      saveCurrentNote();
    }
  });
}
