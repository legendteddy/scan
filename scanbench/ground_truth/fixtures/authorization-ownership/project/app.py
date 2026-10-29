def load_document(db, document_id):
    return db.execute("SELECT id, owner_id FROM documents WHERE id = ?", (document_id,)).fetchone()


def delete_document(db, current_user, document_id):
    if not current_user.is_authenticated:
        raise PermissionError("login required")
    document = load_document(db, document_id)
    if document is None:
        raise LookupError(document_id)
    # BUG: no document.owner_id == current_user.id authorization check.
    db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()
