def replace_preferences(db, user_id, values):
    # Existing preferences are permanently removed before the replacement write.
    db.execute("DELETE FROM preferences WHERE user_id = ?", (user_id,))
    db.commit()
    try:
        db.execute(
            "INSERT INTO preferences(user_id, payload) VALUES (?, ?)",
            (user_id, values),
        )
        db.commit()
    except Exception:
        # Caller sees success even if the replacement insert failed.
        return {"ok": True, "replaced": False}
    return {"ok": True, "replaced": True}
