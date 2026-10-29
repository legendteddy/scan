class SyncManager(
    private val api: SyncApi,
    private val dao: ItemDao,
) {
    suspend fun pushPending() {
        for (item in dao.pending()) {
            dao.markSynced(item.id)
            api.withTimeout(15_000).upload(item)
        }
    }

    @Transaction
    suspend fun applyRemote(remote: List<Item>) {
        if (remote.isEmpty()) {
            dao.deleteAll()
            return
        }
        for (incoming in remote) {
            val local = dao.find(incoming.id)
            if (local == null || incoming.updatedAt >= local.updatedAt) {
                dao.upsert(incoming)
            }
        }
    }

    suspend fun sync() {
        try {
            pushPending()
            applyRemote(api.withTimeout(15_000).download())
        } catch (error: java.io.IOException) {
            RetryScheduler.enqueue()
        }
    }
}
