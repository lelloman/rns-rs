package com.lelloman.rntun.data

import android.content.Context
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerializationException
import java.io.InputStream
import java.io.OutputStream

private object StoreSerializer : Serializer<AppStore> {
    override val defaultValue = AppStore()

    override suspend fun readFrom(input: InputStream): AppStore = try {
        AppJson.decodeFromString(AppStore.serializer(), input.readBytes().decodeToString())
    } catch (error: SerializationException) {
        throw CorruptionException("Cannot read rntun profiles", error)
    }

    override suspend fun writeTo(t: AppStore, output: OutputStream) {
        output.write(AppJson.encodeToString(AppStore.serializer(), t).encodeToByteArray())
    }
}

class ProfileRepository private constructor(context: Context) {
    private val store: DataStore<AppStore> = DataStoreFactory.create(
        serializer = StoreSerializer,
        produceFile = {
            context.filesDir.resolve("rntun").mkdirs()
            context.filesDir.resolve("rntun/profiles.json")
        },
    )

    val state: Flow<AppStore> = store.data
    val profiles: Flow<List<TunnelProfile>> = state.map { it.profiles }

    suspend fun get(id: String): TunnelProfile? = state.first().profiles.find { it.id == id }

    suspend fun defaultProfile(): TunnelProfile? {
        val value = state.first()
        return value.profiles.find { it.id == value.defaultProfileId }
    }

    suspend fun save(profile: TunnelProfile) {
        store.updateData { current ->
            val profiles = current.profiles.filterNot { it.id == profile.id } + profile
            current.copy(
                profiles = profiles,
                defaultProfileId = current.defaultProfileId ?: profile.id,
            )
        }
    }

    suspend fun delete(id: String) {
        store.updateData { current ->
            val profiles = current.profiles.filterNot { it.id == id }
            current.copy(
                profiles = profiles,
                defaultProfileId = if (current.defaultProfileId == id) profiles.firstOrNull()?.id
                else current.defaultProfileId,
            )
        }
    }

    suspend fun setDefault(id: String) {
        store.updateData { current ->
            require(current.profiles.any { it.id == id })
            current.copy(defaultProfileId = id)
        }
    }

    companion object {
        @Volatile private var instance: ProfileRepository? = null

        fun get(context: Context): ProfileRepository = instance ?: synchronized(this) {
            instance ?: ProfileRepository(context.applicationContext).also { instance = it }
        }
    }
}
