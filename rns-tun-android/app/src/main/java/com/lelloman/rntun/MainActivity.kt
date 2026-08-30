package com.lelloman.rntun

import android.content.Intent
import android.graphics.Bitmap
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.lelloman.rntun.data.AppStore
import com.lelloman.rntun.data.InterfaceKind
import com.lelloman.rntun.data.ProfileRepository
import com.lelloman.rntun.data.TransferManager
import com.lelloman.rntun.data.TunnelMode
import com.lelloman.rntun.data.TunnelProfile
import com.lelloman.rntun.service.Diagnostics
import com.lelloman.rntun.service.RntunVpnService
import com.lelloman.rntun.service.TunnelPhase
import com.lelloman.rntun.service.TunnelState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : ComponentActivity() {
    private var pendingProfileId: String? = null
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) pendingProfileId?.let(::startTunnel)
        pendingProfileId = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            RntunTheme {
                RntunApp(
                    repository = ProfileRepository.get(this),
                    identityPath = File(filesDir, "rntun/identity").absolutePath,
                    connect = ::requestConnect,
                    disconnect = {
                        startService(Intent(this, RntunVpnService::class.java).setAction(RntunVpnService.ACTION_STOP))
                    },
                )
            }
        }
    }

    private fun requestConnect(profileId: String) {
        val prepare = VpnService.prepare(this)
        if (prepare == null) startTunnel(profileId) else {
            pendingProfileId = profileId
            consent.launch(prepare)
        }
    }

    private fun startTunnel(profileId: String) {
        ContextCompat.startForegroundService(
            this,
            Intent(this, RntunVpnService::class.java)
                .putExtra(RntunVpnService.EXTRA_PROFILE_ID, profileId),
        )
    }
}

private enum class Screen { PROFILES, CONNECTION, SETTINGS }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RntunApp(
    repository: ProfileRepository,
    identityPath: String,
    connect: (String) -> Unit,
    disconnect: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val store by repository.state.collectAsStateWithLifecycle(initialValue = AppStore())
    val tunnel by TunnelState.current.collectAsStateWithLifecycle()
    var screen by remember { mutableStateOf(Screen.PROFILES) }
    var editing by remember { mutableStateOf<TunnelProfile?>(null) }
    var transferProfile by remember { mutableStateOf<TunnelProfile?>(null) }
    var importBytes by remember { mutableStateOf<ByteArray?>(null) }
    var importQr by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }

    val context = androidx.compose.ui.platform.LocalContext.current
    val profilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { selected ->
            importBytes = runCatching { context.contentResolver.openInputStream(selected)!!.use { it.readBytes() } }
                .onFailure { message = it.message }.getOrNull()
        }
    }
    var pendingWrite by remember { mutableStateOf<ByteArray?>(null) }
    val profileWriter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.rntun.profile"),
    ) { uri ->
        uri?.let { selected ->
            runCatching { context.contentResolver.openOutputStream(selected)!!.use { it.write(pendingWrite) } }
                .onFailure { message = it.message }
        }
        pendingWrite = null
    }
    val scan = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { importQr = it }
    }

    LaunchedEffect(identityPath) {
        withContext(Dispatchers.IO) {
            runCatching { NativeBridge.nativeEnsureIdentity(identityPath) }
                .onFailure { Diagnostics.record(context, "ERROR", it.message ?: "identity setup failed") }
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text(if (editing == null) "rntun" else "Edit profile") }) },
        bottomBar = {
            if (editing == null) NavigationBar {
                NavigationBarItem(
                    selected = screen == Screen.PROFILES,
                    onClick = { screen = Screen.PROFILES },
                    icon = { androidx.compose.material3.Icon(Icons.Default.VpnKey, null) },
                    label = { Text("Profiles") },
                )
                NavigationBarItem(
                    selected = screen == Screen.CONNECTION,
                    onClick = { screen = Screen.CONNECTION },
                    icon = { androidx.compose.material3.Icon(Icons.Default.Info, null) },
                    label = { Text("Connection") },
                )
                NavigationBarItem(
                    selected = screen == Screen.SETTINGS,
                    onClick = { screen = Screen.SETTINGS },
                    icon = { androidx.compose.material3.Icon(Icons.Default.Settings, null) },
                    label = { Text("Settings") },
                )
            }
        },
        floatingActionButton = {
            if (editing == null && screen == Screen.PROFILES) FloatingActionButton(
                onClick = { editing = TunnelProfile() },
            ) { androidx.compose.material3.Icon(Icons.Default.Add, "Add profile") }
        },
    ) { padding ->
        if (editing != null) {
            ProfileEditor(
                initial = editing!!,
                modifier = Modifier.padding(padding),
                cancel = { editing = null },
                save = { profile ->
                    scope.launch {
                        repository.save(profile)
                        editing = null
                    }
                },
            )
        } else when (screen) {
            Screen.PROFILES -> ProfilesScreen(
                store = store,
                activeProfile = tunnel.profileId,
                modifier = Modifier.padding(padding),
                edit = { editing = it },
                connect = connect,
                delete = { scope.launch { repository.delete(it) } },
                makeDefault = { scope.launch { repository.setDefault(it) } },
                transfer = { transferProfile = it },
                importFile = { profilePicker.launch(arrayOf("*/*")) },
                importQr = {
                    scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan rntun profile"))
                },
            )
            Screen.CONNECTION -> ConnectionScreen(tunnel.phase, tunnel.profileName, tunnel.message, tunnel.statusJson, disconnect, Modifier.padding(padding))
            Screen.SETTINGS -> SettingsScreen(identityPath, Modifier.padding(padding))
        }
    }

    transferProfile?.let { profile ->
        TransferDialog(
            profile = profile,
            dismiss = { transferProfile = null },
            exportFile = { password ->
                runCatching { TransferManager.exportProfile(profile, password) }
                    .onSuccess {
                        pendingWrite = it
                        profileWriter.launch("${profile.name.replace(' ', '_')}.rntun-profile")
                        transferProfile = null
                    }.onFailure { message = it.message }
            },
        )
    }
    if (importBytes != null || importQr != null) PasswordDialog(
        title = "Import profile",
        dismiss = { importBytes = null; importQr = null },
    ) { password ->
        scope.launch(Dispatchers.IO) {
            runCatching {
                importBytes?.let { TransferManager.importProfile(it, password) }
                    ?: TransferManager.importProfileQr(requireNotNull(importQr), password)
            }.onSuccess {
                repository.save(it)
                importBytes = null
                importQr = null
            }.onFailure { withContext(Dispatchers.Main) { message = it.message } }
        }
    }
    message?.let { value ->
        AlertDialog(
            onDismissRequest = { message = null },
            confirmButton = { TextButton(onClick = { message = null }) { Text("OK") } },
            title = { Text("rntun") },
            text = { Text(value) },
        )
    }
}

@Composable
private fun ProfilesScreen(
    store: AppStore,
    activeProfile: String?,
    modifier: Modifier,
    edit: (TunnelProfile) -> Unit,
    connect: (String) -> Unit,
    delete: (String) -> Unit,
    makeDefault: (String) -> Unit,
    transfer: (TunnelProfile) -> Unit,
    importFile: () -> Unit,
    importQr: () -> Unit,
) {
    LazyColumn(modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(importFile) { Text("Import file") }
                OutlinedButton(importQr) { Text("Scan QR") }
            }
        }
        if (store.profiles.isEmpty()) item {
            Text("No profiles yet. Add one to connect to an rntun gateway.")
        }
        items(store.profiles, key = { it.id }) { profile ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(profile.name, style = MaterialTheme.typography.titleMedium)
                    Text("${profile.tunnelMode.name.lowercase()} tunnel · ${profile.interfaceKind.name.lowercase()}")
                    if (profile.id == store.defaultProfileId) Text("Default for always-on", color = MaterialTheme.colorScheme.primary)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(onClick = { connect(profile.id) }, enabled = activeProfile == null) { Text("Connect") }
                        TextButton(onClick = { edit(profile) }) { Text("Edit") }
                        TextButton(onClick = { transfer(profile) }) { Text("Share") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (profile.id != store.defaultProfileId) TextButton(onClick = { makeDefault(profile.id) }) { Text("Make default") }
                        TextButton(onClick = { delete(profile.id) }, enabled = activeProfile != profile.id) { Text("Delete") }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProfileEditor(
    initial: TunnelProfile,
    modifier: Modifier,
    cancel: () -> Unit,
    save: (TunnelProfile) -> Unit,
) {
    var value by remember(initial.id) { mutableStateOf(initial) }
    var requested by remember(initial.id) { mutableStateOf(initial.requestedRoutes.joinToString(", ")) }
    var allowed by remember(initial.id) { mutableStateOf(initial.allowedRoutes.joinToString(", ")) }
    var dns by remember(initial.id) { mutableStateOf(initial.allowedDns.joinToString(", ")) }
    var errors by remember { mutableStateOf(emptyList<String>()) }

    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(value.name, { value = value.copy(name = it) }, label = { Text("Profile name") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value.destinationHash, { value = value.copy(destinationHash = it.trim()) }, label = { Text("Gateway destination hash") }, modifier = Modifier.fillMaxWidth())
        Text("Tunnel mode", style = MaterialTheme.typography.titleSmall)
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(value.tunnelMode == TunnelMode.SPLIT, { value = value.copy(tunnelMode = TunnelMode.SPLIT) }); Text("Split")
            RadioButton(value.tunnelMode == TunnelMode.FULL, { value = value.copy(tunnelMode = TunnelMode.FULL) }); Text("Full (all apps)")
        }
        if (value.tunnelMode == TunnelMode.SPLIT) {
            OutlinedTextField(requested, { requested = it }, label = { Text("Requested routes (comma separated)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(allowed, { allowed = it }, label = { Text("Maximum allowed routes") }, modifier = Modifier.fillMaxWidth())
        }
        OutlinedTextField(dns, { dns = it }, label = { Text("Approved DNS servers") }, supportingText = { Text("Required for a full tunnel") }, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Advanced Reticulum config", Modifier.weight(1f))
            Switch(value.interfaceKind == InterfaceKind.ADVANCED, { value = value.copy(interfaceKind = if (it) InterfaceKind.ADVANCED else InterfaceKind.TCP_CLIENT) })
        }
        if (value.interfaceKind == InterfaceKind.TCP_CLIENT) {
            OutlinedTextField(value.tcpHost, { value = value.copy(tcpHost = it) }, label = { Text("TCP host") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value.tcpPort.toString(), { value = value.copy(tcpPort = it.toIntOrNull() ?: 0) }, label = { Text("TCP port") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
        } else {
            OutlinedTextField(value.advancedNodeConfig, { value = value.copy(advancedNodeConfig = it) }, label = { Text("Reticulum config") }, minLines = 10, modifier = Modifier.fillMaxWidth())
        }
        OutlinedTextField(value.mtu.toString(), { value = value.copy(mtu = it.toIntOrNull() ?: 0) }, label = { Text("MTU") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
        errors.forEach { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(cancel) { Text("Cancel") }
            Button(onClick = {
                val parsed = value.copy(
                    requestedRoutes = requested.csv(),
                    allowedRoutes = allowed.csv(),
                    allowedDns = dns.csv(),
                )
                errors = parsed.validate() + listOfNotNull(
                    if (parsed.validate().isEmpty()) NativeBridge.nativeValidateNodeConfig(parsed.nodeConfig(), parsed.tunnelMode == TunnelMode.FULL) else null,
                )
                if (errors.isEmpty()) save(parsed)
            }) { Text("Save") }
        }
        Spacer(Modifier.height(32.dp))
    }
}

private fun String.csv(): List<String> = split(',').map(String::trim).filter(String::isNotEmpty)

@Composable
private fun ConnectionScreen(
    phase: TunnelPhase,
    profile: String?,
    message: String?,
    status: String?,
    disconnect: () -> Unit,
    modifier: Modifier,
) {
    Column(modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(phase.name.lowercase().replaceFirstChar(Char::uppercase), style = MaterialTheme.typography.headlineMedium)
        profile?.let { Text(it, style = MaterialTheme.typography.titleMedium) }
        message?.let { Text(it) }
        if (phase !in listOf(TunnelPhase.IDLE, TunnelPhase.ERROR)) Button(disconnect) { Text("Disconnect") }
        HorizontalDivider()
        Text("Native status", style = MaterialTheme.typography.titleSmall)
        Text(status ?: "No active session", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun SettingsScreen(identityPath: String, modifier: Modifier) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var identity by remember { mutableStateOf("") }
    var diagnostics by remember { mutableStateOf("") }
    var backupPassword by remember { mutableStateOf(false) }
    var restoreBytes by remember { mutableStateOf<ByteArray?>(null) }
    var pendingBackup by remember { mutableStateOf<ByteArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val backupWriter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.rntun.identity"),
    ) { uri ->
        uri?.let { selected ->
            runCatching { context.contentResolver.openOutputStream(selected)!!.use { it.write(pendingBackup) } }
                .onFailure { error = it.message }
        }
        pendingBackup = null
    }
    val restorePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { selected ->
            restoreBytes = runCatching { context.contentResolver.openInputStream(selected)!!.use { it.readBytes() } }
                .onFailure { error = it.message }.getOrNull()
        }
    }
    LaunchedEffect(identityPath) {
        identity = withContext(Dispatchers.IO) { NativeBridge.nativeEnsureIdentity(identityPath) }
        diagnostics = withContext(Dispatchers.IO) { Diagnostics.read(context) }
    }
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Shared identity", style = MaterialTheme.typography.titleLarge)
        Text(identity.ifBlank { "Loading…" }, style = MaterialTheme.typography.bodySmall)
        Text("This identity is used by every profile. Backups are password-encrypted and contain the private identity key.")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { backupPassword = true }) { Text("Back up") }
            OutlinedButton(onClick = { restorePicker.launch(arrayOf("*/*")) }) { Text("Restore") }
        }
        HorizontalDivider()
        Text("Always-on VPN", style = MaterialTheme.typography.titleLarge)
        Text("Select rntun under Android Settings → Network & internet → VPN. The profile marked default is used. Lockdown is supported; full tunnels remain fail-closed while reconnecting.")
        HorizontalDivider()
        Text("Redacted diagnostics", style = MaterialTheme.typography.titleLarge)
        Text(diagnostics.ifBlank { "No diagnostics recorded" }, style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { Diagnostics.clear(context); diagnostics = "" }) { Text("Clear diagnostics") }
        Text("Gateway mode is planned for version 2.")
    }
    if (backupPassword) PasswordDialog("Back up identity", { backupPassword = false }) { password ->
        runCatching { TransferManager.exportIdentity(identityPath, password) }
            .onSuccess {
                pendingBackup = it
                backupPassword = false
                backupWriter.launch("rntun-identity.rntun-identity")
            }.onFailure { error = it.message }
    }
    restoreBytes?.let { encoded -> PasswordDialog(
        "Restore identity (replaces current identity)",
        { restoreBytes = null },
    ) { password ->
        scope.launch(Dispatchers.IO) {
            runCatching { TransferManager.importIdentity(identityPath, encoded, password) }
                .onSuccess { hash ->
                    withContext(Dispatchers.Main) {
                        identity = hash
                        restoreBytes = null
                    }
                }
                .onFailure { withContext(Dispatchers.Main) { error = it.message } }
        }
    } }
    error?.let { value -> AlertDialog(
        onDismissRequest = { error = null },
        confirmButton = { TextButton(onClick = { error = null }) { Text("OK") } },
        title = { Text("Identity operation failed") },
        text = { Text(value) },
    ) }
}

@Composable
private fun TransferDialog(
    profile: TunnelProfile,
    dismiss: () -> Unit,
    exportFile: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var qr by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text("Export ${profile.name}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(password, { password = it }, label = { Text("Password (10+ characters)") }, visualTransformation = PasswordVisualTransformation())
                qr?.let { Image(qrBitmap(it).asImageBitmap(), "Encrypted profile QR", Modifier.size(260.dp)) }
            }
        },
        confirmButton = {
            Row {
                TextButton(onClick = { runCatching { qr = TransferManager.profileQr(profile, password) } }) { Text("Show QR") }
                TextButton(onClick = { exportFile(password) }) { Text("Save file") }
            }
        },
        dismissButton = { TextButton(dismiss) { Text("Close") } },
    )
}

@Composable
private fun PasswordDialog(title: String, dismiss: () -> Unit, accept: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(title) },
        text = { OutlinedTextField(password, { password = it }, label = { Text("Password") }, visualTransformation = PasswordVisualTransformation()) },
        confirmButton = { TextButton(onClick = { accept(password) }, enabled = password.length >= 10) { Text("Import") } },
        dismissButton = { TextButton(dismiss) { Text("Cancel") } },
    )
}

private fun qrBitmap(value: String): Bitmap {
    val matrix = MultiFormatWriter().encode(value, BarcodeFormat.QR_CODE, 640, 640)
    return Bitmap.createBitmap(640, 640, Bitmap.Config.ARGB_8888).also { bitmap ->
        for (y in 0 until 640) for (x in 0 until 640) {
            bitmap.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
    }
}

@Composable
private fun RntunTheme(content: @Composable () -> Unit) {
    MaterialTheme(content = content)
}
