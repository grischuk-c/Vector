package org.matrix.vector

import android.content.pm.ApplicationInfo
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import org.lsposed.lspd.util.Utils

/**
 * Exempts the parasitic manager's host package from GrapheneOS's "Restrict dynamic code loading"
 * exploit protections.
 *
 * GrapheneOS combines three separate restrictions — memory, storage and WebView DCL — into one
 * bitmask in `DynCodeLoading.getAppBindFlags`, then arms the matching native ART checks in the app
 * process. Each restriction is immutable and enabled for system apps. As the manager runs inside
 * [BuildConfig.InjectedPackageName] (`com.android.shell`, a system app), the storage check rejects
 * its DEX: the transplanted `sourceDir` is a `/proc/self/fd/N` handle, which is not on GrapheneOS's
 * allow-list (`/apex`, `/system`, `/data/app`, …), so binding aborts with a "DCL via storage"
 * SecurityException before the manager runs.
 *
 * The hook forces the bind flags to `0` for that package alone, clearing every DCL restriction at
 * once; every other app retains GrapheneOS's verdict. It applies only on GrapheneOS, where the
 * target class exists, and only in system_server, where the flags are resolved and shipped to the
 * process.
 */
object GrapheneDclHooker {

    private const val DCL_CLASS = "android.ext.dcl.DynCodeLoading"

    @JvmStatic
    fun start() {
        val dclClass =
            try {
                XposedHelpers.findClass(DCL_CLASS, this.javaClass.classLoader)
            } catch (_: XposedHelpers.ClassNotFoundError) {
                return // Not GrapheneOS.
            }

        try {
            // int getAppBindFlags(Context, int userId, ApplicationInfo, GosPackageState) OR-combines
            // RESTRICT_MEMORY_DCL, RESTRICT_STORAGE_DCL and RESTRICT_WEBVIEW_DCL. Zeroing it for the
            // manager host leaves handleAppBindFlags with nothing to arm, so no DCL check fires.
            XposedBridge.hookAllMethods(
                dclClass,
                "getAppBindFlags",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam<*>) {
                        val appInfo = param.args.getOrNull(2) as? ApplicationInfo
                        if (appInfo?.packageName == BuildConfig.InjectedPackageName) {
                            param.result = 0 // Allow the manager host to load its DEX.
                        }
                    }
                },
            )
        } catch (e: Throwable) {
            Utils.logE("Failed to patch GrapheneOS DCL restriction", e)
        }
    }
}
