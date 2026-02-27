package org.amnezia.vpn

import android.app.Activity
import com.google.android.play.core.review.ReviewManagerFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val TAG = "ReviewManager"

private const val PREFS_REVIEW_FIRST_USAGE_TIME = "REVIEW_FIRST_USAGE_TIME"
private const val PREFS_REVIEW_USAGE_DAYS = "REVIEW_USAGE_DAYS"
private const val PREFS_REVIEW_LAST_SHOWN_TIME = "REVIEW_LAST_SHOWN_TIME"

private const val THIRTY_MINUTES_MS = 2 * 60 * 1000L // TODO: revert to 30 * 60 * 1000L
private const val TWO_DAYS_MS = 2 * 24 * 60 * 60 * 1000L
private const val REQUIRED_DISTINCT_DAYS = 1 // TODO: revert to 2

private val DAY_FORMAT = SimpleDateFormat("yyyy-MM-dd", Locale.US)

object ReviewManager {

    /**
     * Call on every Activity resume. Prefs I/O runs on IO dispatcher to avoid
     * blocking the main thread (EncryptedSharedPreferences can be slow).
     */
    fun onActivityResumed(activity: Activity, scope: CoroutineScope) {
        scope.launch(Dispatchers.IO) {
            recordUsage()

            if (shouldShowReview()) {
                withContext(Dispatchers.Main) {
                    requestReviewFlow(activity)
                }
            }
        }
    }

    private fun recordUsage() {
        val now = System.currentTimeMillis()

        // Record first usage timestamp
        if (Prefs.load<Long>(PREFS_REVIEW_FIRST_USAGE_TIME) == 0L) {
            Log.d(TAG, "Recording first usage time")
            Prefs.save(PREFS_REVIEW_FIRST_USAGE_TIME, now)
        }

        // Add today to the set of distinct usage days
        val today = DAY_FORMAT.format(Date(now))
        val storedDays = Prefs.load<String>(PREFS_REVIEW_USAGE_DAYS)
        val days = if (storedDays.isBlank()) mutableSetOf() else storedDays.split(",").toMutableSet()

        if (days.add(today)) {
            Log.d(TAG, "Adding new usage day: $today (total distinct days: ${days.size})")
            Prefs.save(PREFS_REVIEW_USAGE_DAYS, days.joinToString(","))
        }
    }

    private fun shouldShowReview(): Boolean {
        val now = System.currentTimeMillis()

        val firstUsageTime = Prefs.load<Long>(PREFS_REVIEW_FIRST_USAGE_TIME)
        if (firstUsageTime == 0L) return false

        // Must have used the app for at least 30 minutes since first launch
        val elapsedMs = now - firstUsageTime
        if (elapsedMs < THIRTY_MINUTES_MS) {
            Log.d(TAG, "Not enough time since first usage (${elapsedMs / 1000}s / ${THIRTY_MINUTES_MS / 1000}s required)")
            return false
        }

        // Must have used the app on at least 2 different days
        val storedDays = Prefs.load<String>(PREFS_REVIEW_USAGE_DAYS)
        val distinctDays = if (storedDays.isBlank()) 0 else storedDays.split(",").size
        if (distinctDays < REQUIRED_DISTINCT_DAYS) {
            Log.d(TAG, "Not enough distinct usage days ($distinctDays / $REQUIRED_DISTINCT_DAYS)")
            return false
        }

        // Must not have been shown within the last 2 days
        val lastShownTime = Prefs.load<Long>(PREFS_REVIEW_LAST_SHOWN_TIME)
        if (lastShownTime != 0L && now - lastShownTime < TWO_DAYS_MS) {
            Log.d(TAG, "Review was shown recently, skipping (${(now - lastShownTime) / 3600000}h ago)")
            return false
        }

        return true
    }

    private fun requestReviewFlow(activity: Activity) {
        Log.d(TAG, "Requesting review flow")
        Prefs.save(PREFS_REVIEW_LAST_SHOWN_TIME, System.currentTimeMillis())

        val reviewManager = ReviewManagerFactory.create(activity)

        val requestReviewFlow = reviewManager.requestReviewFlow()

        requestReviewFlow.addOnCompleteListener { request ->
            if (request.isSuccessful) {
                val reviewInfo = request.result
                val flow = reviewManager.launchReviewFlow(activity, reviewInfo)
                flow.addOnCompleteListener {
                    Log.d(TAG, "Review flow completed")
                }
            } else {
                Log.w(TAG, "Review flow request failed: ${request.exception}")
            }
        }
    }
}
