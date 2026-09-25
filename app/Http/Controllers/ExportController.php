<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use App\Models\Donor;
use App\Models\ExportGuard;
use App\Support\ActivityLog;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;

/**
 * Gatekeeper for "Export Donor Masterlist".
 *
 * Rules:
 *  - The account password must be entered first.
 *  - 3 WRONG passwords in a row  -> locked for 60 seconds.
 *  - Only 3 successful exports within any 24 hours (per account). After the
 *    third, the next one is possible 24 hours after the oldest of the three.
 *
 * The checks and counters live here on the server (database), so they cannot
 * be skipped by refreshing the page or clearing the Audit Log.
 */
class ExportController extends Controller
{
    private const MAX_EXPORTS_PER_DAY = 3;
    private const MAX_WRONG_PASSWORDS = 3;
    private const LOCK_SECONDS = 60;

    public function authorizeExport(Request $request)
    {
        $data = $request->validate(['password' => 'required|string']);
        $user = $request->user();

        // If the export_guards migration has not been run yet (e.g. a local
        // XAMPP setup, or a fresh Railway deploy where `migrate` has not
        // finished), show a clear, actionable message instead of a raw
        // SQLSTATE error — and let the password still be checked below, so
        // export isn't blocked forever just because the table is missing.
        if (!\Illuminate\Support\Facades\Schema::hasTable('export_guards')) {
            if (!\Illuminate\Support\Facades\Hash::check($data['password'], $user->password)) {
                return response()->json(['message' => 'Incorrect password.', 'code' => 'wrong', 'attempts_left' => 3], 422);
            }

            $count = Donor::count();
            ActivityLog::staffActivity($user, 'exported the Donor Masterlist');
            AuditLog::recordDonorAction($user->id, 'Export', null, null, "Full Masterlist ({$count} donor" . ($count === 1 ? '' : 's') . ')');

            return response()->json([
                'message' => 'Authorized.',
                'notice' => 'Setup needed: run "php artisan migrate" so export limits (3 per day) can be enforced.',
            ]);
        }

        $guard = ExportGuard::firstOrCreate(['user_id' => $user->id]);
        $now = now();

        // Successful exports in the last 24 hours (oldest first).
        $recent = collect($guard->exports ?? [])
            ->map(fn ($t) => Carbon::parse($t))
            ->filter(fn ($t) => $t->greaterThan($now->copy()->subDay()))
            ->sortBy(fn ($t) => $t->timestamp)
            ->values();

        // 1) Daily limit
        if ($recent->count() >= self::MAX_EXPORTS_PER_DAY) {
            $retry = max(1, (int) ceil(abs($now->diffInSeconds($recent->first()->copy()->addDay(), false))));
            return response()->json([
                'message' => 'Export limit reached. Please try again later.',
                'code' => 'quota',
                'retry_after' => $retry,
            ], 429);
        }

        // 2) Temporary lock after too many wrong passwords
        if ($guard->locked_until && $guard->locked_until->greaterThan($now)) {
            $retry = max(1, (int) ceil(abs($now->diffInSeconds($guard->locked_until, false))));
            return response()->json([
                'message' => 'Too many incorrect password attempts.',
                'code' => 'locked',
                'retry_after' => $retry,
            ], 429);
        }

        // 3) Password check
        if (!Hash::check($data['password'], $user->password)) {
            $guard->failed_attempts = (int) $guard->failed_attempts + 1;

            if ($guard->failed_attempts >= self::MAX_WRONG_PASSWORDS) {
                $guard->failed_attempts = 0;
                $guard->locked_until = $now->copy()->addSeconds(self::LOCK_SECONDS);
                $guard->save();

                return response()->json([
                    'message' => 'Incorrect password. Too many attempts.',
                    'code' => 'locked',
                    'retry_after' => self::LOCK_SECONDS,
                ], 429);
            }

            $guard->save();
            $left = self::MAX_WRONG_PASSWORDS - $guard->failed_attempts;

            return response()->json([
                'message' => 'Incorrect password.',
                'code' => 'wrong',
                'attempts_left' => $left,
            ], 422);
        }

        // 4) Authorized: reset the wrong-password counter and use up 1 export.
        $recent->push($now);
        $guard->failed_attempts = 0;
        $guard->locked_until = null;
        $guard->exports = $recent->map(fn ($t) => $t->toIso8601String())->all();
        $guard->save();

        $count = Donor::count();
        ActivityLog::staffActivity($user, 'exported the Donor Masterlist');
        AuditLog::recordDonorAction($user->id, 'Export', null, null, "Full Masterlist ({$count} donor" . ($count === 1 ? '' : 's') . ')');

        return response()->json([
            'message' => 'Authorized.',
            'exports_left' => self::MAX_EXPORTS_PER_DAY - $recent->count(),
        ]);
    }
}
