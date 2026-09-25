<?php

namespace App\Support;

use App\Models\AppNotification;
use App\Models\StaffProfile;
use App\Models\User;
use App\Models\UserLog;
use Illuminate\Support\Facades\Log;

/**
 * One place that fills the "activity" tables — user_logs, app_notifications
 * and staff_profiles — so they get real rows as people use the system,
 * instead of staying empty. Every method is best-effort: a problem here is
 * only logged and can never break the action the user actually asked for.
 */
class ActivityLog
{
    /** A row in user_logs (login, logout, register, change_password, ...). */
    public static function userEvent(?int $userId, string $event, ?string $ip = null): void
    {
        if (!$userId) {
            return;
        }

        try {
            UserLog::create([
                'user_id' => $userId,
                'event' => $event,
                'occurred_at' => now(),
                'ip_address' => $ip,
            ]);
        } catch (\Throwable $e) {
            Log::warning('user_logs write failed: ' . $e->getMessage());
        }
    }

    /** A notification for one user. */
    public static function notifyUser(?int $userId, string $message): void
    {
        if (!$userId) {
            return;
        }

        try {
            AppNotification::create(['user_id' => $userId, 'message' => $message]);
        } catch (\Throwable $e) {
            Log::warning('notification write failed: ' . $e->getMessage());
        }
    }

    /** A notification for every approved Admin (optionally except one user). */
    public static function notifyAdmins(string $message, ?int $exceptUserId = null): void
    {
        try {
            $ids = User::where('role', 'Admin')
                ->where('status', 'Approved')
                ->when($exceptUserId, fn ($q) => $q->where('id', '!=', $exceptUserId))
                ->pluck('id');

            foreach ($ids as $id) {
                AppNotification::create(['user_id' => $id, 'message' => $message]);
            }
        } catch (\Throwable $e) {
            Log::warning('admin notification write failed: ' . $e->getMessage());
        }
    }

    /**
     * Tells the Admins when a STAFF member does something with donor data
     * (add / edit / delete / export). No donor names are put in the message.
     */
    public static function staffActivity(?User $actor, string $what): void
    {
        if (!$actor || $actor->role !== 'Staff') {
            return;
        }

        self::notifyAdmins("{$actor->name} (Staff) {$what}.", $actor->id);
    }

    /**
     * Makes sure this account has a staff_profiles row and keeps its
     * (encrypted) profile details up to date.
     */
    public static function syncStaffProfile(User $user): void
    {
        try {
            StaffProfile::updateOrCreate(
                ['user_id' => $user->id],
                ['extra' => [
                    'email' => $user->email,
                    'contact' => $user->contact,
                    'sex' => $user->gender,
                    'bday' => optional($user->dob)->toDateString(),
                    'address' => $user->brgy,
                    'role' => $user->role,
                    'status' => $user->status,
                    'synced_at' => now()->toDateTimeString(),
                ]]
            );
        } catch (\Throwable $e) {
            Log::warning('staff_profiles write failed: ' . $e->getMessage());
        }
    }
}
