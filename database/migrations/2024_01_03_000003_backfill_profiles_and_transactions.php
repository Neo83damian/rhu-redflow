<?php

use App\Models\MonitoringRecord;
use App\Models\User;
use App\Support\ActivityLog;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/**
 * Fills two tables that the app used to leave permanently empty, using data
 * that ALREADY exists (nothing is invented):
 *   - staff_profiles: one row for every existing account.
 *   - monitoring_transactions: one row for every past donation already stored
 *     inside the History Records.
 * From now on the app keeps both up to date by itself.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('staff_profiles') && Schema::hasTable('users')) {
            User::orderBy('id')->chunkById(200, function ($users) {
                foreach ($users as $user) {
                    ActivityLog::syncStaffProfile($user);
                }
            });
        }

        if (Schema::hasTable('monitoring_transactions') && Schema::hasTable('monitoring_records')) {
            MonitoringRecord::orderBy('id')->chunkById(200, function ($records) {
                foreach ($records as $record) {
                    $record->syncTransactions();
                }
            });
        }
    }

    public function down(): void
    {
        // Nothing to undo — these rows are real data.
    }
};
