<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * php artisan redflow:db-check
 *
 * Prints how many rows every REDFLOW table has, and whether the personal
 * data columns are really encrypted — handy to run on Railway
 * (Service → ... → Run command) to see at a glance what is empty.
 */
class DbCheck extends Command
{
    protected $signature = 'redflow:db-check';
    protected $description = 'Show row counts for every REDFLOW table and check that personal data is encrypted';

    public function handle(): int
    {
        // ===== Which database is this actually talking to? =====
        // The #1 cause of "blank on Railway, has data locally" is that no
        // MySQL/Postgres database service was ever connected on Railway, so
        // Laravel silently falls back to a local SQLite FILE. Railway wipes
        // the app's disk on every redeploy/restart, so that file (and
        // EVERYTHING in it — not just one table) resets to empty each time.
        $connectionName = config('database.default');
        $driver = config("database.connections.{$connectionName}.driver");
        $this->line("Database connection: <fg=cyan>{$connectionName}</> (driver: <fg=cyan>{$driver}</>)");
        if ($driver === 'sqlite') {
            $this->warn('WARNING: this app is using SQLite. On Railway, SQLite is stored on the');
            $this->warn('container disk, which is WIPED on every redeploy/restart — so ALL data');
            $this->warn('(not just one table) resets to empty each time. Add a MySQL database on');
            $this->warn('Railway and set DB_CONNECTION=mysql (see RAILWAY-SETUP.md, section 6).');
        } else {
            try {
                DB::connection()->getPdo();
                $this->info('Connected successfully.');
            } catch (\Throwable $e) {
                $this->error('Could NOT connect to the database: ' . $e->getMessage());
                $this->error('Fix the DB_* variables first — the checks below will all show 0 / MISSING until this works.');
            }
        }
        $this->line('');

        $tables = [
            'users' => 'Staff / Admin accounts',
            'staff_profiles' => 'Account profile details',
            'donors' => 'Donor Masterlist',
            'monitoring_records' => 'History Records',
            'monitoring_transactions' => 'Past donations',
            'app_notifications' => 'Notifications',
            'audit_log' => 'Audit Log (ALL rows — see breakdown below)',
            'user_logs' => 'User login/logout events',
            'password_reset_otps' => 'Forgot-password codes',
            'secure_files' => 'ID / selfie photos (encrypted)',
        ];

        $rows = [];
        foreach ($tables as $table => $label) {
            $rows[] = Schema::hasTable($table)
                ? [$table, $label, DB::table($table)->count()]
                : [$table, $label, 'MISSING — run: php artisan migrate --force'];
        }
        $this->table(['Table', 'What it holds', 'Rows'], $rows);

        // ===== Audit Log breakdown =====
        // The Audit Log PAGE in the app (and its "Delete"/"Clear" buttons)
        // only shows/removes entries that have an action_label — the donor
        // Create/Update/Delete/Export/Change trail. Plain security events
        // (login, logout, register, password_reset, approve/reject_staff)
        // have NO action_label: they are intentionally kept out of that page
        // and are NOT removed by "Clear Audit Log". That is why the total
        // row count here can stay high even right after clearing the page.
        if (Schema::hasTable('audit_log')) {
            $shown = DB::table('audit_log')->whereNotNull('action_label')->count();
            $security = DB::table('audit_log')->whereNull('action_label')->count();
            $this->line('');
            $this->line('Audit Log breakdown:');
            $this->line("  Shown on the Audit Log page (Create/Update/Delete/Export/Change): {$shown}");
            $this->line("  Security events not shown there (login/logout/register/etc.):    {$security}");
            $this->line('  "Clear Audit Log" / "Delete selected" only remove the first group.');
        }

        $this->line('');
        $this->line('Encryption check (columns that must NOT be readable):');
        $checks = [
            ['donors', 'name'], ['donors', 'contact'], ['donors', 'blood_type'], ['donors', 'extra'],
            ['monitoring_records', 'blood_type'], ['monitoring_records', 'extra'],
            ['audit_log', 'donor_name'], ['audit_log', 'details'],
        ];
        foreach ($checks as [$table, $column]) {
            if (!Schema::hasTable($table) || !Schema::hasColumn($table, $column)) {
                continue;
            }
            $total = DB::table($table)->whereNotNull($column)->where($column, '!=', '')->count();
            $plain = 0;
            DB::table($table)->whereNotNull($column)->where($column, '!=', '')->orderBy('id')
                ->chunkById(200, function ($chunk) use ($column, &$plain) {
                    foreach ($chunk as $row) {
                        try {
                            Crypt::decryptString($row->{$column});
                        } catch (\Throwable $e) {
                            $plain++;
                        }
                    }
                });
            $this->line(sprintf('  %-26s %s', "{$table}.{$column}",
                $total === 0 ? '(no data yet)' : ($plain === 0 ? "OK — all {$total} encrypted" : "{$plain} of {$total} NOT encrypted — run: php artisan migrate --force")));
        }

        return self::SUCCESS;
    }
}
