<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class AdminSeeder extends Seeder
{
    /**
     * Creates the first Admin account.
     *
     * SECURITY: no password is written in this file. Set your own in the
     * environment before seeding:
     *
     *     ADMIN_EMAIL=adminredflow402@gmail.com     (optional)
     *     ADMIN_PASSWORD=<a strong password only you know>
     *
     * If ADMIN_PASSWORD is not set, a random strong password is generated and
     * shown ONCE in the terminal — copy it and change it right after logging in.
     *
     * If the Admin already exists it is NEVER touched (its password is not
     * reset) — running this seeder again can no longer overwrite a password
     * you have already changed.
     */
    public function run(): void
    {
        $email = strtolower((string) env('ADMIN_EMAIL', 'adminredflow402@gmail.com'));

        if (User::where('email', $email)->exists()) {
            $this->command?->info("Admin {$email} already exists — nothing changed (password NOT reset).");
            return;
        }

        $password = (string) env('ADMIN_PASSWORD', '');
        $generated = false;
        if ($password === '') {
            $password = Str::random(14) . '#' . random_int(10, 99); // letters + symbol + digits
            $generated = true;
        }

        User::create([
            'email' => $email,
            'name' => 'Admin RedFlow',
            'password' => $password, // hashed automatically by the model's 'hashed' cast
            'role' => 'Admin',
            'status' => 'Approved',
            'action_taken' => 'Approved',
        ]);

        $this->command?->info("Admin account created: {$email}");
        if ($generated) {
            $this->command?->warn("Temporary password (shown only once): {$password}");
            $this->command?->warn('Log in and change it right away from Account Security.');
        }
    }
}
