import { createClient } from '@supabase/supabase-js';

const supabaseUrl = 'https://rsatepmxbyoaptrllcpt.supabase.co';
const supabaseServiceKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzYXRlcG14YnlvYXB0cmxsY3B0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MjAzMzMwNCwiZXhwIjoyMDk3NjA5MzA0fQ.5BqZ8Q9X7YwqqpP-BRFxLHhpiLh2FgN47pkUpr8Yg';

const supabase = createClient(supabaseUrl, supabaseServiceKey);

const testUsers = [
  {
    email: 's.jenkins@aimspwa.com',
    password: 'AdminPassword123!',
    username: 'Sarah Jenkins',
    role: 'admin'
  },
  {
    email: 'm.vance@aimspwa.com',
    password: 'ManagerPassword123!',
    username: 'Marcus Vance',
    role: 'manager'
  },
  {
    email: 'a.okafor@aimspwa.com',
    password: 'ManagerPassword123!',
    username: 'Amara Okafor',
    role: 'manager'
  },
  {
    email: 'e.rostova@aimspwa.com',
    password: 'StaffPassword123!',
    username: 'Elena Rostova',
    role: 'staff'
  },
  {
    email: 'd.kim@aimspwa.com',
    password: 'StaffPassword123!',
    username: 'David Kim',
    role: 'staff'
  }
];

async function createTestUsers() {
  console.log('Creating test users...');
  
  for (const user of testUsers) {
    try {
      // Check if user exists
      const { data: existingUsers } = await supabase
        .from('profiles')
        .select('id')
        .eq('email', user.email)
        .single();
      
      if (existingUsers) {
        console.log(`User ${user.email} already exists, skipping...`);
        continue;
      }
      
      // Create user in auth
      const { data: authData, error: authError } = await supabase.auth.admin.createUser({
        email: user.email,
        password: user.password,
        email_confirm: true,
        user_metadata: {
          username: user.username,
          role: user.role
        }
      });
      
      if (authError) {
        console.error(`Error creating auth user ${user.email}:`, authError);
        continue;
      }
      
      console.log(`Created auth user: ${user.email}`);
      
      // Profile will be created automatically by trigger
      
    } catch (error) {
      console.error(`Error processing user ${user.email}:`, error);
    }
  }
  
  console.log('Done!');
}

createTestUsers();
