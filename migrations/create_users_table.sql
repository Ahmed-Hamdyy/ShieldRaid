-- Drop existing trigger first to avoid conflicts
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- Drop existing function to avoid conflicts
DROP FUNCTION IF EXISTS public.handle_new_user();

-- Check if user_role enum exists and create if it doesn't
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('regular_user', 'red_teamer', 'blue_teamer', 'analyzer', 'admin');
    END IF;
END $$;

-- Drop existing table if it exists
DROP TABLE IF EXISTS public.users CASCADE;

-- Create users table
CREATE TABLE public.users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role user_role NOT NULL DEFAULT 'regular_user',
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()),
    CONSTRAINT fk_user_id FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);

-- Enable RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Drop existing policies
DROP POLICY IF EXISTS "Users can view own data" ON public.users;
DROP POLICY IF EXISTS "Admins can view all data" ON public.users;
DROP POLICY IF EXISTS "Admins can update all data" ON public.users;

-- Create policies
CREATE POLICY "Users can view own data" ON public.users
    FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Admins can view all data" ON public.users
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Create function to handle user creation
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    _username TEXT;
    _role user_role;
BEGIN
    -- Get username from metadata or generate from email
    _username := COALESCE(
        NEW.raw_user_meta_data->>'username',
        NEW.user_metadata->>'username',
        split_part(NEW.email, '@', 1)
    );
    
    -- Get role from metadata or use default
    BEGIN
        _role := COALESCE(
            (NEW.raw_user_meta_data->>'role')::user_role,
            (NEW.user_metadata->>'role')::user_role,
            'regular_user'::user_role
        );
    EXCEPTION WHEN OTHERS THEN
        _role := 'regular_user'::user_role;
    END;

    -- Insert new user if they don't exist
    INSERT INTO public.users (id, email, username, role)
    VALUES (
        NEW.id,
        NEW.email,
        _username,
        _role
    )
    ON CONFLICT (id) DO UPDATE
    SET 
        email = EXCLUDED.email,
        username = EXCLUDED.username,
        role = EXCLUDED.role,
        updated_at = TIMEZONE('utc', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user(); 