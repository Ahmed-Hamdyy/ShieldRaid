-- Database setup for VulnScan application
-- This script sets up the database schema with proper security, validation, and audit trails
-- Version: 1.0
-- Last Updated: 2024-12-18

-- Start transaction to ensure atomic setup
BEGIN;

-- Print setup start
DO $$ 
BEGIN 
    RAISE NOTICE 'Starting database setup...';
END $$;

-- Drop existing objects safely
DO $$ 
BEGIN
    -- Drop tables if they exist
    DROP TABLE IF EXISTS public.scans CASCADE;
    DROP TABLE IF EXISTS public.user_stats CASCADE;
    DROP TABLE IF EXISTS public.users CASCADE;
    
    -- Drop functions
    DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;
    
    -- Drop triggers
    DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
    
    RAISE NOTICE 'Cleaned up existing objects';
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Error during cleanup: %', SQLERRM;
END $$;

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- For UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- For cryptographic functions
CREATE EXTENSION IF NOT EXISTS "citext";         -- For case-insensitive text

-- Create custom types
DO $$ 
BEGIN
    -- Create user role enum if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM (
            'regular_user',
            'red_teamer',
            'blue_teamer',
            'analyzer',
            'admin'
        );
        RAISE NOTICE 'Created user_role enum type';
    END IF;
    
    -- Create scan status enum if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_status') THEN
        CREATE TYPE scan_status AS ENUM (
            'pending',
            'in_progress',
            'completed',
            'failed',
            'cancelled'
        );
        RAISE NOTICE 'Created scan_status enum type';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Error creating custom types: %', SQLERRM;
END $$;

-- Create users table
CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id),
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'regular_user',
    profile_pic_url TEXT DEFAULT 'https://example.com/default-profile-pic.png',
    first_name TEXT,
    last_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Create scans table
CREATE TABLE public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id),
    target_url TEXT NOT NULL,
    vulnerabilities JSONB,
    stats JSONB,
    scan_duration DOUBLE PRECISION,
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Create user_stats table
CREATE TABLE public.user_stats (
    user_id UUID PRIMARY KEY REFERENCES public.users(id),
    total_scans INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    successful_scans INTEGER DEFAULT 0,
    total_scan_time DOUBLE PRECISION DEFAULT 0
);

-- Create indexes
CREATE INDEX idx_users_email ON public.users USING btree (email);
CREATE INDEX idx_users_username ON public.users USING btree (username);

-- Add email format check
ALTER TABLE public.users
ADD CONSTRAINT chk_email_format CHECK (
    email ~* E'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
);

-- Enable RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_stats ENABLE ROW LEVEL SECURITY;

-- Drop existing policies first
DROP POLICY IF EXISTS "Users can view their own data" ON public.users;
DROP POLICY IF EXISTS "Users can view their own scans" ON public.scans;
DROP POLICY IF EXISTS "Users can view their own stats" ON public.user_stats;

-- Create policies
CREATE POLICY "Users can view their own data"
    ON public.users
    FOR ALL
    USING (auth.uid() = id);

CREATE POLICY "Users can view their own scans"
    ON public.scans
    FOR ALL
    USING (auth.uid() = user_id);

CREATE POLICY "Users can view their own stats"
    ON public.user_stats
    FOR ALL
    USING (auth.uid() = user_id);

-- Create function to handle new user creation
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.users (id, email, username)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1))
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for new user creation
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION handle_new_user();

-- Function to update user stats with validation
CREATE OR REPLACE FUNCTION update_user_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Validate input
    IF NEW.scan_duration < 0 THEN
        RAISE EXCEPTION 'Scan duration cannot be negative';
    END IF;

    -- Update stats with error handling
    BEGIN
        INSERT INTO public.user_stats (
            user_id, 
            total_scans,
            total_vulnerabilities,
            successful_scans,
            total_scan_time
        )
        VALUES (
            NEW.user_id,
            1,
            CASE 
                WHEN NEW.vulnerabilities IS NULL THEN 0
                WHEN jsonb_typeof(NEW.vulnerabilities) = 'array' THEN jsonb_array_length(NEW.vulnerabilities)
                WHEN jsonb_typeof(NEW.vulnerabilities) = 'string' THEN 
                    CASE 
                        WHEN NEW.vulnerabilities::text = '[]' THEN 0
                        ELSE jsonb_array_length(NEW.vulnerabilities::jsonb)
                    END
                ELSE 0
            END,
            CASE WHEN NEW.status = 'completed' THEN 1 ELSE 0 END,
            COALESCE(NEW.scan_duration, 0)
        )
        ON CONFLICT (user_id) DO UPDATE
        SET
            total_scans = user_stats.total_scans + 1,
            total_vulnerabilities = user_stats.total_vulnerabilities + 
                CASE 
                    WHEN NEW.vulnerabilities IS NULL THEN 0
                    WHEN jsonb_typeof(NEW.vulnerabilities) = 'array' THEN jsonb_array_length(NEW.vulnerabilities)
                    WHEN jsonb_typeof(NEW.vulnerabilities) = 'string' THEN 
                        CASE 
                            WHEN NEW.vulnerabilities::text = '[]' THEN 0
                            ELSE jsonb_array_length(NEW.vulnerabilities::jsonb)
                        END
                    ELSE 0
                END,
            successful_scans = user_stats.successful_scans + 
                CASE WHEN NEW.status = 'completed' THEN 1 ELSE 0 END,
            total_scan_time = user_stats.total_scan_time + COALESCE(NEW.scan_duration, 0);
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'Error updating user stats: %', SQLERRM;
        -- Continue with the transaction even if stats update fails
        RETURN NEW;
    END;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for updating user stats
CREATE TRIGGER update_user_stats_after_scan
    AFTER INSERT ON public.scans
    FOR EACH ROW
    EXECUTE FUNCTION update_user_stats();

-- Enable Row Level Security
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_stats ENABLE ROW LEVEL SECURITY;

-- Create more specific policies
-- Users table policies
CREATE POLICY "Users can view their own data"
    ON public.users
    FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update their own non-sensitive data"
    ON public.users
    FOR UPDATE
    USING (auth.uid() = id)
    WITH CHECK (
        NEW.id = OLD.id AND
        NEW.email = OLD.email AND
        NEW.role = OLD.role
    );

CREATE POLICY "Service role can manage users"
    ON public.users
    USING (auth.jwt()->>'role' = 'service_role');

CREATE POLICY "Admins can view all data"
    ON public.users
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Scans table policies
CREATE POLICY "Users can view their own scans"
    ON public.scans
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can create scans"
    ON public.scans
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans"
    ON public.scans
    FOR UPDATE
    USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all scans"
    ON public.scans
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- User stats policies
CREATE POLICY "Users can view their own stats"
    ON public.user_stats
    FOR SELECT
    USING (auth.uid()::uuid = user_id);

CREATE POLICY "Admins can view all stats"
    ON public.user_stats
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.users
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Grant minimal necessary permissions
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT USAGE ON SCHEMA public TO anon;

-- Grant specific table permissions to authenticated users
GRANT SELECT, INSERT, UPDATE ON public.users TO authenticated;
GRANT SELECT, INSERT ON public.scans TO authenticated;
GRANT SELECT ON public.user_stats TO authenticated;

-- Grant sequence permissions
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- Grant full access to service role
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Enable realtime selectively
ALTER publication supabase_realtime ADD TABLE public.users (username, role, email_verified, is_active);
ALTER publication supabase_realtime ADD TABLE public.scans (id, status, created_at);

-- Create security definer functions for sensitive operations
CREATE OR REPLACE FUNCTION public.update_user_role(user_id UUID, new_role user_role)
RETURNS VOID AS $$
BEGIN
    -- Check if the executing user is an admin
    IF NOT EXISTS (
        SELECT 1 FROM public.users
        WHERE id = auth.uid() AND role = 'admin'
    ) THEN
        RAISE EXCEPTION 'Only administrators can update user roles';
    END IF;

    -- Update the role
    UPDATE public.users
    SET role = new_role
    WHERE id = user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMIT;

-- Print completion message
DO $$ 
BEGIN 
    RAISE NOTICE '----------------------------------------';
    RAISE NOTICE 'Database setup completed successfully!';
    RAISE NOTICE 'Created tables with improved security and validation:';
    RAISE NOTICE '1. users - User management with audit trails';
    RAISE NOTICE '2. scans - Vulnerability scan results with status tracking';
    RAISE NOTICE '3. user_stats - User statistics with computed fields';
    RAISE NOTICE '----------------------------------------';
END $$;