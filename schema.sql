-- Create user_settings table
CREATE TABLE IF NOT EXISTS user_settings (
    id UUID DEFAULT extensions.uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE NOT NULL,
    scan_depth INTEGER DEFAULT 2 CHECK (scan_depth BETWEEN 1 AND 3),
    concurrent_scans INTEGER DEFAULT 3 CHECK (concurrent_scans BETWEEN 1 AND 5),
    scan_timeout INTEGER DEFAULT 30 CHECK (scan_timeout BETWEEN 5 AND 120),
    auto_scan BOOLEAN DEFAULT false,
    email_notifications BOOLEAN DEFAULT true,
    critical_alerts BOOLEAN DEFAULT true,
    scan_completion BOOLEAN DEFAULT true,
    report_format TEXT DEFAULT 'pdf' CHECK (report_format IN ('pdf', 'html', 'json')),
    include_details BOOLEAN DEFAULT true,
    auto_export BOOLEAN DEFAULT false,
    api_key TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_user_settings_updated_at
    BEFORE UPDATE ON user_settings
    FOR EACH ROW
    EXECUTE PROCEDURE update_updated_at_column();

-- Enable Row Level Security
ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;

-- Create policies
-- Allow users to view only their own settings
CREATE POLICY "Users can view own settings"
    ON user_settings FOR SELECT
    USING (auth.uid() = user_id OR auth.role() = 'service_role');

-- Allow users to insert their own settings
CREATE POLICY "Users can insert own settings"
    ON user_settings FOR INSERT
    WITH CHECK (auth.uid() = user_id OR auth.role() = 'service_role');

-- Allow users to update their own settings
CREATE POLICY "Users can update own settings"
    ON user_settings FOR UPDATE
    USING (auth.uid() = user_id OR auth.role() = 'service_role')
    WITH CHECK (auth.uid() = user_id OR auth.role() = 'service_role');

-- Allow users to delete their own settings
CREATE POLICY "Users can delete own settings"
    ON user_settings FOR DELETE
    USING (auth.uid() = user_id OR auth.role() = 'service_role');

-- Create index for faster lookups
CREATE INDEX idx_user_settings_user_id ON user_settings(user_id);
CREATE INDEX idx_user_settings_api_key ON user_settings(api_key);

-- Function to automatically create settings for new users
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_settings (
        user_id,
        scan_depth,
        concurrent_scans,
        scan_timeout,
        auto_scan,
        email_notifications,
        critical_alerts,
        scan_completion,
        report_format,
        include_details,
        auto_export,
        api_key
    ) VALUES (
        NEW.id,
        2,  -- default scan_depth
        3,  -- default concurrent_scans
        30, -- default scan_timeout
        false, -- default auto_scan
        true,  -- default email_notifications
        true,  -- default critical_alerts
        true,  -- default scan_completion
        'pdf', -- default report_format
        true,  -- default include_details
        false, -- default auto_export
        encode(extensions.gen_random_bytes(32), 'base64')
    );
    RETURN NEW;
END;
$$ language 'plpgsql' security definer;

-- Trigger to create settings when a new user is created
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE PROCEDURE handle_new_user();

 