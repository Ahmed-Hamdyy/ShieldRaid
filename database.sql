-- Enable replica identity for the users table
ALTER TABLE public.users REPLICA IDENTITY FULL;

-- Drop existing publication if it exists
DROP PUBLICATION IF EXISTS supabase_realtime;

-- Create publication with full replication support
CREATE PUBLICATION supabase_realtime FOR ALL TABLES WITH (publish = 'insert,update,delete');

-- Create RPC function for updating user roles
CREATE OR REPLACE FUNCTION update_user_role_by_uuid(user_id_param UUID, new_role_param TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE public.users
    SET role = new_role_param,
        updated_at = NOW()
    WHERE id = user_id_param;
    
    RETURN FOUND;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$;

-- Grant execute permission on the function
GRANT EXECUTE ON FUNCTION update_user_role_by_uuid TO authenticated;

// ... existing code ... 