CREATE UNIQUE INDEX IF NOT EXISTS lucid_auth_users_phone_number_unique_idx
    ON lucid_auth_users ((additional_fields ->> 'phoneNumber'))
    WHERE additional_fields ? 'phoneNumber'
      AND additional_fields ->> 'phoneNumber' IS NOT NULL;
