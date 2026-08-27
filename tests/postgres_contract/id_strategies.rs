#[path = "id_strategies/callback.rs"]
mod callback;
#[path = "id_strategies/database.rs"]
mod database;
#[path = "id_strategies/oauth_provider_database.rs"]
mod oauth_provider_database;
#[path = "id_strategies/oauth_provider_fixtures.rs"]
mod oauth_provider_fixtures;
#[path = "id_strategies/oauth_provider_round_trip.rs"]
mod oauth_provider_round_trip;
#[path = "id_strategies/organization_database.rs"]
mod organization_database;
#[path = "id_strategies/organization_round_trip.rs"]
mod organization_round_trip;
#[path = "id_strategies/plugin_round_trip.rs"]
mod plugin_round_trip;
#[path = "id_strategies/returned_verification.rs"]
mod returned_verification;
#[path = "id_strategies/round_trip.rs"]
mod round_trip;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn core_database_id_strategies_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    round_trip::all_application_and_native_strategies().await?;
    returned_verification::database_ids_are_hydrated_and_missing_ids_error().await
}
