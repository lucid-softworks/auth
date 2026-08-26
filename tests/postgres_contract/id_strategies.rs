#[path = "id_strategies/database.rs"]
mod database;
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
