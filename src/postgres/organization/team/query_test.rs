use super::*;
use chrono::Utc;
use uuid::Uuid;

#[test]
fn team_queries_remap_update_delete_member_sort_and_user_join() {
    let physical = super::super::super::test_support::physical_schema();
    let team = physical.model("team").unwrap();
    let member = physical.model("teamMember").unwrap();
    let team_id = Uuid::from_u128(41).to_string();
    let user_id = Uuid::from_u128(42).to_string();
    let record = OrganizationTeam {
        id: team_id.clone(),
        name: "secret team".into(),
        organization_id: Uuid::from_u128(43).to_string(),
        created_at: Utc::now(),
        updated_at: Some(Utc::now()),
    };

    let list = list_teams_query(&team, &record.organization_id).unwrap();
    assert!(list.sql().contains("FROM \"org\"\"teams\""));
    assert!(list.sql().contains("WHERE \"tenant id\" = $1"));
    assert!(list.sql().contains("ORDER BY \"created time\" ASC"));

    let update = update_team_query(&team, &record).unwrap();
    assert!(update.sql().contains("SET \"team name\" = $1"));
    assert!(update.sql().contains("\"member count\" AS \"memberCount\""));
    assert!(
        update
            .sql()
            .ends_with(&format!(") RETURNING {}", team.all_projection()))
    );
    assert!(!update.sql().contains("secret team"));

    let user_id = user_id.to_string();
    let delete = delete_team_member_query(&member, &team_id, &user_id).unwrap();
    assert!(
        delete
            .sql()
            .starts_with("DELETE FROM \"org\"\"team members\"")
    );
    assert!(
        delete
            .sql()
            .contains("\"team id\" = $1 AND \"person id\" = $2")
    );

    let members = list_team_members_query(&member, &team_id).unwrap();
    assert!(members.sql().contains("ORDER BY \"joined time\" ASC"));
    let user_teams = list_user_teams_query(&team, &member, &user_id).unwrap();
    assert!(user_teams.sql().contains("FROM \"org\"\"team members\""));
    assert!(
        user_teams
            .sql()
            .contains("\"team id\" = \"org\"\"teams\".\"id\"")
    );
    assert!(user_teams.sql().contains("\"person id\" = $1"));
}
