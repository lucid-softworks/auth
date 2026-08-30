use super::*;

impl AuthService {
    pub(crate) async fn dash_touch_user_activity(&self, user_id: &str) -> Result<(), AuthError> {
        self.dash_set_user_activity(user_id, Utc::now()).await
    }

    pub(crate) async fn dash_set_user_activity(
        &self,
        user_id: &str,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut additional_fields = Map::new();
        additional_fields.insert("lastActiveAt".into(), json!(last_active_at));
        self.store
            .update_user_profile(
                user_id,
                UserProfileUpdate {
                    additional_fields,
                    ..UserProfileUpdate::default()
                },
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn dash_user_stats(&self) -> Result<Value, AuthError> {
        let now = Utc::now();
        let day = chrono::Duration::days(1);
        let week = chrono::Duration::weeks(1);
        let month = chrono::Duration::days(30);
        let (
            daily,
            previous_daily,
            weekly,
            previous_weekly,
            monthly,
            previous_monthly,
            total,
            daily_active,
            previous_daily_active,
            weekly_active,
            previous_weekly_active,
            monthly_active,
            previous_monthly_active,
        ) = tokio::join!(
            self.dash_signup_window(now - day, None),
            self.dash_signup_window(now - day * 2, Some(now - day)),
            self.dash_signup_window(now - week, None),
            self.dash_signup_window(now - week * 2, Some(now - week)),
            self.dash_signup_window(now - month, None),
            self.dash_signup_window(now - month * 2, Some(now - month)),
            self.store.count_users(&[]),
            self.dash_active_users(now - day, None),
            self.dash_active_users(now - day * 2, Some(now - day)),
            self.dash_active_users(now - week, None),
            self.dash_active_users(now - week * 2, Some(now - week)),
            self.dash_active_users(now - month, None),
            self.dash_active_users(now - month * 2, Some(now - month)),
        );
        let degraded = [
            &daily,
            &previous_daily,
            &weekly,
            &previous_weekly,
            &monthly,
            &previous_monthly,
            &total,
            &daily_active,
            &previous_daily_active,
            &weekly_active,
            &previous_weekly_active,
            &monthly_active,
            &previous_monthly_active,
        ]
        .iter()
        .any(|result| result.is_err());
        let mut body = json!({
            "daily": optional_period(&daily, &previous_daily, "signUps"),
            "weekly": optional_period(&weekly, &previous_weekly, "signUps"),
            "monthly": optional_period(&monthly, &previous_monthly, "signUps"),
            "total": total.ok(),
            "activeUsers": {
                "daily": optional_period(&daily_active, &previous_daily_active, "active"),
                "weekly": optional_period(&weekly_active, &previous_weekly_active, "active"),
                "monthly": optional_period(&monthly_active, &previous_monthly_active, "active"),
            },
        });
        if degraded {
            body.as_object_mut()
                .expect("stats body is an object")
                .insert("degraded".into(), Value::Bool(true));
        }
        Ok(body)
    }

    pub(crate) async fn dash_user_graph(
        &self,
        period: crate::DashPeriod,
    ) -> Result<Value, AuthError> {
        use chrono::Datelike as _;
        let now = Utc::now();
        let (intervals, duration) = match period {
            crate::DashPeriod::Daily => (7, chrono::Duration::days(1)),
            crate::DashPeriod::Weekly => (8, chrono::Duration::weeks(1)),
            crate::DashPeriod::Monthly => (6, chrono::Duration::days(30)),
        };
        let mut data = Vec::with_capacity(intervals);
        for index in (0..intervals).rev() {
            let end = now - duration * index as i32;
            let start = end - duration;
            let total = self
                .store
                .count_users(&[AdminListCondition {
                    field: "createdAt".into(),
                    operator: AdminListOperator::Lte,
                    value: json!(end),
                }])
                .await?;
            let new_users = self.dash_signup_window(start, Some(end)).await?;
            let active = self.dash_active_users(start, Some(end)).await?;
            let label = match period {
                crate::DashPeriod::Daily => end.format("%a").to_string(),
                crate::DashPeriod::Weekly => format!("{} {}", end.format("%b"), end.day()),
                crate::DashPeriod::Monthly => end.format("%b").to_string(),
            };
            data.push(json!({
                "date": end,
                "label": label,
                "totalUsers": total,
                "newUsers": new_users,
                "activeUsers": active,
            }));
        }
        Ok(json!({"data": data, "period": period}))
    }

    pub(crate) async fn dash_user_retention(
        &self,
        period: crate::DashPeriod,
    ) -> Result<Value, AuthError> {
        use chrono::{Datelike as _, NaiveDate, TimeZone as _, Weekday};
        let now = Utc::now();
        let day = now.date_naive();
        let active_start_date = match period {
            crate::DashPeriod::Daily => day,
            crate::DashPeriod::Weekly => {
                let days = match day.weekday() {
                    Weekday::Mon => 0,
                    Weekday::Tue => 1,
                    Weekday::Wed => 2,
                    Weekday::Thu => 3,
                    Weekday::Fri => 4,
                    Weekday::Sat => 5,
                    Weekday::Sun => 6,
                };
                day - chrono::Duration::days(days)
            }
            crate::DashPeriod::Monthly => {
                NaiveDate::from_ymd_opt(day.year(), day.month(), 1).expect("current month is valid")
            }
        };
        let active_start = Utc.from_utc_datetime(
            &active_start_date
                .and_hms_opt(0, 0, 0)
                .expect("midnight is valid"),
        );
        let active_end = add_period(active_start, period, 1);
        let horizons = match period {
            crate::DashPeriod::Daily => 7,
            crate::DashPeriod::Weekly => 8,
            crate::DashPeriod::Monthly => 6,
        };
        let prefix = match period {
            crate::DashPeriod::Daily => "D",
            crate::DashPeriod::Weekly => "W",
            crate::DashPeriod::Monthly => "M",
        };
        let mut data = Vec::with_capacity(horizons);
        for n in 1..=horizons {
            data.push(
                self.dash_retention_bucket(period, n, prefix, active_start, active_end)
                    .await?,
            );
        }
        Ok(json!({"data": data, "period": period}))
    }

    async fn dash_retention_bucket(
        &self,
        period: crate::DashPeriod,
        n: usize,
        prefix: &str,
        active_start: DateTime<Utc>,
        active_end: DateTime<Utc>,
    ) -> Result<Value, AuthError> {
        let cohort_start = add_period(active_start, period, -(n as i32));
        let cohort_end = add_period(cohort_start, period, 1);
        let cohort = self
            .store
            .list_users(&AdminListUsersQuery {
                limit: usize::MAX,
                conditions: vec![
                    AdminListCondition {
                        field: "createdAt".into(),
                        operator: AdminListOperator::Gte,
                        value: json!(cohort_start),
                    },
                    AdminListCondition {
                        field: "createdAt".into(),
                        operator: AdminListOperator::Lt,
                        value: json!(cohort_end),
                    },
                ],
                ..AdminListUsersQuery::default()
            })
            .await?;
        let cohort_size = cohort.len();
        let mut retained = 0_usize;
        for user in &cohort {
            let active = if self
                .dash_plugin()
                .is_some_and(|plugin| plugin.options().activity_tracking.enabled)
            {
                user.additional_fields
                    .get("lastActiveAt")
                    .and_then(|value| serde_json::from_value::<DateTime<Utc>>(value.clone()).ok())
                    .is_some_and(|last| last >= active_start && last < active_end)
            } else {
                self.store
                    .list_sessions(&user.id)
                    .await?
                    .iter()
                    .any(|session| {
                        session.updated_at >= active_start && session.updated_at < active_end
                    })
            };
            retained += usize::from(active);
        }
        let rate = if cohort_size == 0 {
            0.0
        } else {
            ((retained as f64 / cohort_size as f64 * 100.0) * 10.0).round() / 10.0
        };
        Ok(json!({
            "n": n,
            "label": format!("{prefix}{n}"),
            "cohortStart": cohort_start,
            "cohortEnd": cohort_end,
            "activeStart": active_start,
            "activeEnd": active_end,
            "cohortSize": cohort_size,
            "retained": retained,
            "retentionRate": rate,
        }))
    }

    async fn dash_signup_window(
        &self,
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    ) -> Result<i64, AuthError> {
        let mut conditions = vec![AdminListCondition {
            field: "createdAt".into(),
            operator: AdminListOperator::Gte,
            value: json!(from),
        }];
        if let Some(to) = to {
            conditions.push(AdminListCondition {
                field: "createdAt".into(),
                operator: AdminListOperator::Lt,
                value: json!(to),
            });
        }
        self.store.count_users(&conditions).await
    }

    async fn dash_active_users(
        &self,
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    ) -> Result<i64, AuthError> {
        let plugin = self.dash_plugin().expect("Dash routes require DashPlugin");
        if plugin.options().activity_tracking.enabled {
            let mut conditions = vec![AdminListCondition {
                field: "lastActiveAt".into(),
                operator: AdminListOperator::Gte,
                value: json!(from),
            }];
            if let Some(to) = to {
                conditions.push(AdminListCondition {
                    field: "lastActiveAt".into(),
                    operator: AdminListOperator::Lt,
                    value: json!(to),
                });
            }
            return self.store.count_users(&conditions).await;
        }
        let users = self
            .store
            .list_users(&AdminListUsersQuery {
                limit: usize::MAX,
                ..AdminListUsersQuery::default()
            })
            .await?;
        let mut active = 0_i64;
        for user in users {
            if self
                .store
                .list_sessions(&user.id)
                .await?
                .iter()
                .any(|session| {
                    session.updated_at >= from && to.is_none_or(|to| session.updated_at < to)
                })
            {
                active += 1;
            }
        }
        Ok(active)
    }
}
