use super::super::{DashPlugin, tracking::EventObservation};
use super::support::{ProjectionContext, data, route, trigger};
use crate::{AuthService, AuthUser, DatabaseHookContext};
use serde_json::{Value, json};

pub(super) async fn created(
    plugin: &DashPlugin,
    service: &AuthService,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    let trigger = trigger(service, context, &user.id).await;
    plugin.track_event(
        EventObservation::new(
            "user_created",
            &user.id,
            format!(
                "{} signed up",
                if user.name.is_empty() {
                    user.email.as_str()
                } else {
                    user.name.as_str()
                }
            ),
            user_data(user, &trigger, &[]),
            projection.location.clone(),
        ),
        Some(context),
    );
}

pub(super) async fn updated(
    plugin: &DashPlugin,
    service: &AuthService,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    let trigger = trigger(service, context, &user.id).await;
    let fields = projection.body.keys().cloned().collect::<Vec<_>>();
    let only_image = fields.as_slice() == ["image"];
    let only_verified = fields.as_slice() == ["emailVerified"];
    let has_verified = fields.iter().any(|field| field == "emailVerified");
    let mut events = profile_events(
        user,
        &trigger,
        &projection,
        &fields,
        only_image,
        only_verified,
        has_verified,
    );
    events.extend(admin_events(user, &trigger, &projection));
    for event in events {
        plugin.track_event(event, Some(context));
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_events(
    user: &AuthUser,
    trigger: &super::support::Trigger,
    projection: &ProjectionContext,
    fields: &[String],
    only_image: bool,
    only_verified: bool,
    has_verified: bool,
) -> Vec<EventObservation> {
    let mut events = Vec::new();
    if route(&projection.path, "/update-user") || route(&projection.path, "/dash/update-user") {
        if only_verified && user.email_verified {
            events.push(email_verified(user, trigger, projection.location.clone()));
        } else if only_image && user.image.is_some() {
            events.push(simple(
                user,
                trigger,
                "profile_image_updated",
                "Profile image updated",
                projection.location.clone(),
            ));
        } else if !only_image && !only_verified {
            events.push(EventObservation::new(
                "profile_updated",
                &user.id,
                "Profile updated",
                user_data(user, trigger, &[("updatedFields", json!(fields))]),
                projection.location.clone(),
            ));
            if has_verified && user.email_verified {
                events.push(email_verified(user, trigger, projection.location.clone()));
            }
        }
    } else if route(&projection.path, "/change-email") {
        events.push(EventObservation::new(
            "profile_updated",
            &user.id,
            "Profile updated",
            user_data(user, trigger, &[("updatedFields", json!(fields))]),
            projection.location.clone(),
        ));
    }
    if route(&projection.path, "/verify-email") && user.email_verified {
        events.push(email_verified(user, trigger, projection.location.clone()));
    }
    events
}

fn admin_events(
    user: &AuthUser,
    trigger: &super::support::Trigger,
    projection: &ProjectionContext,
) -> Vec<EventObservation> {
    let mut events = Vec::new();
    if route(&projection.path, "/admin/ban-user") && user.banned {
        let reason = user
            .ban_reason
            .as_ref()
            .map(|reason| format!(": {reason}"))
            .unwrap_or_default();
        let expiry = user
            .ban_expires
            .map(|expires| format!(" (until {})", expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)))
            .unwrap_or_default();
        events.push(EventObservation::new(
            "user_banned",
            &user.id,
            format!("User banned{reason}{expiry}"),
            user_data(
                user,
                trigger,
                &[
                    ("banned", json!(user.banned)),
                    ("banReason", json!(user.ban_reason)),
                    ("banExpires", json!(user.ban_expires)),
                ],
            ),
            projection.location.clone(),
        ));
    }
    if route(&projection.path, "/admin/unban-user") && !user.banned {
        events.push(EventObservation::new(
            "user_unbanned",
            &user.id,
            "User unbanned",
            user_data(user, trigger, &[("banned", json!(false))]),
            projection.location.clone(),
        ));
    }
    events
}

pub(super) async fn deleted(
    plugin: &DashPlugin,
    service: &AuthService,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    let trigger = trigger(service, context, &user.id).await;
    plugin.track_event(
        simple(
            user,
            &trigger,
            "user_deleted",
            "User deleted",
            projection.location,
        ),
        Some(context),
    );
}

fn email_verified(
    user: &AuthUser,
    trigger: &super::support::Trigger,
    location: super::super::tracking::EventLocation,
) -> EventObservation {
    simple(user, trigger, "email_verified", "Email verified", location)
}

fn simple(
    user: &AuthUser,
    trigger: &super::support::Trigger,
    event_type: &'static str,
    display: &'static str,
    location: super::super::tracking::EventLocation,
) -> EventObservation {
    EventObservation::new(
        event_type,
        &user.id,
        display,
        user_data(user, trigger, &[]),
        location,
    )
}

fn user_data(
    user: &AuthUser,
    trigger: &super::support::Trigger,
    extra: &[(&'static str, Value)],
) -> Value {
    let mut entries = vec![
        ("userId", json!(user.id)),
        ("userEmail", json!(user.email)),
        ("userName", json!(user.name)),
    ];
    entries.extend(extra.iter().cloned());
    entries.extend([
        ("triggeredBy", json!(trigger.actor)),
        ("triggerContext", json!(trigger.context)),
    ]);
    data(entries)
}
