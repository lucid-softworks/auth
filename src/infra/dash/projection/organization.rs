use super::super::{DashPlugin, tracking::{EventLocation, EventObservation}};
use crate::{AfterOrganizationEvent, AuthUser, Organization};
use serde_json::{Map, Value, json};

mod invitation;
mod member;
mod team;

pub(super) fn project(plugin: &DashPlugin, event: &AfterOrganizationEvent<'_>) {
    let context = crate::database_hooks::current_context();
    let location = EventLocation::from_request(context.request.as_ref());
    let observation = match event {
        AfterOrganizationEvent::Created { organization, user } => observation(
            organization,
            user,
            "organization_created",
            "Organization Created",
            [],
            location,
        ),
        AfterOrganizationEvent::Updated { organization, user } => observation(
            organization,
            user,
            "organization_updated",
            "Organization Updated",
            [],
            location,
        ),
        event @ (AfterOrganizationEvent::MemberAdded { .. }
        | AfterOrganizationEvent::MemberRemoved { .. }
        | AfterOrganizationEvent::MemberRoleUpdated { .. }) => member::project(event, location),
        event @ (AfterOrganizationEvent::MemberInvited { .. }
        | AfterOrganizationEvent::InvitationAccepted { .. }
        | AfterOrganizationEvent::InvitationRejected { .. }
        | AfterOrganizationEvent::InvitationCanceled { .. }) => invitation::project(event, location),
        event @ (AfterOrganizationEvent::TeamCreated { .. }
        | AfterOrganizationEvent::TeamUpdated { .. }
        | AfterOrganizationEvent::TeamDeleted { .. }
        | AfterOrganizationEvent::TeamMemberAdded { .. }
        | AfterOrganizationEvent::TeamMemberRemoved { .. }) => team::project(event, location),
    };
    plugin.track_event(observation, Some(&context));
}

pub(super) fn observation(
    organization: &Organization,
    user: &AuthUser,
    event_type: &'static str,
    display: &'static str,
    extra: impl IntoIterator<Item = (&'static str, Value)>,
    location: EventLocation,
) -> EventObservation {
    let mut data = Map::from_iter([
        ("organizationId".into(), json!(organization.id)),
        ("organizationSlug".into(), json!(organization.slug)),
        ("organizationName".into(), json!(organization.name)),
    ]);
    data.extend(extra.into_iter().map(|(key, value)| (key.into(), value)));
    data.extend([
        ("triggeredBy".into(), json!(user.id)),
        ("triggerContext".into(), json!("organization")),
    ]);
    EventObservation::new(
        event_type,
        &organization.id,
        display,
        Value::Object(data),
        location,
    )
}
