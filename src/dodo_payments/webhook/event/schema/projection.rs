use serde_json::Value;

pub(super) fn object(value: &Value, fields: &[&str]) -> Value {
    let source = value
        .as_object()
        .expect("projection follows successful object validation");
    Value::Object(
        fields
            .iter()
            .filter_map(|field| {
                source
                    .get(*field)
                    .map(|value| ((*field).to_owned(), value.clone()))
            })
            .collect(),
    )
}

pub(super) fn nested_object(projected: &mut Value, field: &str, normalize: fn(&Value) -> Value) {
    if let Some(value) = projected
        .as_object_mut()
        .and_then(|object| object.get_mut(field))
        && !value.is_null()
    {
        *value = normalize(value);
    }
}

pub(super) fn object_array(projected: &mut Value, field: &str, normalize: fn(&Value) -> Value) {
    let Some(value) = projected
        .as_object_mut()
        .and_then(|object| object.get_mut(field))
    else {
        return;
    };
    let Some(items) = value.as_array_mut() else {
        return;
    };
    for item in items {
        *item = normalize(item);
    }
}
