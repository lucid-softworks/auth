use crate::AgentCapability;

pub(super) fn match_query(query: &str, capabilities: Vec<AgentCapability>) -> Vec<AgentCapability> {
    let raw = query.trim();
    if raw.is_empty() {
        return capabilities;
    }
    if let Some((pattern, flags)) = raw
        .strip_prefix('/')
        .and_then(|value| value.rsplit_once('/'))
        && valid_flags(flags)
        && let Some(regex) = SearchRegex::new(pattern, flags)
    {
        return match_regex(regex, &capabilities);
    }
    if raw.contains(['*', '?']) {
        return match_pattern(raw, &capabilities);
    }
    let terms: Vec<_> = raw.split_whitespace().map(str::to_lowercase).collect();
    let mut scored = Vec::new();
    for capability in capabilities {
        let name_tokens = tokenize(&capability.name);
        let name = capability.name.to_lowercase();
        let description_tokens = tokenize(&capability.description);
        let description = capability.description.to_lowercase();
        let mut name_hits = 0;
        let mut description_hits = 0;
        for term in &terms {
            let in_name = term_matches_text(term, &name)
                || name_tokens
                    .iter()
                    .any(|token| term_matches_token(term, token));
            let in_description = term_matches_text(term, &description)
                || description_tokens
                    .iter()
                    .any(|token| term_matches_token(term, token));
            if in_name {
                name_hits += 1;
            } else if in_description {
                description_hits += 1;
            }
        }
        let score = name_hits * 2 + description_hits;
        if score > 0 {
            scored.push((score, capability));
        }
    }
    scored.sort_by_key(|item| std::cmp::Reverse(item.0));
    scored
        .into_iter()
        .map(|(_, capability)| capability)
        .collect()
}

fn tokenize(value: &str) -> Vec<String> {
    let mut separated = String::with_capacity(value.len());
    let mut previous_lower = false;
    for character in value.chars() {
        if previous_lower && character.is_ascii_uppercase() {
            separated.push(' ');
        }
        separated.push(if character.is_ascii_alphanumeric() {
            character
        } else {
            ' '
        });
        previous_lower = character.is_ascii_lowercase();
    }
    separated
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn stem(word: &str) -> String {
    if word.len() <= 3 {
        return word.to_owned();
    }
    for (suffix, replacement, minimum) in [
        ("ies", "y", 4),
        ("ing", "", 5),
        ("tion", "", 5),
        ("ness", "", 5),
        ("es", "", 4),
    ] {
        if word.ends_with(suffix) && word.len() > minimum {
            return format!("{}{replacement}", &word[..word.len() - suffix.len()]);
        }
    }
    if word.ends_with('s') && !word.ends_with("ss") && word.len() > 3 {
        return word[..word.len() - 1].to_owned();
    }
    word.to_owned()
}

fn stemmed_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left = stem(left);
    let right = stem(right);
    left == right || left.starts_with(&right) || right.starts_with(&left)
}

fn synonyms(term: &str) -> &'static [&'static str] {
    match term {
        "email" => &["message", "mail"],
        "message" => &["email", "mail"],
        "mail" => &["email", "message"],
        "send" => &["deliver", "dispatch", "compose"],
        "delete" => &["remove", "trash", "destroy"],
        "remove" => &["delete", "trash"],
        "trash" => &["delete", "remove"],
        "create" => &["add", "new", "make"],
        "add" => &["create", "new"],
        "get" => &["read", "fetch", "retrieve", "view"],
        "read" => &["get", "fetch", "view"],
        "fetch" => &["get", "read", "retrieve"],
        "update" => &["modify", "edit", "change", "patch"],
        "modify" => &["update", "edit", "change"],
        "edit" => &["update", "modify", "change"],
        _ => &[],
    }
}

fn expanded(term: &str) -> Vec<String> {
    let stemmed = stem(term);
    let synonyms = if synonyms(term).is_empty() {
        synonyms(&stemmed)
    } else {
        synonyms(term)
    };
    let mut values = vec![term.to_owned(), stemmed];
    values.extend(synonyms.iter().map(|value| (*value).to_owned()));
    values.extend(synonyms.iter().map(|value| stem(value)));
    values
}

fn term_matches_token(term: &str, token: &str) -> bool {
    expanded(term)
        .iter()
        .any(|expanded| stemmed_match(expanded, token))
}

fn term_matches_text(term: &str, text: &str) -> bool {
    expanded(term)
        .iter()
        .any(|expanded| text.contains(expanded))
}

fn match_pattern(pattern: &str, capabilities: &[AgentCapability]) -> Vec<AgentCapability> {
    let escaped = regex::escape(pattern)
        .replace(r"\*", ".*")
        .replace(r"\?", ".");
    let regex = regex::RegexBuilder::new(&format!("^{escaped}$"))
        .case_insensitive(true)
        .build()
        .expect("escaped glob is a valid regex");
    match_regex(SearchRegex::stateless(regex), capabilities)
}

fn match_regex(mut regex: SearchRegex, capabilities: &[AgentCapability]) -> Vec<AgentCapability> {
    let mut names = Vec::new();
    let mut descriptions = Vec::new();
    for capability in capabilities {
        if regex.test(&capability.name) {
            names.push(capability.clone());
        } else if regex.test(&capability.description) {
            descriptions.push(capability.clone());
        }
    }
    names.extend(descriptions);
    names
}

fn valid_flags(flags: &str) -> bool {
    flags.chars().all(|flag| "gimsuy".contains(flag))
        && flags
            .chars()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == flags.len()
}

struct SearchRegex {
    regex: regex::Regex,
    global: bool,
    sticky: bool,
    last_index: usize,
}

impl SearchRegex {
    fn new(pattern: &str, flags: &str) -> Option<Self> {
        let mut builder = regex::RegexBuilder::new(pattern);
        builder
            .case_insensitive(flags.contains('i'))
            .multi_line(flags.contains('m'))
            .dot_matches_new_line(flags.contains('s'));
        Some(Self {
            regex: builder.build().ok()?,
            global: flags.contains('g'),
            sticky: flags.contains('y'),
            last_index: 0,
        })
    }

    fn stateless(regex: regex::Regex) -> Self {
        Self {
            regex,
            global: false,
            sticky: false,
            last_index: 0,
        }
    }

    fn test(&mut self, value: &str) -> bool {
        if !self.global && !self.sticky {
            return self.regex.is_match(value);
        }
        let Some(start) = utf16_to_byte(value, self.last_index) else {
            self.last_index = 0;
            return false;
        };
        let found = self.regex.find_at(value, start);
        let found = found.filter(|found| !self.sticky || found.start() == start);
        if let Some(found) = found {
            self.last_index = value[..found.end()].encode_utf16().count();
            true
        } else {
            self.last_index = 0;
            false
        }
    }
}

fn utf16_to_byte(value: &str, target: usize) -> Option<usize> {
    let mut units = 0;
    for (index, character) in value.char_indices() {
        if units == target {
            return Some(index);
        }
        units += character.len_utf16();
        if units > target {
            return None;
        }
    }
    (units == target).then_some(value.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_search_supports_stemming_synonyms_and_globs() {
        let caps = vec![
            AgentCapability::new("messages.create", "Compose email"),
            AgentCapability::new("files.delete", "Destroy a file"),
        ];
        assert_eq!(match_query("send", caps.clone())[0].name, "messages.create");
        assert_eq!(match_query("remove", caps.clone())[0].name, "files.delete");
        assert_eq!(match_query("messages.*", caps)[0].name, "messages.create");
    }

    #[test]
    fn global_regex_last_index_is_shared_across_capabilities_like_javascript() {
        let caps = vec![
            AgentCapability::new("a", "x"),
            AgentCapability::new("a", "a"),
            AgentCapability::new("a", "x"),
        ];
        let matched = match_query("/a/g", caps);
        assert_eq!(
            matched
                .iter()
                .map(|capability| capability.description.as_str())
                .collect::<Vec<_>>(),
            ["x", "a"]
        );
    }

    #[test]
    fn duplicate_javascript_regex_flags_make_the_query_plain_text() {
        let caps = vec![AgentCapability::new("a", "letter")];
        assert!(match_query("/a/gg", caps).is_empty());
    }
}
