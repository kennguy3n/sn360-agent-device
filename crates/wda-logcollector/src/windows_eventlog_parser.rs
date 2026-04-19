//! Parser for Windows Event Log XML fragments produced by `EvtRender`.
//!
//! Kept target-agnostic so the unit tests can run on any host. The
//! parser intentionally avoids a full XML dependency: event XML is
//! well-formed and regular enough that a small hand-rolled scanner is
//! adequate for the handful of fields we care about.

/// Turn an event log XML fragment into a compact, human-readable text
/// representation suitable for publishing on the event bus.
///
/// The output contains the most useful System-level fields (Provider,
/// EventID, Level, TimeCreated, Channel, Computer) followed by every
/// `<Data>` element under `<EventData>`. Returns the raw XML if no
/// recognised fields are found, so we never drop data.
pub fn parse_event_message(xml: &str) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(v) = extract_attr(xml, "Provider", "Name") {
        parts.push(format!("Provider: {}", v));
    }
    if let Some(v) = extract_element_text(xml, "EventID") {
        parts.push(format!("EventID: {}", v.trim()));
    }
    if let Some(v) = extract_element_text(xml, "Level") {
        parts.push(format!("Level: {}", v.trim()));
    }
    if let Some(v) = extract_attr(xml, "TimeCreated", "SystemTime") {
        parts.push(format!("TimeCreated: {}", v));
    }
    if let Some(v) = extract_element_text(xml, "Channel") {
        parts.push(format!("Channel: {}", v.trim()));
    }
    if let Some(v) = extract_element_text(xml, "Computer") {
        parts.push(format!("Computer: {}", v.trim()));
    }

    for (name, value) in extract_data_elements(xml) {
        match name {
            Some(n) => parts.push(format!("Data [{}]: {}", n, value.trim())),
            None => parts.push(format!("Data: {}", value.trim())),
        }
    }

    if parts.is_empty() {
        xml.to_string()
    } else {
        parts.join("\n")
    }
}

/// Extract the text content of the first `<tag ...>content</tag>`.
/// Returns None for self-closing tags.
fn extract_element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let after_open = &xml[start + open.len()..];

    // The character right after the tag name must be whitespace, '>'
    // or '/' — otherwise we matched a prefix (e.g. "EventID" is a
    // prefix of "EventIDQualifiers").
    let next = after_open.chars().next()?;
    if !matches!(next, ' ' | '\t' | '\n' | '\r' | '>' | '/') {
        // Recurse on the remainder to look for a later match.
        let next_start = start + open.len();
        return extract_element_text(&xml[next_start..], tag);
    }

    let tag_end = after_open.find('>')?;
    // Self-closing tags have no text content.
    if after_open[..tag_end].ends_with('/') {
        return None;
    }
    let content_start = start + open.len() + tag_end + 1;
    let rel_close = xml[content_start..].find(&close)?;
    Some(xml[content_start..content_start + rel_close].to_string())
}

/// Extract the value of `attr` on the first `<tag ...>` opening tag.
fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let start = xml.find(&open)?;
    let after = &xml[start..];

    let next = after.as_bytes().get(open.len()).copied()?;
    if !matches!(next, b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') {
        let next_start = start + open.len();
        return extract_attr(&xml[next_start..], tag, attr);
    }

    let close = after.find('>')?;
    let tag_contents = &after[..close];
    extract_attr_in_tag(tag_contents, attr)
}

/// Extract every `<Data>` element in document order, along with its
/// optional `Name` attribute. Handles both `<Data Name="x">value</Data>`
/// and self-closing `<Data Name="x"/>` forms.
fn extract_data_elements(xml: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    let open = "<Data";
    let close = "</Data>";

    while let Some(found) = xml[cursor..].find(open) {
        let tag_start = cursor + found;
        // Ensure we matched the whole element name, not a prefix.
        let after_tag = &xml[tag_start + open.len()..];
        let next = match after_tag.chars().next() {
            Some(c) => c,
            None => break,
        };
        if !matches!(next, ' ' | '\t' | '\n' | '\r' | '>' | '/') {
            cursor = tag_start + open.len();
            continue;
        }

        let tag_end_rel = match after_tag.find('>') {
            Some(i) => i,
            None => break,
        };
        let tag_contents = &after_tag[..tag_end_rel];
        let name = extract_attr_in_tag(tag_contents, "Name");

        let self_closing = tag_contents.ends_with('/');
        let value_start = tag_start + open.len() + tag_end_rel + 1;

        if self_closing {
            out.push((name, String::new()));
            cursor = value_start;
            continue;
        }

        let rel_close = match xml[value_start..].find(close) {
            Some(i) => i,
            None => break,
        };
        let value = xml[value_start..value_start + rel_close].to_string();
        out.push((name, value));
        cursor = value_start + rel_close + close.len();
    }

    out
}

/// Extract the value of `attr` from the body of an opening tag
/// (the text between `<TagName` and `>`). Accepts either single or
/// double-quoted attribute values, matching the XML 1.0 grammar.
fn extract_attr_in_tag(tag_body: &str, attr: &str) -> Option<String> {
    let eq_marker = format!("{}=", attr);
    let mut search_from = 0usize;
    // Skip attribute names that end with `attr` as a suffix (e.g. the
    // request for `Name` should not match `FileName`).
    loop {
        let rel = tag_body[search_from..].find(&eq_marker)?;
        let eq_pos = search_from + rel;
        let preceding = tag_body.as_bytes().get(eq_pos.wrapping_sub(1)).copied();
        match preceding {
            Some(b) if b.is_ascii_alphanumeric() || b == b'-' || b == b':' || b == b'_' => {
                search_from = eq_pos + eq_marker.len();
                continue;
            }
            _ => {
                let value_start = eq_pos + eq_marker.len();
                let quote = tag_body.as_bytes().get(value_start).copied()?;
                if quote != b'"' && quote != b'\'' {
                    return None;
                }
                let rest = &tag_body[value_start + 1..];
                let end = rest.find(quote as char)?;
                return Some(rest[..end].to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SECURITY_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime='2026-04-19T03:00:00.000000000Z'/>
    <EventRecordID>12345</EventRecordID>
    <Correlation/>
    <Execution ProcessID='624' ThreadID='724'/>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    <Data Name='SubjectDomainName'>NT AUTHORITY</Data>
    <Data Name='TargetUserName'>alice</Data>
    <Data Name='LogonType'>3</Data>
  </EventData>
</Event>"#;

    #[test]
    fn parses_provider_attribute() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Provider: Microsoft-Windows-Security-Auditing"));
    }

    #[test]
    fn parses_event_id_text() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("EventID: 4624"));
    }

    #[test]
    fn parses_level_text() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Level: 0"));
    }

    #[test]
    fn parses_time_created_attribute() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("TimeCreated: 2026-04-19T03:00:00.000000000Z"));
    }

    #[test]
    fn parses_channel_and_computer() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Channel: Security"));
        assert!(msg.contains("Computer: DESKTOP-ABC"));
    }

    #[test]
    fn parses_named_data_elements() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Data [SubjectUserName]: SYSTEM"));
        assert!(msg.contains("Data [TargetUserName]: alice"));
        assert!(msg.contains("Data [LogonType]: 3"));
    }

    #[test]
    fn ignores_prefix_matches_for_event_id() {
        let xml = r#"<Event>
            <System>
                <EventIDQualifiers>42</EventIDQualifiers>
                <EventID>1234</EventID>
            </System>
        </Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("EventID: 1234"));
        // Make sure we did not pick up the Qualifiers value.
        assert!(!msg.contains("EventID: 42"));
    }

    #[test]
    fn handles_self_closing_data_elements() {
        let xml = r#"<Event><EventData>
            <Data Name='Empty'/>
            <Data Name='Filled'>value</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Data [Empty]: "));
        assert!(msg.contains("Data [Filled]: value"));
    }

    #[test]
    fn handles_unnamed_data_elements() {
        let xml = r#"<Event><EventData>
            <Data>positional value</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Data: positional value"));
    }

    #[test]
    fn returns_raw_xml_when_no_fields_match() {
        let xml = "<Something/>";
        let msg = parse_event_message(xml);
        assert_eq!(msg, xml);
    }

    #[test]
    fn handles_missing_optional_fields() {
        let xml = r#"<Event>
            <System>
                <EventID>1</EventID>
            </System>
        </Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("EventID: 1"));
        assert!(!msg.contains("Level:"));
        assert!(!msg.contains("Channel:"));
    }
}
