use std::mem;

/// Extract likely package executables from a deliberately small shell subset.
pub fn extract_script_commands(command: &str) -> Vec<String> {
    let segments = tokenize_segments(command);
    let mut commands = Vec::new();
    for mut words in segments {
        while words.first().is_some_and(|word| is_assignment(word)) {
            words.remove(0);
        }
        while words
            .first()
            .is_some_and(|word| matches!(word.as_str(), "env" | "cross-env"))
        {
            words.remove(0);
            while words.first().is_some_and(|word| is_assignment(word)) {
                words.remove(0);
            }
        }
        let Some(command) = unwrap_command(&words) else {
            continue;
        };
        let executable = command.rsplit(['/', '\\']).next().unwrap_or(command);
        if !is_shell_builtin(executable) {
            commands.push(executable.to_string());
        }
    }
    commands.sort();
    commands.dedup();
    commands
}

fn unwrap_command(words: &[String]) -> Option<&str> {
    let first = words.first()?.as_str();
    match first {
        "npx" | "bunx" => first_non_flag(&words[1..]),
        "npm" | "pnpm" => {
            let action = words.get(1)?.as_str();
            if matches!(action, "exec" | "x") {
                first_non_flag(&words[2..])
            } else {
                None
            }
        }
        "yarn" => {
            let rest = match words.get(1).map(String::as_str) {
                Some("exec" | "run") => &words[2..],
                _ => &words[1..],
            };
            first_non_flag(rest)
        }
        _ => Some(first),
    }
}

fn first_non_flag(words: &[String]) -> Option<&str> {
    words
        .iter()
        .map(String::as_str)
        .find(|word| *word != "--" && !word.starts_with('-'))
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
    })
}

fn is_shell_builtin(command: &str) -> bool {
    matches!(
        command,
        "cd" | "echo" | "export" | "set" | "unset" | "source" | "." | "true" | "false"
    )
}

fn tokenize_segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                word.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            ' ' | '\t' | '\n' => push_word(&mut words, &mut word),
            ';' | '|' => {
                if chars.peek() == Some(&character) {
                    chars.next();
                }
                push_segment(&mut segments, &mut words, &mut word);
            }
            '&' => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                }
                push_segment(&mut segments, &mut words, &mut word);
            }
            _ => word.push(character),
        }
    }
    push_segment(&mut segments, &mut words, &mut word);
    segments
}

fn push_word(words: &mut Vec<String>, word: &mut String) {
    if !word.is_empty() {
        words.push(mem::take(word));
    }
}

fn push_segment(segments: &mut Vec<Vec<String>>, words: &mut Vec<String>, word: &mut String) {
    push_word(words, word);
    if !words.is_empty() {
        segments.push(mem::take(words));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_chained_commands_and_ignores_assignments() {
        assert_eq!(
            extract_script_commands("NODE_ENV=test tsc && vite build || biome check .; echo done"),
            vec!["biome", "tsc", "vite"]
        );
    }

    #[test]
    fn unwraps_supported_package_runners() {
        assert_eq!(extract_script_commands("npx vite"), vec!["vite"]);
        assert_eq!(
            extract_script_commands("npm exec -- vitest run"),
            vec!["vitest"]
        );
        assert_eq!(
            extract_script_commands("pnpm exec biome check"),
            vec!["biome"]
        );
        assert_eq!(extract_script_commands("bunx eslint ."), vec!["eslint"]);
        assert_eq!(extract_script_commands("yarn vite build"), vec!["vite"]);
    }
}
