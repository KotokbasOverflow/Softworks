//! Subsequence fuzzy matching with a cheap relevance score.
//!
//! Higher is better. Name matches outrank command matches via caller-supplied
//! field weights — see [`search`](crate::search).

/// Score `query` against `target` (both matched case-insensitively).
/// Returns `None` when the query is not a subsequence of the target.
pub fn fuzzy_score(query: &str, target: &str) -> Option<i64> {
    let q: Vec<char> = query.to_lowercase().chars().collect();
    let t: Vec<char> = target.to_lowercase().chars().collect();
    if q.is_empty() {
        return Some(0);
    }
    let mut ti = 0usize;
    let mut score: i64 = 100;
    let mut first_pos: Option<usize> = None;
    let mut prev_match: Option<usize> = None;

    for qc in &q {
        let mut found = None;
        while ti < t.len() {
            if t[ti] == *qc {
                found = Some(ti);
                ti += 1;
                break;
            }
            ti += 1;
        }
        let pos = found?;
        if first_pos.is_none() {
            first_pos = Some(pos);
        }
        // Consecutive matches are worth more than scattered ones.
        if prev_match.is_some_and(|p| p + 1 == pos) {
            score += 5;
        } else {
            score -= 2;
        }
        prev_match = Some(pos);
    }
    // Early matches rank higher.
    score -= first_pos.unwrap_or(t.len()) as i64;
    Some(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_beats_scattered() {
        let exact = fuzzy_score("docker", "docker cleanup").unwrap();
        let scattered = fuzzy_score("docker", "d-x-o-c-k-e-r").unwrap();
        assert!(exact > scattered);
    }

    #[test]
    fn early_beats_late_and_case_insensitive() {
        assert!(
            fuzzy_score("DOCK", "docker ps").unwrap() > fuzzy_score("DOCK", "xxdocker").unwrap()
        );
    }

    #[test]
    fn non_subsequence_is_none() {
        assert_eq!(fuzzy_score("zzz", "docker ps"), None);
        assert_eq!(fuzzy_score("", "anything"), Some(0));
    }
}
