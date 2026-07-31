// holds the question pool with difficulty tagging

use crate::error::{Error, Result};
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionVariant {
    pub id: u64,
    pub substitutions: HashMap<String, String>,
    pub options: Vec<String>,
    pub correct_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionItem {
    pub id: u64,
    pub difficulty: Difficulty,
    pub stem: String,
    pub variants: Vec<QuestionVariant>,
}

#[derive(Debug, Clone)]
pub struct QuestionBank {
    pub items: Vec<QuestionItem>,
    pub easy_indices: Vec<usize>,
    pub medium_indices: Vec<usize>,
    pub hard_indices: Vec<usize>,
}

impl QuestionBank {
    pub fn new(items: Vec<QuestionItem>) -> Result<Self> {
        if items.is_empty() {
            return Err(Error::InvalidInput("question bank cannot be empty".into()));
        }
        let mut easy = Vec::new();
        let mut medium = Vec::new();
        let mut hard = Vec::new();
        for (i, item) in items.iter().enumerate() {
            if item.variants.is_empty() {
                return Err(Error::InvalidInput(format!(
                    "question item {} has no variants",
                    item.id
                )));
            }
            match item.difficulty {
                Difficulty::Easy => easy.push(i),
                Difficulty::Medium => medium.push(i),
                Difficulty::Hard => hard.push(i),
            }
        }
        if easy.is_empty() || medium.is_empty() || hard.is_empty() {
            return Err(Error::InvalidInput(
                "question bank must contain at least one item of each difficulty".into(),
            ));
        }
        Ok(Self {
            items,
            easy_indices: easy,
            medium_indices: medium,
            hard_indices: hard,
        })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct DifficultyRatio {
    pub easy: f64,
    pub medium: f64,
    pub hard: f64,
}

impl DifficultyRatio {
    pub fn new(easy: f64, medium: f64, hard: f64) -> Result<Self> {
        let total = easy + medium + hard;
        if (total - 1.0).abs() > 1e-6 {
            return Err(Error::InvalidInput(
                "difficulty ratio must sum to 1.0".into(),
            ));
        }

        if easy < 0.0 || medium < 0.0 || hard < 0.0 {
            return Err(Error::InvalidInput(
                "difficulty ratio must be non-negative".into(),
            ));
        }

        Ok(Self { easy, medium, hard })
    }
}

// creates a unique encrypted packet per student
pub fn select_questions<'a>(
    bank: &'a QuestionBank,
    num_questions: usize,
    ratio: &DifficultyRatio,
    rng: &mut impl Rng,
) -> Result<Vec<&'a QuestionItem>> {
    // stratified sampling: draw proportionally from each difficulty pool
    let n_easy = (num_questions as f64 * ratio.easy).round() as usize;
    let n_medium = (num_questions as f64 * ratio.medium).round() as usize;
    let n_hard = (num_questions as f64 * ratio.hard).round() as usize;

    if n_easy > bank.easy_indices.len()
        || n_medium > bank.medium_indices.len()
        || n_hard > bank.hard_indices.len()
    {
        return Err(Error::InvalidInput(
            "not enough questions in bank for the requested ratio".into(),
        ));
    }

    let mut selected: Vec<&QuestionItem> = Vec::with_capacity(num_questions);
    for &i in bank.easy_indices.choose_multiple(rng, n_easy) {
        selected.push(&bank.items[i]);
    }
    for &i in bank.medium_indices.choose_multiple(rng, n_medium) {
        selected.push(&bank.items[i]);
    }
    for &i in bank.hard_indices.choose_multiple(rng, n_hard) {
        selected.push(&bank.items[i]);
    }
    selected.shuffle(rng);
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn sample_item(id: u64, difficulty: Difficulty, num_variants: usize) -> QuestionItem {
        let variants = (0..num_variants)
            .map(|i| QuestionVariant {
                id: i as u64,
                substitutions: HashMap::new(),
                options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                correct_index: 0,
            })
            .collect();

        QuestionItem {
            id,
            difficulty,
            stem: format!("question {}", id),
            variants,
        }
    }

    fn sample_bank() -> QuestionBank {
        let items = vec![
            sample_item(1, Difficulty::Easy, 2),
            sample_item(2, Difficulty::Easy, 2),
            sample_item(3, Difficulty::Easy, 2),
            sample_item(4, Difficulty::Medium, 2),
            sample_item(5, Difficulty::Medium, 2),
            sample_item(6, Difficulty::Medium, 2),
            sample_item(7, Difficulty::Hard, 2),
            sample_item(8, Difficulty::Hard, 2),
            sample_item(9, Difficulty::Hard, 2),
        ];
        QuestionBank::new(items).unwrap()
    }

    #[test]
    fn test_question_bank_new() {
        let bank = sample_bank();
        assert_eq!(bank.len(), 9);
        assert_eq!(bank.easy_indices.len(), 3);
        assert_eq!(bank.medium_indices.len(), 3);
        assert_eq!(bank.hard_indices.len(), 3);
    }

    #[test]
    fn test_question_bank_empty() {
        let err = QuestionBank::new(vec![]).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_question_bank_missing_difficulty() {
        let items = vec![sample_item(1, Difficulty::Easy, 2)];
        let err = QuestionBank::new(items).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_question_bank_no_variants() {
        let items = vec![
            QuestionItem {
                id: 1,
                difficulty: Difficulty::Easy,
                stem: "q".into(),
                variants: vec![],
            },
            sample_item(2, Difficulty::Easy, 2),
            sample_item(3, Difficulty::Easy, 2),
            sample_item(4, Difficulty::Medium, 2),
            sample_item(5, Difficulty::Medium, 2),
            sample_item(6, Difficulty::Medium, 2),
            sample_item(7, Difficulty::Hard, 2),
            sample_item(8, Difficulty::Hard, 2),
            sample_item(9, Difficulty::Hard, 2),
        ];
        let err = QuestionBank::new(items).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_difficulty_ratio_new() {
        let r = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
        assert!((r.easy - 0.3).abs() < 1e-6);
    }

    #[test]
    fn test_difficulty_ratio_invalid_sum() {
        let err = DifficultyRatio::new(0.5, 0.5, 0.5).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_difficulty_ratio_negative() {
        let err = DifficultyRatio::new(-0.1, 0.6, 0.5).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_select_questions_correct_count() {
        let bank = sample_bank();
        let ratio = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
        let mut rng = rand::thread_rng();
        let selected = select_questions(&bank, 6, &ratio, &mut rng).unwrap();
        assert_eq!(selected.len(), 6);
    }

    #[test]
    fn test_select_questions_too_many() {
        let bank = sample_bank();
        let ratio = DifficultyRatio::new(0.5, 0.3, 0.2).unwrap();
        let mut rng = rand::thread_rng();
        let err = select_questions(&bank, 100, &ratio, &mut rng).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_select_questions_deterministic_seed() {
        let bank = sample_bank();
        let ratio = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
        let mut rng1 = rand::rngs::StdRng::seed_from_u64(42);
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(42);
        let s1 = select_questions(&bank, 6, &ratio, &mut rng1).unwrap();
        let s2 = select_questions(&bank, 6, &ratio, &mut rng2).unwrap();
        for (a, b) in s1.iter().zip(s2.iter()) {
            assert_eq!(a.id, b.id);
        }
    }

    #[test]
    fn test_select_questions_all_difficulties_represented() {
        let bank = sample_bank();
        let ratio = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
        let mut rng = rand::thread_rng();
        let selected = select_questions(&bank, 6, &ratio, &mut rng).unwrap();
        let easy_count = selected
            .iter()
            .filter(|i| i.difficulty == Difficulty::Easy)
            .count();
        let medium_count = selected
            .iter()
            .filter(|i| i.difficulty == Difficulty::Medium)
            .count();
        let hard_count = selected
            .iter()
            .filter(|i| i.difficulty == Difficulty::Hard)
            .count();
        assert!(easy_count >= 1);
        assert!(medium_count >= 2);
        assert!(hard_count >= 1);
    }
}
