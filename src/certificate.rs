use serde::{Deserialize, Serialize};

use crate::crypto::sha256;
use crate::encoding::{Encoder, TAG_CERTIFICATE};
use crate::types::{Digest, Salt};
use crate::{Error, Result};

/// Off-chain document; only its hash goes into the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub id: String,
    #[serde(rename = "estudiante")]
    pub student: String,
    #[serde(rename = "carrera")]
    pub program: String,
    /// Unix seconds, UTC.
    #[serde(rename = "fecha")]
    pub date: u64,
    #[serde(rename = "detalle")]
    pub courses: Vec<Course>,
    pub salt: Salt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Course {
    #[serde(rename = "ramo")]
    pub name: String,
    /// Tenths: 50 means 5.0.
    #[serde(rename = "nota")]
    pub grade: u8,
}

impl Certificate {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(TAG_CERTIFICATE)
            .bytes(self.id.as_bytes())
            .bytes(self.student.as_bytes())
            .bytes(self.program.as_bytes())
            .u64(self.date)
            .u32(u32::try_from(self.courses.len()).expect("too many courses"));
        for course in &self.courses {
            encoder = encoder.bytes(course.name.as_bytes()).u8(course.grade);
        }
        encoder.fixed(&self.salt.0).finish()
    }

    pub fn hash(&self) -> Digest {
        sha256(&self.canonical_bytes())
    }

    /// Checks grade range and required fields.
    pub fn validate(&self) -> Result<()> {
        let required = [
            ("id", &self.id),
            ("estudiante", &self.student),
            ("carrera", &self.program),
        ];
        for (field, value) in required {
            if value.trim().is_empty() {
                return Err(Error::Invalid(format!("falta el campo {field}")));
            }
        }
        if self.courses.is_empty() {
            return Err(Error::Invalid("el detalle no tiene ramos".into()));
        }
        for course in &self.courses {
            if course.name.trim().is_empty() {
                return Err(Error::Invalid("hay un ramo sin nombre".into()));
            }
            if !(MIN_GRADE..=MAX_GRADE).contains(&course.grade) {
                return Err(Error::Invalid(format!(
                    "nota {} fuera de rango en {} (debe estar entre {MIN_GRADE} y {MAX_GRADE})",
                    course.grade, course.name
                )));
            }
        }
        Ok(())
    }
}

/// Grades in tenths: 1.0 to 7.0.
pub const MIN_GRADE: u8 = 10;
pub const MAX_GRADE: u8 = 70;

pub fn generate_salt() -> Result<Salt> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(Salt(salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Certificate {
        Certificate {
            id: "CERT-001".into(),
            student: "Ana".into(),
            program: "Ingeniería Civil Telemática".into(),
            date: 1_700_000_000,
            courses: vec![
                Course {
                    name: "Criptografía".into(),
                    grade: 65,
                },
                Course {
                    name: "Redes".into(),
                    grade: 50,
                },
            ],
            salt: Salt([7; 32]),
        }
    }

    #[test]
    fn json_formatting_does_not_change_hash() {
        let salt = "07".repeat(32);
        let compact = format!(
            r#"{{"id":"CERT-001","estudiante":"Ana","carrera":"Ingeniería Civil Telemática","fecha":1700000000,"detalle":[{{"ramo":"Criptografía","nota":65}},{{"ramo":"Redes","nota":50}}],"salt":"{salt}"}}"#
        );
        let reordered = format!(
            r#"{{
                "salt": "{salt}",
                "detalle": [ {{ "nota": 65, "ramo": "Criptografía" }}, {{ "nota": 50, "ramo": "Redes" }} ],
                "fecha": 1700000000,
                "carrera": "Ingeniería Civil Telemática",
                "estudiante": "Ana",
                "id": "CERT-001"
            }}"#
        );
        let a: Certificate = serde_json::from_str(&compact).unwrap();
        let b: Certificate = serde_json::from_str(&reordered).unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.hash(), sample().hash());
    }

    #[test]
    fn any_change_changes_hash() {
        let base = sample().hash();
        let mut cert = sample();
        cert.courses[0].grade = 66;
        assert_ne!(cert.hash(), base);
        let mut cert = sample();
        cert.salt = Salt([8; 32]);
        assert_ne!(cert.hash(), base);
        let mut cert = sample();
        cert.courses.swap(0, 1);
        assert_ne!(cert.hash(), base);
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["honores"] = true.into();
        assert!(serde_json::from_value::<Certificate>(json).is_err());
    }

    #[test]
    fn grade_range() {
        for (grade, ok) in [(9, false), (10, true), (70, true), (71, false)] {
            let mut cert = sample();
            cert.courses[0].grade = grade;
            assert_eq!(cert.validate().is_ok(), ok, "nota {grade}");
        }
    }

    #[test]
    fn rejects_missing_fields() {
        let mut cert = sample();
        cert.student = "  ".into();
        assert!(cert.validate().is_err());
        let mut cert = sample();
        cert.courses.clear();
        assert!(cert.validate().is_err());
        let mut cert = sample();
        cert.courses[1].name = String::new();
        assert!(cert.validate().is_err());
    }

    #[test]
    fn salts_are_random() {
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
    }
}
