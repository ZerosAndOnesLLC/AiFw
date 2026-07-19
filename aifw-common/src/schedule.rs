//! Schedule window evaluation (#537). Pure time logic the rule engine uses
//! to decide whether a rule referencing a schedule is inside its active
//! window. Persistence lives in `aifw-core::db`; HTTP CRUD and storage-format
//! validation live in `aifw-api` (`routes::schedules`).
//!
//! Evaluation runs against the appliance's **local time** (callers pass
//! `Local::now().naive_local()`), so windows follow the configured system
//! timezone including DST shifts.

use chrono::{Datelike, NaiveDateTime, Timelike, Weekday};
use std::collections::HashMap;

/// A parsed schedule: a day-of-week set plus minute-of-day ranges.
///
/// Storage format (from the `schedules` table):
/// - `time_ranges`: `"08:00-17:00"` or comma-separated `"08:00-12:00,13:00-17:00"`
/// - `days_of_week`: `"mon,tue,wed,thu,fri"`
///
/// Range semantics:
/// - `start < end` — active on a listed day within `[start, end)`
/// - `start > end` — overnight window: `[start, midnight)` on a listed day,
///   continuing through `[midnight, end)` of the following day (the day check
///   applies to the day the window *started*)
/// - `start == end` — full-day window on listed days
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleSpec {
    /// A disabled schedule never constrains a rule (rule behaves unscheduled)
    pub enabled: bool,
    /// Active days, indexed by `Weekday::num_days_from_monday()`
    days: [bool; 7],
    /// Minute-of-day ranges
    ranges: Vec<(u16, u16)>,
}

impl ScheduleSpec {
    /// Parse the stored representation. Returns `None` if either field is
    /// malformed (callers treat unparseable schedules as non-constraining
    /// and log, mirroring the dangling-reference case).
    pub fn parse(time_ranges: &str, days_of_week: &str, enabled: bool) -> Option<Self> {
        let mut days = [false; 7];
        for d in days_of_week.split(',') {
            let idx = match d.trim() {
                "mon" => 0,
                "tue" => 1,
                "wed" => 2,
                "thu" => 3,
                "fri" => 4,
                "sat" => 5,
                "sun" => 6,
                "" => continue,
                _ => return None,
            };
            days[idx] = true;
        }
        let mut ranges = Vec::new();
        for range in time_ranges.split(',') {
            let range = range.trim();
            if range.is_empty() {
                continue;
            }
            let (start, end) = range.split_once('-')?;
            ranges.push((parse_minute(start)?, parse_minute(end)?));
        }
        Some(Self {
            enabled,
            days,
            ranges,
        })
    }

    fn day_on(&self, day: Weekday) -> bool {
        self.days[day.num_days_from_monday() as usize]
    }

    /// Whether the schedule's window covers the given local time
    pub fn is_active_at(&self, now: NaiveDateTime) -> bool {
        let day = now.weekday();
        let minute = (now.hour() * 60 + now.minute()) as u16;
        for &(start, end) in &self.ranges {
            let active = if start < end {
                self.day_on(day) && minute >= start && minute < end
            } else if start > end {
                // Overnight wrap: the pre-midnight half belongs to the listed
                // day; the post-midnight half to the day after it.
                (self.day_on(day) && minute >= start) || (self.day_on(day.pred()) && minute < end)
            } else {
                self.day_on(day)
            };
            if active {
                return true;
            }
        }
        false
    }
}

fn parse_minute(hm: &str) -> Option<u16> {
    let (h, m) = hm.trim().split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Whether a rule with the given optional schedule reference is currently
/// inside its active window.
///
/// Missing or unparseable schedule references **fail open** (rule stays
/// loaded, identical to an unscheduled rule): rules can be `block` as well as
/// `pass`, so silently unloading on a dangling reference could open the
/// firewall rather than close it. Callers log dangling references.
pub fn rule_schedule_active(
    schedule_id: Option<&str>,
    schedules: &HashMap<String, ScheduleSpec>,
    now: NaiveDateTime,
) -> bool {
    match schedule_id {
        None => true,
        Some(id) => match schedules.get(id) {
            None => true,
            Some(s) if !s.enabled => true,
            Some(s) => s.is_active_at(now),
        },
    }
}
