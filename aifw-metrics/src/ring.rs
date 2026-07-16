use serde::{Deserialize, Serialize};

/// A fixed-size circular buffer that overwrites oldest entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingBuffer<T: Clone> {
    data: Vec<Option<T>>,
    capacity: usize,
    head: usize,
    count: usize,
}

impl<T: Clone> RingBuffer<T> {
    /// Create an empty buffer holding at most `capacity` entries.
    /// `capacity` must be non-zero — a zero-capacity buffer panics on `push`.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![None; capacity],
            capacity,
            head: 0,
            count: 0,
        }
    }

    /// Append a value, overwriting the oldest entry once the buffer is full
    pub fn push(&mut self, value: T) {
        self.data[self.head] = Some(value);
        self.head = (self.head + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    /// Get all values in chronological order (oldest first)
    pub fn values(&self) -> Vec<&T> {
        let mut result = Vec::with_capacity(self.count);
        if self.count == 0 {
            return result;
        }

        let start = if self.count < self.capacity {
            0
        } else {
            self.head
        };

        for i in 0..self.count {
            let idx = (start + i) % self.capacity;
            if let Some(ref val) = self.data[idx] {
                result.push(val);
            }
        }
        result
    }

    /// Get the last N values in chronological order
    pub fn last_n(&self, n: usize) -> Vec<&T> {
        let vals = self.values();
        let skip = vals.len().saturating_sub(n);
        vals.into_iter().skip(skip).collect()
    }

    /// Get the most recent value
    pub fn latest(&self) -> Option<&T> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            self.capacity - 1
        } else {
            self.head - 1
        };
        self.data[idx].as_ref()
    }

    /// Number of values currently stored (at most `capacity`)
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the buffer holds no values
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Maximum number of values the buffer can hold
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Remove all values, keeping the capacity
    pub fn clear(&mut self) {
        self.data = vec![None; self.capacity];
        self.head = 0;
        self.count = 0;
    }
}
