use unicode_width::UnicodeWidthStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A conservative default for interactive, single-line input.
pub const DEFAULT_MAX_CHARS: usize = 4096;

/// An insertion was rejected without changing the input or its cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextInputError {
    /// Control characters, including CR, LF, NUL, ESC and tabs, are not accepted.
    ControlCharacter,
    /// The insertion would exceed the configured Unicode scalar-value limit.
    LengthLimitExceeded { max_chars: usize },
}

impl std::fmt::Display for TextInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControlCharacter => {
                formatter.write_str("control characters are not allowed in text input")
            }
            Self::LengthLimitExceeded { max_chars } => {
                write!(
                    formatter,
                    "text input exceeds the {max_chars}-character limit"
                )
            }
        }
    }
}

impl std::error::Error for TextInputError {}

/// A single-line editor whose cursor is a Unicode scalar-value (`char`) index.
///
/// The cursor is always between characters in `0..=len_chars()` and is converted
/// to a UTF-8 byte boundary only at the point of mutation. Editing operates on
/// `char`s, not grapheme clusters: a base character and its combining marks are
/// separate editable units, but every mutation preserves valid UTF-8.
///
/// All control characters are rejected atomically on insertion. In particular,
/// pasted terminal escapes, line breaks and NUL bytes are never stored, executed
/// or partially inserted. This type only edits text; it never invokes a command.
pub struct TextInput {
    value: String,
    cursor: usize,
    max_chars: usize,
}

impl Default for TextInput {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CHARS)
    }
}

impl Zeroize for TextInput {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.cursor = 0;
        self.max_chars = 0;
    }
}

impl ZeroizeOnDrop for TextInput {}

impl Clone for TextInput {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            cursor: self.cursor,
            max_chars: self.max_chars,
        }
    }
}

impl std::fmt::Debug for TextInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TextInput")
            .field("len_chars", &self.len_chars())
            .field("cursor", &self.cursor)
            .field("max_chars", &self.max_chars)
            .finish()
    }
}

impl TextInput {
    /// Creates an empty input with a limit measured in Unicode scalar values.
    pub fn new(max_chars: usize) -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            max_chars,
        }
    }

    /// Creates an input containing `value`, with the cursor at the end.
    ///
    /// The same control-character and length checks as [`Self::paste`] apply.
    pub fn with_value(value: &str, max_chars: usize) -> Result<Self, TextInputError> {
        let mut input = Self::new(max_chars);
        input.paste(value)?;
        Ok(input)
    }

    /// Returns the actual value. Use [`Self::masked_value`] for secret display.
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn max_chars(&self) -> usize {
        self.max_chars
    }

    /// Returns the number of Unicode scalar values, not UTF-8 bytes or graphemes.
    pub fn len_chars(&self) -> usize {
        self.value.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns the cursor as a `char` index in `0..=len_chars()`.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Returns the UTF-8 byte boundary corresponding to the cursor.
    pub fn cursor_byte_offset(&self) -> usize {
        self.byte_offset(self.cursor)
    }

    /// Moves to a `char` index. Out-of-range indices leave the cursor unchanged.
    pub fn set_cursor(&mut self, char_index: usize) -> bool {
        if char_index > self.len_chars() {
            return false;
        }
        self.cursor = char_index;
        true
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.len_chars());
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.len_chars();
    }

    /// Inserts one non-control character, returning an error at the length limit.
    pub fn insert_char(&mut self, character: char) -> Result<(), TextInputError> {
        let mut encoded = [0; 4];
        self.paste(character.encode_utf8(&mut encoded))
    }

    /// Pastes text at the cursor and advances past all inserted characters.
    ///
    /// The operation is atomic: any control character or limit overflow rejects
    /// the entire paste without changing the value or cursor. CR, LF, NUL, ESC,
    /// tabs and all other characters for which `char::is_control()` is true are
    /// rejected. This strict policy is shared by ordinary and secret fields.
    pub fn paste(&mut self, text: &str) -> Result<(), TextInputError> {
        if text.chars().any(|character| character.is_control()) {
            return Err(TextInputError::ControlCharacter);
        }

        let inserted_chars = text.chars().count();
        let within_limit = self
            .len_chars()
            .checked_add(inserted_chars)
            .is_some_and(|length| length <= self.max_chars);
        if !within_limit {
            return Err(TextInputError::LengthLimitExceeded {
                max_chars: self.max_chars,
            });
        }

        let offset = self.cursor_byte_offset();
        self.value.insert_str(offset, text);
        self.cursor += inserted_chars;
        Ok(())
    }

    /// Deletes the character immediately before the cursor.
    pub fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let start = self.byte_offset(self.cursor - 1);
        let end = self.cursor_byte_offset();
        self.value.replace_range(start..end, "");
        self.cursor -= 1;
        true
    }

    /// Deletes the character immediately after the cursor.
    pub fn delete(&mut self) -> bool {
        if self.cursor == self.len_chars() {
            return false;
        }
        let start = self.cursor_byte_offset();
        let end = self.byte_offset(self.cursor + 1);
        self.value.replace_range(start..end, "");
        true
    }

    /// Implements Ctrl+U: deletes everything before the cursor.
    pub fn delete_to_start(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let end = self.cursor_byte_offset();
        self.value.replace_range(..end, "");
        self.cursor = 0;
        true
    }

    /// Implements Ctrl+W: deletes preceding whitespace and the preceding word.
    pub fn delete_word_before(&mut self) -> bool {
        let end = self.cursor_byte_offset();
        let new_cursor = self.value[..end]
            .chars()
            .rev()
            .skip_while(|character| character.is_whitespace())
            .skip_while(|character| !character.is_whitespace())
            .count();
        if new_cursor == self.cursor {
            return false;
        }

        let start = self.byte_offset(new_cursor);
        self.value.replace_range(start..end, "");
        self.cursor = new_cursor;
        true
    }

    pub fn clear(&mut self) {
        let max_chars = self.max_chars;
        self.zeroize();
        self.max_chars = max_chars;
    }

    /// Returns a horizontally clipped view and the cursor column inside it.
    /// `mask` replaces every input character without exposing secret contents.
    pub fn window(&self, viewport_cells: usize, mask: Option<char>) -> (String, usize) {
        if viewport_cells == 0 {
            return (String::new(), 0);
        }
        let rendered = mask.map_or_else(|| self.value.clone(), |mask| self.masked_value(mask));
        let mut start = 0;
        while start < self.cursor {
            let start_offset = char_index_to_byte_offset(&rendered, start).unwrap_or(0);
            let cursor_offset = char_index_to_byte_offset(&rendered, self.cursor).unwrap_or(0);
            if display_width(&rendered[start_offset..cursor_offset]) < viewport_cells {
                break;
            }
            start += 1;
        }
        let start_offset = char_index_to_byte_offset(&rendered, start).unwrap_or(0);
        let mut end = start;
        let mut width = 0;
        for (index, character) in rendered[start_offset..].chars().enumerate() {
            let character_width = display_width(&character.to_string());
            if width + character_width > viewport_cells {
                break;
            }
            width += character_width;
            end = start + index + 1;
        }
        let end_offset = char_index_to_byte_offset(&rendered, end).unwrap_or(start_offset);
        let cursor_offset = char_index_to_byte_offset(&rendered, self.cursor)
            .unwrap_or(start_offset)
            .clamp(start_offset, end_offset);
        (
            rendered[start_offset..end_offset].to_string(),
            display_width(&rendered[start_offset..cursor_offset]),
        )
    }

    /// Returns one mask character per input `char`, without exposing the value.
    ///
    /// Use a printable, non-control mask character for terminal rendering.
    pub fn masked_value(&self, mask: char) -> String {
        mask.to_string().repeat(self.len_chars())
    }

    /// Returns the terminal-cell width of the unmasked value.
    pub fn display_width(&self) -> usize {
        display_width(&self.value)
    }

    /// Returns the terminal-cell column of the cursor in the unmasked value.
    pub fn cursor_display_column(&self) -> usize {
        display_width(&self.value[..self.cursor_byte_offset()])
    }

    /// Returns the cursor column when rendering [`Self::masked_value`].
    pub fn masked_cursor_display_column(&self, mask: char) -> usize {
        display_width(&mask.to_string().repeat(self.cursor))
    }

    fn byte_offset(&self, char_index: usize) -> usize {
        char_index_to_byte_offset(&self.value, char_index).unwrap_or(self.value.len())
    }
}

/// Converts a `char` index to a UTF-8 byte offset, returning `None` if the
/// index is greater than the number of characters. The end index is valid.
pub fn char_index_to_byte_offset(value: &str, char_index: usize) -> Option<usize> {
    value
        .char_indices()
        .map(|(offset, _)| offset)
        .chain(std::iter::once(value.len()))
        .nth(char_index)
}

/// Measures terminal cells using the same Unicode width rules as Ratatui.
pub fn display_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_in_the_middle() {
        let mut input = TextInput::with_value("ac", 10).expect("valid initial value");
        input.move_left();
        input.insert_char('b').expect("room for one character");

        assert_eq!(input.value(), "abc");
        assert_eq!(input.cursor(), 2);
        assert_eq!(input.cursor_byte_offset(), 2);
    }

    #[test]
    fn movement_stops_at_both_boundaries() {
        let mut input = TextInput::with_value("ab", 10).expect("valid initial value");
        input.move_left();
        assert_eq!(input.cursor(), 1);
        input.move_left();
        input.move_left();
        assert_eq!(input.cursor(), 0);

        input.move_right();
        assert_eq!(input.cursor(), 1);
        input.move_end();
        input.move_right();
        assert_eq!(input.cursor(), 2);
        input.move_home();
        assert_eq!(input.cursor(), 0);
    }

    #[test]
    fn rejects_only_out_of_range_cursor_positions() {
        let mut input = TextInput::with_value("界🙂", 2).expect("valid initial value");
        assert!(!input.set_cursor(3));
        assert_eq!(input.cursor(), 2);
        assert!(input.set_cursor(1));
        assert_eq!(input.cursor_byte_offset(), 3);
    }

    #[test]
    fn backspace_and_delete_use_character_boundaries() {
        let mut input = TextInput::with_value("a🦀界c", 4).expect("valid initial value");
        assert!(input.set_cursor(2));

        assert!(input.backspace());
        assert_eq!(input.value(), "a界c");
        assert_eq!(input.cursor(), 1);
        assert!(input.delete());
        assert_eq!(input.value(), "ac");
        assert_eq!(input.cursor(), 1);
        assert!(input.delete());
        assert!(!input.delete());
        input.move_home();
        assert!(!input.backspace());
    }

    #[test]
    fn delete_removes_one_leading_quote_from_a_path() {
        let mut input =
            TextInput::with_value(r#""C:\tmp\remxo"#, 128).expect("valid path-shaped test value");
        input.move_home();
        assert!(input.delete());
        assert_eq!(input.value(), r#"C:\tmp\remxo"#);
        assert_eq!(input.cursor(), 0);
    }

    #[test]
    fn unicode_insert_and_deletion_preserve_utf8() {
        let mut input = TextInput::with_value("A界🙂e\u{301}", 7).expect("valid Unicode");
        assert_eq!(input.len_chars(), 5);
        assert_ne!(input.len_chars(), input.value().len());
        assert!(input.set_cursor(2));

        input.paste("中🦀").expect("two characters fit");
        assert_eq!(input.value(), "A界中🦀🙂e\u{301}");
        assert_eq!(input.cursor(), 4);
        assert!(input.backspace());
        assert_eq!(input.value(), "A界中🙂e\u{301}");
        assert!(input.value().is_char_boundary(input.cursor_byte_offset()));
    }

    #[test]
    fn combining_marks_are_separate_safe_editing_units() {
        let mut input = TextInput::with_value("e\u{301}x", 3).expect("valid Unicode");
        input.move_left();
        assert_eq!(input.cursor(), 2);
        assert_eq!(input.cursor_byte_offset(), 3);
        assert_eq!(input.cursor_display_column(), 1);

        assert!(input.backspace());
        assert_eq!(input.value(), "ex");
        assert_eq!(input.cursor(), 1);
        assert_eq!(input.cursor_byte_offset(), 1);
    }

    #[test]
    fn char_index_conversion_accepts_only_real_boundaries() {
        let value = "a界🙂";
        assert_eq!(char_index_to_byte_offset(value, 0), Some(0));
        assert_eq!(char_index_to_byte_offset(value, 1), Some(1));
        assert_eq!(char_index_to_byte_offset(value, 2), Some(4));
        assert_eq!(char_index_to_byte_offset(value, 3), Some(8));
        assert_eq!(char_index_to_byte_offset(value, 4), None);
        assert_eq!(char_index_to_byte_offset("", 0), Some(0));
        assert_eq!(char_index_to_byte_offset("", 1), None);
    }

    #[test]
    fn paste_inserts_at_the_cursor() {
        let mut input = TextInput::with_value("ad", 10).expect("valid initial value");
        input.move_left();
        input.paste("bc").expect("paste fits");
        assert_eq!(input.value(), "abcd");
        assert_eq!(input.cursor(), 3);
    }

    #[test]
    fn paste_rejects_controls_atomically() {
        for pasted in [
            "ab\ncd",
            "ab\r\ncd",
            "ab\0cd",
            "a\u{1b}[2J",
            "a\tb",
            "a\u{7f}b",
        ] {
            let mut input = TextInput::with_value("safe", 32).expect("valid initial value");
            input.set_cursor(2);
            assert_eq!(input.paste(pasted), Err(TextInputError::ControlCharacter));
            assert_eq!(input.value(), "safe");
            assert_eq!(input.cursor(), 2);
        }

        let mut input = TextInput::default();
        assert_eq!(
            input.insert_char('\n'),
            Err(TextInputError::ControlCharacter)
        );
        assert!(input.is_empty());
    }

    #[test]
    fn length_limit_counts_unicode_characters_not_bytes() {
        let mut input = TextInput::new(3);
        input.paste("界🙂").expect("two Unicode characters fit");
        input.insert_char('🦀').expect("third character fits");
        let before = input.value().to_owned();

        assert_eq!(
            input.insert_char('x'),
            Err(TextInputError::LengthLimitExceeded { max_chars: 3 })
        );
        assert_eq!(
            input.paste("abc"),
            Err(TextInputError::LengthLimitExceeded { max_chars: 3 })
        );
        assert_eq!(input.value(), before);
        assert_eq!(input.cursor(), 3);
        assert!(TextInput::with_value("界🙂", 1).is_err());
    }

    #[test]
    fn empty_paste_is_allowed_at_zero_limit() {
        let mut input = TextInput::new(0);
        input
            .paste("")
            .expect("empty paste does not grow the value");
        assert_eq!(
            input.insert_char('a'),
            Err(TextInputError::LengthLimitExceeded { max_chars: 0 })
        );
        assert!(input.is_empty());
    }

    #[test]
    fn ctrl_u_and_ctrl_w_delete_the_expected_ranges() {
        let mut input = TextInput::with_value("one two  ", 32).expect("valid initial value");
        assert!(input.delete_word_before());
        assert_eq!(input.value(), "one ");
        assert_eq!(input.cursor(), 4);
        assert!(input.delete_word_before());
        assert!(input.is_empty());
        assert!(!input.delete_word_before());

        input.paste("ab界cd").expect("new value fits");
        assert!(input.set_cursor(3));
        assert!(input.delete_to_start());
        assert_eq!(input.value(), "cd");
        assert_eq!(input.cursor(), 0);
        assert!(!input.delete_to_start());
    }

    #[test]
    fn clear_resets_value_and_cursor() {
        let mut input = TextInput::with_value("secret", 16).expect("valid initial value");
        input.move_left();
        input.clear();
        assert!(input.is_empty());
        assert_eq!(input.cursor(), 0);
    }

    #[test]
    fn display_helpers_count_terminal_cells_not_chars_or_bytes() {
        assert_eq!(display_width("ab界🙂"), 6);
        assert_eq!(display_width("e\u{301}"), 1);

        let mut input = TextInput::with_value("a界🙂b", 4).expect("valid Unicode");
        assert!(input.set_cursor(2));
        assert_eq!(input.display_width(), 6);
        assert_eq!(input.cursor_display_column(), 3);
        input.move_right();
        assert_eq!(input.cursor_display_column(), 5);
    }

    #[test]
    fn masked_window_keeps_long_paths_and_secret_cursors_visible() {
        let mut input = TextInput::with_value("0123456789", 32).expect("valid path");
        let (window, cursor) = input.window(4, None);
        assert_eq!(window, "789");
        assert_eq!(cursor, 3);
        input.move_home();
        let (window, cursor) = input.window(4, None);
        assert_eq!(window, "0123");
        assert_eq!(cursor, 0);

        let input = TextInput::with_value("test-only-secret", 32).expect("valid secret");
        let (window, cursor) = input.window(5, Some('*'));
        assert_eq!(window, "****");
        assert_eq!(cursor, 4);
        assert!(!window.contains("test-only-secret"));
        assert_eq!(input.window(0, Some('*')), (String::new(), 0));
    }

    #[test]
    fn masked_view_and_debug_output_do_not_expose_the_secret() {
        let secret = "s3cr3t-界-🙂";
        let mut input = TextInput::with_value(secret, 32).expect("valid secret");
        input.move_left();

        let masked = input.masked_value('•');
        assert_eq!(masked, "•".repeat(input.len_chars()));
        assert_eq!(input.masked_cursor_display_column('＊'), 2 * input.cursor());
        assert_eq!(
            input.masked_cursor_display_column('•'),
            display_width(&"•".repeat(input.cursor()))
        );
        for rendering in [masked, input.masked_value('*'), format!("{input:?}")] {
            assert!(!rendering.contains("s3cr3t"));
            assert!(!rendering.contains('界'));
            assert!(!rendering.contains('🙂'));
        }
    }
}
