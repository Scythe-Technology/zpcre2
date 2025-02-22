const std = @import("std");

extern fn pcre2_match_data_free_8(match_data: *pcre2_match_data) callconv(.C) void;
extern fn pcre2_get_ovector_pointer_8(match_data: *pcre2_match_data) callconv(.C) [*]isize;
extern fn pcre2_get_ovector_count_8(match_data: *pcre2_match_data) callconv(.C) u32;
extern fn pcre2_match_data_create_from_pattern_8(
    code: *const pcre2_code,
    gcontext: ?*pcre2_general_context,
) callconv(.C) ?*pcre2_match_data;
extern fn pcre2_match_8(
    code: *const pcre2_code,
    subject: [*]const u8,
    len: usize,
    offset: usize,
    options: u32,
    match_data: *pcre2_match_data,
    mcontext: ?*pcre2_match_context,
) callconv(.C) c_int;
extern fn pcre2_compile_8(
    pattern: [*]const u8,
    len: usize,
    options: u32,
    errorcode: *c_int,
    erroroffset: *usize,
    context: ?*pcre2_compile_context,
) callconv(.C) ?*pcre2_code;
extern fn pcre2_substitute_8(
    code: *const pcre2_code,
    subject: [*]const u8,
    len: usize,
    start_offset: usize,
    options: u32,
    match_data: ?*pcre2_match_data,
    mcontext: ?*pcre2_match_context,
    replacement: [*]const u8,
    replace_len: usize,
    buffer: [*]u8,
    buffer_len: *usize,
) callconv(.C) c_int;
extern fn pcre2_pattern_info_8(
    code: *const pcre2_code,
    what: u32,
    where: *anyopaque,
) callconv(.C) c_int;
extern fn pcre2_code_free_8(code: *pcre2_code) callconv(.C) void;
extern fn pcre2_get_error_message_8(errorcode: c_int, buffer: [*]u8, bufflen: usize) callconv(.C) c_int;

pub const pcre2_general_context = opaque {};
pub const pcre2_match_data = opaque {
    pub const deinit = pcre2_match_data_free_8;
};
pub const pcre2_compile_context = opaque {};
pub const pcre2_match_context = opaque {};

pub const pcre2_memctl = extern struct {
    malloc: *const fn (usize, *anyopaque) callconv(.c) *anyopaque,
    free: *const fn (*anyopaque, *anyopaque) callconv(.c) void,
    memory_data: *anyopaque,
};

pub const pcre2_code = extern struct {
    /// Memory control fields
    memctl: pcre2_memctl,
    /// The character tables
    tables: [*]const u8,
    /// Pointer to JIT code
    executable_jit: *anyopaque,
    /// Bitmap for starting code unit < 256
    start_bitmap: [32]u8,
    /// Total (bytes) that was malloc-ed
    blocksize: usize,
    /// Byte code start offset
    code_start: usize,
    /// Paranoid and endianness check
    magic_number: u32,
    /// Options passed to pcre2_compile()
    compile_options: u32,
    /// Options after processing the pattern
    overall_options: u32,
    /// Taken from compile_context
    extra_options: u32,
    /// Various state flags
    flags: u32,
    /// Limit set in the pattern
    limit_heap: u32,
    /// Limit set in the pattern
    limit_match: u32,
    /// Limit set in the pattern
    limit_depth: u32,
    /// Starting code unit
    first_codeunit: u32,
    /// This codeunit must be seen
    last_codeunit: u32,
    /// What \R matches
    bsr_convention: u16,
    /// What is a newline?
    newline_convention: u16,
    /// Longest lookbehind (characters)
    max_lookbehind: u16,
    /// Minimum length of match
    minlength: u16,
    /// Highest numbered group
    top_bracket: u16,
    /// Highest numbered back reference
    top_backref: u16,
    /// Size (code units) of table entries
    name_entry_size: u16,
    /// Number of name entries in the table
    name_count: u16,
    /// Optimizations enabled at compile time
    optimization_flags: u32,

    fn createMatchData(self: *const pcre2_code, gcontext: ?*pcre2_general_context) !*pcre2_match_data {
        return pcre2_match_data_create_from_pattern_8(self, gcontext) orelse return error.OutOfMemory;
    }

    fn checkUTF(self: *const pcre2_code, subject: []const u8) !void {
        if (self.compile_options & Options.PCRE2_UTF != 0)
            if (!std.unicode.utf8ValidateSlice(subject))
                return error.InvalidUtf8;
    }

    pub fn isMatch(
        code: *const pcre2_code,
        subject: []const u8,
    ) !bool {
        try code.checkUTF(subject);
        const match_data = try createMatchData(code, null);
        defer match_data.deinit();
        const rc = pcre2_match_8(code, subject.ptr, subject.len, 0, Options.PCRE2_ANCHORED | Options.PCRE2_ENDANCHORED, match_data, null);
        if (rc < 0) {
            const err: MatchingError = @enumFromInt(rc);
            if (err == .NOMATCH)
                return false;
            return err.toError();
        }
        return true;
    }

    fn inner_match(
        code: *const pcre2_code,
        match_data: *pcre2_match_data,
        allocator: std.mem.Allocator,
        subject: []const u8,
        offset: usize,
        options: u32,
    ) !?Result {
        const rc = pcre2_match_8(code, subject.ptr, subject.len, offset, options, match_data, null);
        if (rc < 0) {
            const err: MatchingError = @enumFromInt(rc);
            if (err == .NOMATCH)
                return null;
            return err.toError();
        }
        if (rc == 0) {
            return error.StringCapturesTooLarge;
        }
        const count: usize = @intCast(rc);
        const ovector = pcre2_get_ovector_pointer_8(match_data);

        const captures = try allocator.alloc(?Result.Capture, count);

        for (0..count) |i| {
            const start = ovector[2 * i];
            const end = ovector[(2 * i) + 1];
            if (start < 0 or end < 0) {
                captures[i] = null;
                continue;
            }
            captures[i] = .{
                .index = @intCast(start),
                .slice = subject[@intCast(start)..@intCast(end)],
            };
        }

        var namecount: u32 = 0;
        _ = pcre2_pattern_info_8(code, Info.NameCount, @ptrCast(@alignCast(&namecount)));

        if (namecount > 0) {
            var nametable: [*]const u8 = undefined;
            var nameentrysize: u32 = 0;
            _ = pcre2_pattern_info_8(code, Info.NameTable, @ptrCast(@alignCast(&nametable)));
            _ = pcre2_pattern_info_8(code, Info.NameEntrySize, @ptrCast(@alignCast(&nameentrysize)));
            for (0..namecount) |_| {
                defer nametable = nametable[@intCast(nameentrysize)..];
                const index: usize = (@as(usize, @intCast(nametable[0])) << 8) | nametable[1];
                if (index >= count)
                    continue;
                const name = nametable[2..@intCast(nameentrysize - 3)];
                const capture = &(captures[index] orelse continue);
                capture.name = try allocator.dupe(u8, name);
            }
        }

        return .{
            .captures = captures,
        };
    }

    pub fn matchOnce(
        code: *const pcre2_code,
        allocator: std.mem.Allocator,
        subject: []const u8,
        options: u32,
    ) !?Result {
        try code.checkUTF(subject);
        const match_data = try createMatchData(code, null);
        defer match_data.deinit();
        return code.inner_match(match_data, allocator, subject, 0, options);
    }

    pub fn match(
        code: *const pcre2_code,
        allocator: std.mem.Allocator,
        subject: []const u8,
    ) !?Result {
        return matchOnce(code, allocator, subject, Options.PCRE2_ANCHORED | Options.PCRE2_ENDANCHORED);
    }

    pub fn search(
        code: *const pcre2_code,
        allocator: std.mem.Allocator,
        subject: []const u8,
    ) !?Result {
        return matchOnce(code, allocator, subject, 0);
    }

    pub fn newIterator(
        code: *const pcre2_code,
        subject: []const u8,
        options: u32,
    ) !Iterator {
        try code.checkUTF(subject);
        const match_data = try createMatchData(code, null);

        return .{
            .code = code,
            .match_data = match_data,
            .subject = subject,
            .offset = 0,
            .options = options,
        };
    }

    pub fn matchIterator(
        code: *const pcre2_code,
        subject: []const u8,
    ) !Iterator {
        return newIterator(code, subject, Options.PCRE2_ANCHORED | Options.PCRE2_ENDANCHORED);
    }

    pub fn searchIterator(
        code: *const pcre2_code,
        subject: []const u8,
    ) !Iterator {
        return newIterator(code, subject, 0);
    }

    const Result = struct {
        captures: []?Capture,
        pub const Capture = struct {
            index: usize,
            slice: []const u8,
            name: ?[]const u8 = null,
        };
        pub fn free(self: Result, allocator: std.mem.Allocator) void {
            for (self.captures) |capture|
                if (capture) |c| {
                    if (c.name) |n|
                        allocator.free(n);
                };
            allocator.free(self.captures);
        }
    };

    pub const Iterator = struct {
        code: *const pcre2_code,
        subject: []const u8,
        offset: usize,
        match_data: *pcre2_match_data,
        options: u32,

        pub fn next(self: *Iterator, allocator: std.mem.Allocator) !?Result {
            if (self.offset >= self.subject.len)
                return null;

            return self.code.inner_match(self.match_data, allocator, self.subject, self.offset, self.options);
        }

        pub fn free(it: *Iterator) void {
            it.match_data.deinit();
        }
    };

    pub fn subsitute(
        code: *const pcre2_code,
        allocator: std.mem.Allocator,
        subject: []const u8,
        replacement: []const u8,
        options: u32,
    ) ![]u8 {
        try code.checkUTF(subject);
        try code.checkUTF(replacement);
        const match_data = try createMatchData(code, null);
        defer match_data.deinit();

        var buffer: [4096]u8 = undefined;
        const in_options = options | Options.PCRE2_SUBSTITUTE_OVERFLOW_LENGTH;

        var out_len: usize = buffer.len;
        const rc = pcre2_substitute_8(
            code,
            subject.ptr,
            subject.len,
            0,
            in_options,
            match_data,
            null,
            replacement.ptr,
            replacement.len,
            &buffer,
            &out_len,
        );
        if (rc < 0) {
            const err: MatchingError = @enumFromInt(rc);
            if (err != .NOMEMORY)
                return err.toError();
            const buf = try allocator.alloc(u8, out_len);
            const rc2 = pcre2_substitute_8(
                code,
                subject.ptr,
                subject.len,
                0,
                in_options,
                match_data,
                null,
                replacement.ptr,
                replacement.len,
                buf.ptr,
                &out_len,
            );
            if (rc2 < 0) {
                const err2: MatchingError = @enumFromInt(rc);
                return err2.toError();
            }
            return buf[0..out_len];
        }

        return allocator.dupe(u8, buffer[0..out_len]);
    }

    pub fn allocReplace(code: *const pcre2_code, allocator: std.mem.Allocator, subject: []const u8, replacement: []const u8) ![]u8 {
        return code.subsitute(allocator, subject, replacement, Options.PCRE2_SUBSTITUTE_EXTENDED);
    }

    pub fn allocReplaceAll(code: *const pcre2_code, allocator: std.mem.Allocator, subject: []const u8, replacement: []const u8) ![]u8 {
        return code.subsitute(allocator, subject, replacement, Options.PCRE2_SUBSTITUTE_EXTENDED | Options.PCRE2_SUBSTITUTE_GLOBAL);
    }

    pub fn allocFormat(code: *const pcre2_code, allocator: std.mem.Allocator, subject: []const u8, replacement: []const u8) ![]u8 {
        return code.subsitute(allocator, subject, replacement, Options.PCRE2_SUBSTITUTE_EXTENDED | Options.PCRE2_SUBSTITUTE_REPLACEMENT_ONLY | Options.PCRE2_SUBSTITUTE_GLOBAL);
    }

    pub const deinit = pcre2_code_free_8;
};

pub fn compile(pattern: []const u8, options: u32, offset: *usize) !*pcre2_code {
    var errorcode: c_int = 0;
    return pcre2_compile_8(pattern.ptr, pattern.len, options, &errorcode, offset, null) orelse {
        const err: CompileError = @enumFromInt(errorcode);
        return err.toError();
    };
}

pub const Options = struct {
    pub const PCRE2_ANCHORED = 0x80000000;
    pub const PCRE2_NO_UTF_CHECK = 0x40000000;
    pub const PCRE2_ENDANCHORED = 0x20000000;
    pub const PCRE2_ALLOW_EMPTY_CLASS = 0x00000001;
    pub const PCRE2_ALT_BSUX = 0x00000002;
    pub const PCRE2_AUTO_CALLOUT = 0x00000004;
    pub const PCRE2_CASELESS = 0x00000008;
    pub const PCRE2_DOLLAR_ENDONLY = 0x00000010;
    pub const PCRE2_DOTALL = 0x00000020;
    pub const PCRE2_DUPNAMES = 0x00000040;
    pub const PCRE2_EXTENDED = 0x00000080;
    pub const PCRE2_FIRSTLINE = 0x00000100;
    pub const PCRE2_MATCH_UNSET_BACKREF = 0x00000200;
    pub const PCRE2_MULTILINE = 0x00000400;
    pub const PCRE2_NEVER_UCP = 0x00000800;
    pub const PCRE2_NEVER_UTF = 0x00001000;
    pub const PCRE2_NO_AUTO_CAPTURE = 0x00002000;
    pub const PCRE2_NO_AUTO_POSSESS = 0x00004000;
    pub const PCRE2_NO_DOTSTAR_ANCHOR = 0x00008000;
    pub const PCRE2_NO_START_OPTIMIZE = 0x00010000;
    pub const PCRE2_UCP = 0x00020000;
    pub const PCRE2_UNGREEDY = 0x00040000;
    pub const PCRE2_UTF = 0x00080000;
    pub const PCRE2_NEVER_BACKSLASH_C = 0x00100000;
    pub const PCRE2_ALT_CIRCUMFLEX = 0x00200000;
    pub const PCRE2_ALT_VERBNAMES = 0x00400000;
    pub const PCRE2_USE_OFFSET_LIMIT = 0x00800000;
    pub const PCRE2_EXTENDED_MORE = 0x01000000;
    pub const PCRE2_LITERAL = 0x02000000;
    pub const PCRE2_MATCH_INVALID_UTF = 0x04000000;
    pub const PCRE2_ALT_EXTENDED_CLASS = 0x08000000;

    pub const PCRE2_NOTBOL = 0x00000001;
    pub const PCRE2_NOTEOL = 0x00000002;
    pub const PCRE2_NOTEMPTY = 0x00000004;
    pub const PCRE2_NOTEMPTY_ATSTART = 0x00000008;
    pub const PCRE2_PARTIAL_SOFT = 0x00000010;
    pub const PCRE2_PARTIAL_HARD = 0x00000020;
    pub const PCRE2_DFA_RESTART = 0x00000040;
    pub const PCRE2_DFA_SHORTEST = 0x00000080;
    pub const PCRE2_SUBSTITUTE_GLOBAL = 0x00000100;
    pub const PCRE2_SUBSTITUTE_EXTENDED = 0x00000200;
    pub const PCRE2_SUBSTITUTE_UNSET_EMPTY = 0x00000400;
    pub const PCRE2_SUBSTITUTE_UNKNOWN_UNSET = 0x00000800;
    pub const PCRE2_SUBSTITUTE_OVERFLOW_LENGTH = 0x00001000;
    pub const PCRE2_NO_JIT = 0x00002000;
    pub const PCRE2_COPY_MATCHED_SUBJECT = 0x00004000;
    pub const PCRE2_SUBSTITUTE_LITERAL = 0x00008000;
    pub const PCRE2_SUBSTITUTE_MATCHED = 0x00010000;
    pub const PCRE2_SUBSTITUTE_REPLACEMENT_ONLY = 0x00020000;
    pub const PCRE2_DISABLE_RECURSELOOP_CHECK = 0x00040000;
};

pub const Info = struct {
    /// Final options after compiling
    pub const AllOptions = 0;
    /// Options passed to pcre2_compile()
    pub const ArgOptions = 1;
    /// Number of highest backreference
    pub const BackrefMax = 2;
    /// What \R matches:
    ///  - PCRE2_BSR_UNICODE: Unicode line endings
    ///  - PCRE2_BSR_ANYCRLF: CR, LF, or CRLF only
    pub const BSR = 3;
    /// Number of capturing subpatterns
    pub const CaptureCount = 4;
    /// First code unit when type is 1
    pub const FirstCodeUnit = 5;
    // Type of start-of-match information
    //  - 0 nothing set
    //  - 1 first code unit is set
    //  - 2 start of string or after newline
    pub const FirstCodeType = 6;
    /// Bitmap of first code units, or NULL
    pub const FirstBitMap = 7;
    pub const HasCRLF = 8;
    pub const JChanged = 9;
    pub const JITSize = 10;
    pub const LastCodeUnit = 11;
    pub const LastCodeType = 12;
    pub const MatchEmpty = 13;
    pub const MatchLimit = 14;
    pub const MaxLookbehind = 15;
    pub const MinLength = 16;
    /// Number of named subpatterns
    pub const NameCount = 17;
    /// Size of name table entries
    pub const NameEntrySize = 18;
    /// Pointer to name table
    pub const NameTable = 19;
    pub const Newline = 20;
    ///  Backtracking depth limit if set, otherwise PCRE2_ERROR_UNSET
    pub const DepthLimit = 21;
    pub const RecursionLimit = 21;
    /// Size of compiled pattern
    pub const Size = 22;
    pub const HasBackslashC = 23;
    /// Size of backtracking frame
    pub const FrameSize = 24;
    pub const HeapLimit = 25;
    /// Extra options that were passed in the
    /// - compile context
    pub const ExtraOptions = 26;
};

pub const CompileError = enum(c_int) {
    END_BACKSLASH = 101,
    END_BACKSLASH_C = 102,
    UNKNOWN_ESCAPE = 103,
    QUANTIFIER_OUT_OF_ORDER = 104,
    QUANTIFIER_TOO_BIG = 105,
    MISSING_SQUARE_BRACKET = 106,
    ESCAPE_INVALID_IN_CLASS = 107,
    CLASS_RANGE_ORDER = 108,
    QUANTIFIER_INVALID = 109,
    INTERNAL_UNEXPECTED_REPEAT = 110,
    INVALID_AFTER_PARENS_QUERY = 111,
    POSIX_CLASS_NOT_IN_CLASS = 112,
    POSIX_NO_SUPPORT_COLLATING = 113,
    MISSING_CLOSING_PARENTHESIS = 114,
    BAD_SUBPATTERN_REFERENCE = 115,
    NULL_PATTERN = 116,
    BAD_OPTIONS = 117,
    MISSING_COMMENT_CLOSING = 118,
    PARENTHESES_NEST_TOO_DEEP = 119,
    PATTERN_TOO_LARGE = 120,
    HEAP_FAILED = 121,
    UNMATCHED_CLOSING_PARENTHESIS = 122,
    INTERNAL_CODE_OVERFLOW = 123,
    MISSING_CONDITION_CLOSING = 124,
    LOOKBEHIND_NOT_FIXED_LENGTH = 125,
    ZERO_RELATIVE_REFERENCE = 126,
    TOO_MANY_CONDITION_BRANCHES = 127,
    CONDITION_ASSERTION_EXPECTED = 128,
    BAD_RELATIVE_REFERENCE = 129,
    UNKNOWN_POSIX_CLASS = 130,
    INTERNAL_STUDY_ERROR = 131,
    UNICODE_NOT_SUPPORTED = 132,
    PARENTHESES_STACK_CHECK = 133,
    CODE_POINT_TOO_BIG = 134,
    LOOKBEHIND_TOO_COMPLICATED = 135,
    LOOKBEHIND_INVALID_BACKSLASH_C = 136,
    UNSUPPORTED_ESCAPE_SEQUENCE = 137,
    CALLOUT_NUMBER_TOO_BIG = 138,
    MISSING_CALLOUT_CLOSING = 139,
    ESCAPE_INVALID_IN_VERB = 140,
    UNRECOGNIZED_AFTER_QUERY_P = 141,
    MISSING_NAME_TERMINATOR = 142,
    DUPLICATE_SUBPATTERN_NAME = 143,
    INVALID_SUBPATTERN_NAME = 144,
    UNICODE_PROPERTIES_UNAVAILABLE = 145,
    MALFORMED_UNICODE_PROPERTY = 146,
    UNKNOWN_UNICODE_PROPERTY = 147,
    SUBPATTERN_NAME_TOO_LONG = 148,
    TOO_MANY_NAMED_SUBPATTERNS = 149,
    CLASS_INVALID_RANGE = 150,
    OCTAL_BYTE_TOO_BIG = 151,
    INTERNAL_OVERRAN_WORKSPACE = 152,
    INTERNAL_MISSING_SUBPATTERN = 153,
    DEFINE_TOO_MANY_BRANCHES = 154,
    BACKSLASH_O_MISSING_BRACE = 155,
    INTERNAL_UNKNOWN_NEWLINE = 156,
    BACKSLASH_G_SYNTAX = 157,
    PARENS_QUERY_R_MISSING_CLOSING = 158,
    VERB_ARGUMENT_NOT_ALLOWED = 159,
    VERB_UNKNOWN = 160,
    SUBPATTERN_NUMBER_TOO_BIG = 161,
    SUBPATTERN_NAME_EXPECTED = 162,
    INTERNAL_PARSED_OVERFLOW = 163,
    INVALID_OCTAL = 164,
    SUBPATTERN_NAMES_MISMATCH = 165,
    MARK_MISSING_ARGUMENT = 166,
    INVALID_HEXADECIMAL = 167,
    BACKSLASH_C_SYNTAX = 168,
    BACKSLASH_K_SYNTAX = 169,
    INTERNAL_BAD_CODE_LOOKBEHINDS = 170,
    BACKSLASH_N_IN_CLASS = 171,
    CALLOUT_STRING_TOO_LONG = 172,
    UNICODE_DISALLOWED_CODE_POINT = 173,
    UTF_IS_DISABLED = 174,
    UCP_IS_DISABLED = 175,
    VERB_NAME_TOO_LONG = 176,
    BACKSLASH_U_CODE_POINT_TOO_BIG = 177,
    MISSING_OCTAL_OR_HEX_DIGITS = 178,
    VERSION_CONDITION_SYNTAX = 179,
    INTERNAL_BAD_CODE_AUTO_POSSESS = 180,
    CALLOUT_NO_STRING_DELIMITER = 181,
    CALLOUT_BAD_STRING_DELIMITER = 182,
    BACKSLASH_C_CALLER_DISABLED = 183,
    QUERY_BARJX_NEST_TOO_DEEP = 184,
    BACKSLASH_C_LIBRARY_DISABLED = 185,
    PATTERN_TOO_COMPLICATED = 186,
    LOOKBEHIND_TOO_LONG = 187,
    PATTERN_STRING_TOO_LONG = 188,
    INTERNAL_BAD_CODE = 189,
    INTERNAL_BAD_CODE_IN_SKIP = 190,
    NO_SURROGATES_IN_UTF16 = 191,
    BAD_LITERAL_OPTIONS = 192,
    SUPPORTED_ONLY_IN_UNICODE = 193,
    INVALID_HYPHEN_IN_OPTIONS = 194,
    ALPHA_ASSERTION_UNKNOWN = 195,
    SCRIPT_RUN_NOT_AVAILABLE = 196,
    TOO_MANY_CAPTURES = 197,
    CONDITION_ATOMIC_ASSERTION_EXPECTED = 198,
    BACKSLASH_K_IN_LOOKAROUND = 199,

    pub fn toError(e: CompileError) anyerror {
        return switch (e) {
            .END_BACKSLASH => error.EndBackslash,
            .END_BACKSLASH_C => error.EndBackslashC,
            .UNKNOWN_ESCAPE => error.UnknownEscape,
            .QUANTIFIER_OUT_OF_ORDER => error.QuantifierOutOfOrder,
            .QUANTIFIER_TOO_BIG => error.QuantifierTooBig,
            .MISSING_SQUARE_BRACKET => error.MissingSquareBracket,
            .ESCAPE_INVALID_IN_CLASS => error.EscapeInvalidInClass,
            .CLASS_RANGE_ORDER => error.ClassRangeOrder,
            .QUANTIFIER_INVALID => error.QuantifierInvalid,
            .INTERNAL_UNEXPECTED_REPEAT => error.UnexpectedRepeat,
            .INVALID_AFTER_PARENS_QUERY => error.InvalidAfterParensQuery,
            .POSIX_CLASS_NOT_IN_CLASS => error.PosixClassNotInClass,
            .POSIX_NO_SUPPORT_COLLATING => error.PosixNoSupportCollating,
            .MISSING_CLOSING_PARENTHESIS => error.MissingClosingParenthesis,
            .BAD_SUBPATTERN_REFERENCE => error.BadSubpatternReference,
            .NULL_PATTERN => error.NullPattern,
            .BAD_OPTIONS => error.BadOptions,
            .MISSING_COMMENT_CLOSING => error.MissingCommentClosing,
            .PARENTHESES_NEST_TOO_DEEP => error.ParensNestTooDeep,
            .PATTERN_TOO_LARGE => error.PatternTooLarge,
            .HEAP_FAILED => error.HeapFailed,
            .UNMATCHED_CLOSING_PARENTHESIS => error.UnmatchedClosingParenthesis,
            .INTERNAL_CODE_OVERFLOW => error.InternalCodeOverflow,
            .MISSING_CONDITION_CLOSING => error.MissingConditionClosing,
            .LOOKBEHIND_NOT_FIXED_LENGTH => error.LookbehindNotFixedLength,
            .ZERO_RELATIVE_REFERENCE => error.ZeroRelativeReference,
            .TOO_MANY_CONDITION_BRANCHES => error.TooManyConditionBranches,
            .CONDITION_ASSERTION_EXPECTED => error.ConditionAssertionExpected,
            .BAD_RELATIVE_REFERENCE => error.BadRelativeReference,
            .UNKNOWN_POSIX_CLASS => error.UnknownPosixClass,
            .INTERNAL_STUDY_ERROR => error.InternalStudyError,
            .UNICODE_NOT_SUPPORTED => error.UnicodeNotSupported,
            .PARENTHESES_STACK_CHECK => error.ParensStackCheck,
            .CODE_POINT_TOO_BIG => error.CodePointTooBig,
            .LOOKBEHIND_TOO_COMPLICATED => error.LookbehindTooComplicated,
            .LOOKBEHIND_INVALID_BACKSLASH_C => error.LookbehindInvalidBackslashC,
            .UNSUPPORTED_ESCAPE_SEQUENCE => error.UnsupportedEscapeSequence,
            .CALLOUT_NUMBER_TOO_BIG => error.CalloutNumberTooBig,
            .MISSING_CALLOUT_CLOSING => error.MissingCalloutClosing,
            .ESCAPE_INVALID_IN_VERB => error.EscapeInvalidInVerb,
            .UNRECOGNIZED_AFTER_QUERY_P => error.UnrecognizedAfterQueryP,
            .MISSING_NAME_TERMINATOR => error.MissingNameTerminator,
            .DUPLICATE_SUBPATTERN_NAME => error.DuplicateSubpatternName,
            .INVALID_SUBPATTERN_NAME => error.InvalidSubpatternName,
            .UNICODE_PROPERTIES_UNAVAILABLE => error.UnicodePropertiesUnavailable,
            .MALFORMED_UNICODE_PROPERTY => error.MalformedUnicodeProperty,
            .UNKNOWN_UNICODE_PROPERTY => error.UnknownUnicodeProperty,
            .SUBPATTERN_NAME_TOO_LONG => error.SubpatternNameTooLong,
            .TOO_MANY_NAMED_SUBPATTERNS => error.TooManyNamedSubpatterns,
            .CLASS_INVALID_RANGE => error.ClassInvalidRange,
            .OCTAL_BYTE_TOO_BIG => error.OctalByteTooBig,
            .INTERNAL_OVERRAN_WORKSPACE => error.InternalOverranWorkspace,
            .INTERNAL_MISSING_SUBPATTERN => error.InternalMissingSubpattern,
            .DEFINE_TOO_MANY_BRANCHES => error.DefineTooManyBranches,
            .BACKSLASH_O_MISSING_BRACE => error.BackslashOMissingBrace,
            .INTERNAL_UNKNOWN_NEWLINE => error.InternalUnknownNewline,
            .BACKSLASH_G_SYNTAX => error.BackslashGSyntax,
            .PARENS_QUERY_R_MISSING_CLOSING => error.ParensQueryRMissingClosing,
            .VERB_ARGUMENT_NOT_ALLOWED => error.VerbArgumentNotAllowed,
            .VERB_UNKNOWN => error.VerbUnknown,
            .SUBPATTERN_NUMBER_TOO_BIG => error.SubpatternNumberTooBig,
            .SUBPATTERN_NAME_EXPECTED => error.SubpatternNameExpected,
            .INTERNAL_PARSED_OVERFLOW => error.InternalParsedOverflow,
            .INVALID_OCTAL => error.InvalidOctal,
            .SUBPATTERN_NAMES_MISMATCH => error.SubpatternNamesMismatch,
            .MARK_MISSING_ARGUMENT => error.MarkMissingArgument,
            .INVALID_HEXADECIMAL => error.InvalidHexadecimal,
            .BACKSLASH_C_SYNTAX => error.BackslashCSyntax,
            .BACKSLASH_K_SYNTAX => error.BackslashKSyntax,
            .INTERNAL_BAD_CODE_LOOKBEHINDS => error.InternalBadCodeLookbehinds,
            .BACKSLASH_N_IN_CLASS => error.BackslashNInClass,
            .CALLOUT_STRING_TOO_LONG => error.CalloutStringTooLong,
            .UNICODE_DISALLOWED_CODE_POINT => error.UnicodeDisallowedCodePoint,
            .UTF_IS_DISABLED => error.UtfIsDisabled,
            .UCP_IS_DISABLED => error.UcpIsDisabled,
            .VERB_NAME_TOO_LONG => error.VerbNameTooLong,
            .BACKSLASH_U_CODE_POINT_TOO_BIG => error.BackslashUCodePointTooBig,
            .MISSING_OCTAL_OR_HEX_DIGITS => error.MissingOctalOrHexDigits,
            .VERSION_CONDITION_SYNTAX => error.VersionConditionSyntax,
            .INTERNAL_BAD_CODE_AUTO_POSSESS => error.InternalBadCodeAutoPossess,
            .CALLOUT_NO_STRING_DELIMITER => error.CalloutNoStringDelimiter,
            .CALLOUT_BAD_STRING_DELIMITER => error.CalloutBadStringDelimiter,
            .BACKSLASH_C_CALLER_DISABLED => error.BackslashCCallerDisabled,
            .QUERY_BARJX_NEST_TOO_DEEP => error.QueryBarJxNestTooDeep,
            .BACKSLASH_C_LIBRARY_DISABLED => error.BackslashCLibraryDisabled,
            .PATTERN_TOO_COMPLICATED => error.PatternTooComplicated,
            .LOOKBEHIND_TOO_LONG => error.LookbehindTooLong,
            .PATTERN_STRING_TOO_LONG => error.PatternStringTooLong,
            .INTERNAL_BAD_CODE => error.InternalBadCode,
            .INTERNAL_BAD_CODE_IN_SKIP => error.InternalBadCodeInSkip,
            .NO_SURROGATES_IN_UTF16 => error.NoSurrogatesInUtf16,
            .BAD_LITERAL_OPTIONS => error.BadLiteralOptions,
            .SUPPORTED_ONLY_IN_UNICODE => error.SupportedOnlyInUnicode,
            .INVALID_HYPHEN_IN_OPTIONS => error.InvalidHyphenInOptions,
            .ALPHA_ASSERTION_UNKNOWN => error.AlphaAssertionUnknown,
            .SCRIPT_RUN_NOT_AVAILABLE => error.ScriptRunNotAvailable,
            .TOO_MANY_CAPTURES => error.TooManyCaptures,
            .CONDITION_ATOMIC_ASSERTION_EXPECTED => error.ConditionAtomicAssertionExpected,
            .BACKSLASH_K_IN_LOOKAROUND => error.BackslashKInLookaround,
        };
    }
};

pub const MatchingError = enum(c_int) {
    NOMATCH = -1,
    PARTIAL = -2,
    UTF8_ERR1 = -3,
    UTF8_ERR2 = -4,
    UTF8_ERR3 = -5,
    UTF8_ERR4 = -6,
    UTF8_ERR5 = -7,
    UTF8_ERR6 = -8,
    UTF8_ERR7 = -9,
    UTF8_ERR8 = -10,
    UTF8_ERR9 = -11,
    UTF8_ERR10 = -12,
    UTF8_ERR11 = -13,
    UTF8_ERR12 = -14,
    UTF8_ERR13 = -15,
    UTF8_ERR14 = -16,
    UTF8_ERR15 = -17,
    UTF8_ERR16 = -18,
    UTF8_ERR17 = -19,
    UTF8_ERR18 = -20,
    UTF8_ERR19 = -21,
    UTF8_ERR20 = -22,
    UTF8_ERR21 = -23,
    UTF16_ERR1 = -24,
    UTF16_ERR2 = -25,
    UTF16_ERR3 = -26,
    UTF32_ERR1 = -27,
    UTF32_ERR2 = -28,
    BADDATA = -29,
    MIXEDTABLES = -30,
    BADMAGIC = -31,
    BADMODE = -32,
    BADOFFSET = -33,
    BADOPTION = -34,
    BADREPLACEMENT = -35,
    BADUTFOFFSET = -36,
    CALLOUT = -37,
    DFA_BADRESTART = -38,
    DFA_RECURSE = -39,
    DFA_UCOND = -40,
    DFA_UFUNC = -41,
    DFA_UITEM = -42,
    DFA_WSSIZE = -43,
    INTERNAL = -44,
    JIT_BADOPTION = -45,
    JIT_STACKLIMIT = -46,
    MATCHLIMIT = -47,
    NOMEMORY = -48,
    NOSUBSTRING = -49,
    NOUNIQUESUBSTRING = -50,
    NULL = -51,
    RECURSELOOP = -52,
    DEPTHLIMIT = -53,
    UNAVAILABLE = -54,
    UNSET = -55,
    BADOFFSETLIMIT = -56,
    BADREPESCAPE = -57,
    REPMISSINGBRACE = -58,
    BADSUBSTITUTION = -59,
    BADSUBSPATTERN = -60,
    TOOMANYREPLACE = -61,
    BADSERIALIZEDDATA = -62,
    HEAPLIMIT = -63,
    CONVERT_SYNTAX = -64,
    INTERNAL_DUPMATCH = -65,
    DFA_UINVALID_UTF = -66,

    pub fn toError(e: MatchingError) anyerror {
        return switch (e) {
            .NOMATCH => error.NoMatch,
            .PARTIAL => error.Partial,
            .UTF8_ERR1 => error.Utf8Err1,
            .UTF8_ERR2 => error.Utf8Err2,
            .UTF8_ERR3 => error.Utf8Err3,
            .UTF8_ERR4 => error.Utf8Err4,
            .UTF8_ERR5 => error.Utf8Err5,
            .UTF8_ERR6 => error.Utf8Err6,
            .UTF8_ERR7 => error.Utf8Err7,
            .UTF8_ERR8 => error.Utf8Err8,
            .UTF8_ERR9 => error.Utf8Err9,
            .UTF8_ERR10 => error.Utf8Err10,
            .UTF8_ERR11 => error.Utf8Err11,
            .UTF8_ERR12 => error.Utf8Err12,
            .UTF8_ERR13 => error.Utf8Err13,
            .UTF8_ERR14 => error.Utf8Err14,
            .UTF8_ERR15 => error.Utf8Err15,
            .UTF8_ERR16 => error.Utf8Err16,
            .UTF8_ERR17 => error.Utf8Err17,
            .UTF8_ERR18 => error.Utf8Err18,
            .UTF8_ERR19 => error.Utf8Err19,
            .UTF8_ERR20 => error.Utf8Err20,
            .UTF8_ERR21 => error.Utf8Err21,
            .UTF16_ERR1 => error.Utf16Err1,
            .UTF16_ERR2 => error.Utf16Err2,
            .UTF16_ERR3 => error.Utf16Err3,
            .UTF32_ERR1 => error.Utf32Err1,
            .UTF32_ERR2 => error.Utf32Err2,
            .BADDATA => error.BadData,
            .MIXEDTABLES => error.MixedTables,
            .BADMAGIC => error.BadMagic,
            .BADMODE => error.BadMode,
            .BADOFFSET => error.BadOffset,
            .BADOPTION => error.BadOption,
            .BADREPLACEMENT => error.BadReplacement,
            .BADUTFOFFSET => error.BadUtfOffset,
            .CALLOUT => error.Callout,
            .DFA_BADRESTART => error.DfaBadRestart,
            .DFA_RECURSE => error.DfaRecurse,
            .DFA_UCOND => error.DfaUCond,
            .DFA_UFUNC => error.DfaUFunc,
            .DFA_UITEM => error.DfaUItem,
            .DFA_WSSIZE => error.DfaWsSize,
            .INTERNAL => error.Internal,
            .JIT_BADOPTION => error.JitBadOption,
            .JIT_STACKLIMIT => error.JitStackLimit,
            .MATCHLIMIT => error.MatchLimit,
            .NOMEMORY => error.NoMemory,
            .NOSUBSTRING => error.NoSubstring,
            .NOUNIQUESUBSTRING => error.NoUniqueSubstring,
            .NULL => error.Null,
            .RECURSELOOP => error.RecurseLoop,
            .DEPTHLIMIT => error.DepthLimit,
            .UNAVAILABLE => error.Unavailable,
            .UNSET => error.Unset,
            .BADOFFSETLIMIT => error.BadOffsetLimit,
            .BADREPESCAPE => error.BadRepEscape,
            .REPMISSINGBRACE => error.RepmissingBrace,
            .BADSUBSTITUTION => error.BadSubstitution,
            .BADSUBSPATTERN => error.BadSubpattern,
            .TOOMANYREPLACE => error.TooManyReplace,
            .BADSERIALIZEDDATA => error.BadSerializedData,
            .HEAPLIMIT => error.HeapLimit,
            .CONVERT_SYNTAX => error.ConvertSyntax,
            .INTERNAL_DUPMATCH => error.InternalDupMatch,
            .DFA_UINVALID_UTF => error.DfaUInvalidUtf,
        };
    }
};

test "sample" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("(foo)(bar)?", 0, &pos);
    defer regex.deinit();

    const subject = "foobar foobaz foo";
    var iter = try regex.matchIterator(subject);
    defer iter.free();
    var count: u8 = 0;
    while (try iter.next(allocator)) |match| {
        defer match.free(allocator);
        if (count == 0) {
            try std.testing.expectEqual(3, match.captures.len);
            try std.testing.expectEqualStrings("foobar", match.captures[0].?.slice);
            try std.testing.expectEqual(0, match.captures[0].?.index);
            try std.testing.expectEqualStrings("foo", match.captures[1].?.slice);
            try std.testing.expectEqual(0, match.captures[1].?.index);
            try std.testing.expectEqualStrings("bar", match.captures[2].?.slice);
            try std.testing.expectEqual(3, match.captures[2].?.index);
        } else if (count == 1) {
            try std.testing.expectEqual(2, match.captures.len);
            try std.testing.expectEqualStrings("foo", match.captures[0].?.slice);
            try std.testing.expectEqual(7, match.captures[0].?.index);
            try std.testing.expectEqualStrings("foo", match.captures[1].?.slice);
            try std.testing.expectEqual(7, match.captures[1].?.index);
        } else if (count == 2) {
            try std.testing.expectEqual(2, match.captures.len);
            try std.testing.expectEqualStrings("foo", match.captures[0].?.slice);
            try std.testing.expectEqual(14, match.captures[0].?.index);
            try std.testing.expectEqualStrings("foo", match.captures[1].?.slice);
            try std.testing.expectEqual(14, match.captures[1].?.index);
        }
        count += 1;
    }
}

test "Fail" {
    {
        var pos: usize = 0;
        const subject: []const u8 = "(b+";
        try std.testing.expectError(CompileError.MISSING_CLOSING_PARENTHESIS.toError(), compile(subject, 0, &pos));
        try std.testing.expectEqual(3, pos);
        try std.testing.expectEqual(subject.len, pos);
    }
    {
        var pos: usize = 0;
        const subject: []const u8 = "())(b+)";
        try std.testing.expectError(CompileError.UNMATCHED_CLOSING_PARENTHESIS.toError(), compile(subject, 0, &pos));
        try std.testing.expectEqual(2, pos);
        try std.testing.expectEqual(')', subject[pos]);
    }
}

test "isMatch" {
    var pos: usize = 0;
    var re = try compile("b+", 0, &pos);
    defer re.deinit();

    try std.testing.expect(try re.isMatch("bbb"));
    try std.testing.expect(!try re.isMatch("abbbc"));
    try std.testing.expect(!try re.isMatch("adddc"));
}

test "isMatch (unicode)" {
    var pos: usize = 0;
    var re = try compile("🍕+", Options.PCRE2_UTF, &pos);
    defer re.deinit();

    try std.testing.expect(try re.isMatch("🍕🍕🍕"));
    try std.testing.expect(!try re.isMatch("a🍕🍕🍕c"));
    try std.testing.expect(!try re.isMatch("adddc"));
}

test "Match" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("a(b+)c", 0, &pos);
    defer regex.deinit();

    if (try regex.match(allocator, "abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.match(allocator, "   abbbc")) |m| {
        defer m.free(allocator);
        return error.Fail;
    }
}

test "Match (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("a(🍕+)c", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    if (try regex.match(allocator, "a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.match(allocator, "   a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        return error.Fail;
    }
}

test "Workaround Match" {
    const allocator = std.testing.allocator;
    var pos: usize = 0;
    var re = try compile("\\s*(a(b+)c)\\s*", 0, &pos);
    defer re.deinit();

    if (try re.match(allocator, "abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("abbbc", m.captures[1].?.slice);
        try std.testing.expectEqual(0, m.captures[1].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[2].?.slice);
        try std.testing.expectEqual(1, m.captures[2].?.index);
    } else return error.Fail;

    if (try re.match(allocator, "   abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqualStrings("   abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("abbbc", m.captures[1].?.slice);
        try std.testing.expectEqual(3, m.captures[1].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[2].?.slice);
        try std.testing.expectEqual(4, m.captures[2].?.index);
    } else return error.Fail;
}

test "Workaround Match (unicode)" {
    const allocator = std.testing.allocator;
    var pos: usize = 0;
    var re = try compile("\\s*(a(🍕+)c)\\s*", Options.PCRE2_UTF, &pos);
    defer re.deinit();

    if (try re.match(allocator, "a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[1].?.slice);
        try std.testing.expectEqual(0, m.captures[1].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[2].?.slice);
        try std.testing.expectEqual(1, m.captures[2].?.index);
    } else return error.Fail;

    if (try re.match(allocator, "   a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqualStrings("   a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[1].?.slice);
        try std.testing.expectEqual(3, m.captures[1].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[2].?.slice);
        try std.testing.expectEqual(4, m.captures[2].?.index);
    } else return error.Fail;
}

test "Search" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("a(b+)c", 0, &pos);
    defer regex.deinit();

    if (try regex.search(allocator, "abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.search(allocator, "   abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(3, m.captures[0].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[1].?.slice);
        try std.testing.expectEqual(4, m.captures[1].?.index);
    }
}

test "Search (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("a(🍕+)c", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    if (try regex.search(allocator, "a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.search(allocator, "   a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(3, m.captures[0].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[1].?.slice);
        try std.testing.expectEqual(4, m.captures[1].?.index);
    }
}

test "Replace" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("b+", 0, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplace(allocator, "abbbc", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("abbbc", result1);
    const result2 = try regex.allocReplace(allocator, "abbbc", "c");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("acc", result2);
    const result3 = try regex.allocReplace(allocator, "adddc", "c");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("adddc", result3);
    const result4 = try regex.allocReplace(allocator, "abbbc abbbc", "c");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("acc abbbc", result4);
}

test "Replace (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("🍕+", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplace(allocator, "a🍕🍕🍕c", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("a🍕🍕🍕c", result1);
    const result2 = try regex.allocReplace(allocator, "a🍕🍕🍕c", "c");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("acc", result2);
    const result3 = try regex.allocReplace(allocator, "adddc", "c");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("adddc", result3);
    const result4 = try regex.allocReplace(allocator, "a🍕🍕🍕c a🍕🍕🍕c", "c");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("acc a🍕🍕🍕c", result4);
}

test "ReplaceAll" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("b+", 0, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "abbbc", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("abbbc", result1);
    const result2 = try regex.allocReplaceAll(allocator, "abbbc", "c");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("acc", result2);
    const result3 = try regex.allocReplaceAll(allocator, "adddc", "c");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("adddc", result3);
    const result4 = try regex.allocReplaceAll(allocator, "abbbc abbbc", "c");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("acc acc", result4);
}

test "ReplaceAll (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("🍕+", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "a🍕🍕🍕c", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("a🍕🍕🍕c", result1);
    const result2 = try regex.allocReplaceAll(allocator, "a🍕🍕🍕c", "c");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("acc", result2);
    const result3 = try regex.allocReplaceAll(allocator, "adddc", "c");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("adddc", result3);
    const result4 = try regex.allocReplaceAll(allocator, "a🍕🍕🍕c a🍕🍕🍕c", "c");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("acc acc", result4);
}

test "ReplaceAll CaseInsensitive" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^(a)(b+)(c)$", Options.PCRE2_CASELESS, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "ABBBC", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("ABBBC", result1);
    const result2 = try regex.allocReplaceAll(allocator, "ABBBC", "$1c$3");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("AcC", result2);
    const result3 = try regex.allocReplaceAll(allocator, "ADDDC", "$1c$3");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("ADDDC", result3);
    const result4 = try regex.allocReplaceAll(allocator, "ABBBC ABBBC", "$1c$3");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("ABBBC ABBBC", result4);
    const result5 = try regex.allocReplaceAll(allocator, "ABBBC\nABBBC", "$1c$3");
    defer allocator.free(result5);
    try std.testing.expectEqualStrings("ABBBC\nABBBC", result5);
}

test "ReplaceAll CaseInsensitive (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^(a)(🍕+)(c)$", Options.PCRE2_CASELESS | Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("A🍕🍕🍕C", result1);
    const result2 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C", "$1c$3");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("AcC", result2);
    const result3 = try regex.allocReplaceAll(allocator, "ADDDC", "$1c$3");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("ADDDC", result3);
    const result4 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C A🍕🍕🍕C", "$1c$3");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("A🍕🍕🍕C A🍕🍕🍕C", result4);
    const result5 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C\nA🍕🍕🍕C", "$1c$3");
    defer allocator.free(result5);
    try std.testing.expectEqualStrings("A🍕🍕🍕C\nA🍕🍕🍕C", result5);
}

test "ReplaceAll CaseInsensitive Multiline" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^(a)(b+)(c)$", Options.PCRE2_CASELESS | Options.PCRE2_MULTILINE, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "ABBBC\nABBBC", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("ABBBC\nABBBC", result1);
    const result2 = try regex.allocReplaceAll(allocator, "ABBBC\nABBBC", "$1c$3");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("AcC\nAcC", result2);
    const result3 = try regex.allocReplaceAll(allocator, "ADDDC\nADDDC", "$1c$3");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("ADDDC\nADDDC", result3);
    const result4 = try regex.allocReplaceAll(allocator, "ABBBC ABBBC\nABBBC ABBBC", "$1c$3");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("ABBBC ABBBC\nABBBC ABBBC", result4);
}

test "ReplaceAll CaseInsensitive Multiline (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^(a)(🍕+)(c)$", Options.PCRE2_CASELESS | Options.PCRE2_UTF | Options.PCRE2_MULTILINE, &pos);
    defer regex.deinit();

    const result1 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C\nA🍕🍕🍕C", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("A🍕🍕🍕C\nA🍕🍕🍕C", result1);
    const result2 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C\nA🍕🍕🍕C", "$1c$3");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("AcC\nAcC", result2);
    const result3 = try regex.allocReplaceAll(allocator, "ADDDC\nADDDC", "$1c$3");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("ADDDC\nADDDC", result3);
    const result4 = try regex.allocReplaceAll(allocator, "A🍕🍕🍕C A🍕🍕🍕C\nA🍕🍕🍕C A🍕🍕🍕C", "$1c$3");
    defer allocator.free(result4);
    try std.testing.expectEqualStrings("A🍕🍕🍕C A🍕🍕🍕C\nA🍕🍕🍕C A🍕🍕🍕C", result4);
}

test "Format" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("b+", 0, &pos);
    defer regex.deinit();

    const result1 = try regex.allocFormat(allocator, "abbbc", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("bbb", result1);
    const result2 = try regex.allocFormat(allocator, "abbbc", "b=$0");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("b=bbb", result2);
}

test "Format (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("🍕+", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    const result1 = try regex.allocFormat(allocator, "a🍕🍕🍕c", "$0");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("🍕🍕🍕", result1);
    const result2 = try regex.allocFormat(allocator, "a🍕🍕🍕c", "🍕=$0");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("🍕=🍕🍕🍕", result2);
}

test "Strict Search" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^a(b+)c$", 0, &pos);
    defer regex.deinit();

    if (try regex.search(allocator, "abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.search(allocator, "   abbbc")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("abbbc", m.captures[0].?.slice);
        try std.testing.expectEqual(3, m.captures[0].?.index);
        try std.testing.expectEqualStrings("bbb", m.captures[1].?.slice);
        try std.testing.expectEqual(4, m.captures[1].?.index);
    }
}

test "Strict Search (unicode)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("^a(🍕+)c$", Options.PCRE2_UTF, &pos);
    defer regex.deinit();

    if (try regex.search(allocator, "a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(0, m.captures[0].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[1].?.slice);
        try std.testing.expectEqual(1, m.captures[1].?.index);
    }

    if (try regex.search(allocator, "   a🍕🍕🍕c")) |m| {
        defer m.free(allocator);
        try std.testing.expectEqual(2, m.captures.len);
        try std.testing.expectEqualStrings("a🍕🍕🍕c", m.captures[0].?.slice);
        try std.testing.expectEqual(3, m.captures[0].?.index);
        try std.testing.expectEqualStrings("🍕🍕🍕", m.captures[1].?.slice);
        try std.testing.expectEqual(4, m.captures[1].?.index);
    }
}

test "subsitute - replace" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("(foo)(bar)?", 0, &pos);
    defer regex.deinit();

    const subject = "foobar foobaz foo";
    const replacement = "baz$1";
    const result = try regex.subsitute(allocator, subject, replacement, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("bazfoo foobaz foo", result);
}

test "subsitute - replaceAll" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    const regex = try compile("(foo)(bar)?", 0, &pos);
    defer regex.deinit();

    const subject = "foobar foobaz foo";
    const replacement = "baz$1";
    const result = try regex.subsitute(allocator, subject, replacement, Options.PCRE2_SUBSTITUTE_GLOBAL);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("bazfoo bazfoobaz bazfoo", result);
}

test "Semver 2.0.0" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    var re = try compile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$", 0, &pos);
    defer re.deinit();

    var valid_iter = std.mem.splitSequence(u8,
        \\0.0.4
        \\1.2.3
        \\1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay
        \\0.0.4
        \\1.2.3
        \\10.20.30
        \\1.1.2-prerelease+meta
        \\1.1.2+meta
        \\1.1.2+meta-valid
        \\1.0.0-alpha
        \\1.0.0-beta
        \\1.0.0-alpha.beta
        \\1.0.0-alpha.beta.1
        \\1.0.0-alpha.1
        \\1.0.0-alpha0.valid
        \\1.0.0-alpha.0valid
        \\1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay
        \\1.0.0-rc.1+build.1
        \\2.0.0-rc.1+build.123
        \\1.2.3-beta
        \\10.2.3-DEV-SNAPSHOT
        \\1.2.3-SNAPSHOT-123
        \\1.0.0
        \\2.0.0
        \\1.1.7
        \\2.0.0+build.1848
        \\2.0.1-alpha.1227
        \\1.0.0-alpha+beta
        \\1.2.3----RC-SNAPSHOT.12.9.1--.12+788
        \\1.2.3----R-S.12.9.1--.12+meta
        \\1.2.3----RC-SNAPSHOT.12.9.1--.12
        \\1.0.0+0.build.1-rc.10000aaa-kk-0.1
        \\99999999999999999999999.999999999999999999.99999999999999999
        \\1.0.0-0A.is.legal
    , "\n");

    var invalid_iter = std.mem.splitSequence(u8,
        \\1
        \\1.2
        \\1.2.3-0123
        \\1.2.3-0123.0123
        \\1.1.2+.123
        \\+invalid
        \\-invalid
        \\-invalid+invalid
        \\-invalid.01
        \\alpha
        \\alpha.beta
        \\alpha.beta.1
        \\alpha.1
        \\alpha+beta
        \\alpha_beta
        \\alpha.
        \\alpha..
        \\beta
        \\1.0.0-alpha_beta
        \\-alpha.
        \\1.0.0-alpha..
        \\1.0.0-alpha..1
        \\1.0.0-alpha...1
        \\1.0.0-alpha....1
        \\1.0.0-alpha.....1
        \\1.0.0-alpha......1
        \\1.0.0-alpha.......1
        \\01.1.1
        \\1.01.1
        \\1.1.01
        \\1.2
        \\1.2.3.DEV
        \\1.2-SNAPSHOT
        \\1.2.31.2.3----RC-SNAPSHOT.12.09.1--..12+788
        \\1.2-RC-SNAPSHOT
        \\-1.0.3-gamma+b7718
        \\+justmeta
        \\9.8.7+meta+meta
        \\9.8.7-whatever+meta+meta
        \\99999999999999999999999.999999999999999999.99999999999999999----RC-SNAPSHOT.12.09.1--------------------------------..12
    , "\n");

    while (valid_iter.next()) |line| {
        // Suppose to match
        if (try re.match(allocator, line)) |m| {
            defer m.free(allocator);
            try std.testing.expect(m.captures.len > 0);
        } else return error.Fail;
    }

    while (invalid_iter.next()) |line| {
        // Not suppose to match
        if (try re.match(allocator, line)) |m| {
            defer m.free(allocator);
            return error.Fail;
        }
    }
}

test "Semver 2.0.0 (Perl)" {
    const allocator = std.testing.allocator;

    var pos: usize = 0;
    var re = try compile("^(?P<major>0|[1-9]\\d*)\\.(?P<minor>0|[1-9]\\d*)\\.(?P<patch>0|[1-9]\\d*)(?:-(?P<prerelease>(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$", 0, &pos);
    defer re.deinit();

    var valid_iter = std.mem.splitSequence(u8,
        \\0.0.4
        \\1.2.3
        \\1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay
        \\0.0.4
        \\1.2.3
        \\10.20.30
        \\1.1.2-prerelease+meta
        \\1.1.2+meta
        \\1.1.2+meta-valid
        \\1.0.0-alpha
        \\1.0.0-beta
        \\1.0.0-alpha.beta
        \\1.0.0-alpha.beta.1
        \\1.0.0-alpha.1
        \\1.0.0-alpha0.valid
        \\1.0.0-alpha.0valid
        \\1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay
        \\1.0.0-rc.1+build.1
        \\2.0.0-rc.1+build.123
        \\1.2.3-beta
        \\10.2.3-DEV-SNAPSHOT
        \\1.2.3-SNAPSHOT-123
        \\1.0.0
        \\2.0.0
        \\1.1.7
        \\2.0.0+build.1848
        \\2.0.1-alpha.1227
        \\1.0.0-alpha+beta
        \\1.2.3----RC-SNAPSHOT.12.9.1--.12+788
        \\1.2.3----R-S.12.9.1--.12+meta
        \\1.2.3----RC-SNAPSHOT.12.9.1--.12
        \\1.0.0+0.build.1-rc.10000aaa-kk-0.1
        \\99999999999999999999999.999999999999999999.99999999999999999
        \\1.0.0-0A.is.legal
    , "\n");

    var invalid_iter = std.mem.splitSequence(u8,
        \\1
        \\1.2
        \\1.2.3-0123
        \\1.2.3-0123.0123
        \\1.1.2+.123
        \\+invalid
        \\-invalid
        \\-invalid+invalid
        \\-invalid.01
        \\alpha
        \\alpha.beta
        \\alpha.beta.1
        \\alpha.1
        \\alpha+beta
        \\alpha_beta
        \\alpha.
        \\alpha..
        \\beta
        \\1.0.0-alpha_beta
        \\-alpha.
        \\1.0.0-alpha..
        \\1.0.0-alpha..1
        \\1.0.0-alpha...1
        \\1.0.0-alpha....1
        \\1.0.0-alpha.....1
        \\1.0.0-alpha......1
        \\1.0.0-alpha.......1
        \\01.1.1
        \\1.01.1
        \\1.1.01
        \\1.2
        \\1.2.3.DEV
        \\1.2-SNAPSHOT
        \\1.2.31.2.3----RC-SNAPSHOT.12.09.1--..12+788
        \\1.2-RC-SNAPSHOT
        \\-1.0.3-gamma+b7718
        \\+justmeta
        \\9.8.7+meta+meta
        \\9.8.7-whatever+meta+meta
        \\99999999999999999999999.999999999999999999.99999999999999999----RC-SNAPSHOT.12.09.1--------------------------------..12
    , "\n");

    while (valid_iter.next()) |line| {
        // Suppose to match
        if (try re.match(allocator, line)) |m| {
            defer m.free(allocator);
            try std.testing.expect(m.captures.len > 0);
        } else return error.Fail;
    }

    while (invalid_iter.next()) |line| {
        // Not suppose to match
        if (try re.match(allocator, line)) |m| {
            defer m.free(allocator);
            return error.Fail;
        }
    }
}
