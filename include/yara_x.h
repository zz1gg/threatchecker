#ifndef YARA_X
#define YARA_X

#pragma once

/* Generated with cbindgen:0.26.0 */

// This file is autogenerated by cbindgen. Don't modify it manually.
#define YARA_X_MAJOR 0
#define YARA_X_MINOR 3
#define YARA_X_PATCH 0


#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


// Flag passed to [`yrx_compiler_create`] for producing colorful error
// messages.
#define YRX_COLORIZE_ERRORS 1

// Flag passed to [`yrx_compiler_create`] that enables a more relaxed
// syntax check for regular expressions.
//
// YARA-X enforces stricter regular expression syntax compared to YARA.
// For instance, YARA accepts invalid escape sequences and treats them
// as literal characters (e.g., \R is interpreted as a literal 'R'). It
// also allows some special characters to appear unescaped, inferring
// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
// literal, but in `/foo{0,1}bar/` they form the repetition operator
// `{0,1}`).
//
// When this flag is set, YARA-X mimics YARA's behavior, allowing
// constructs that YARA-X doesn't accept by default.
#define YRX_RELAXED_RE_SYNTAX 2

// Metadata value types.
typedef enum YRX_METADATA_VALUE_TYPE {
  I64,
  F64,
  BOOLEAN,
  STRING,
  BYTES,
} YRX_METADATA_VALUE_TYPE;

// Error codes returned by functions in this API.
typedef enum YRX_RESULT {
  // Everything was OK.
  SUCCESS,
  // A syntax error occurred while compiling YARA rules.
  SYNTAX_ERROR,
  // An error occurred while defining or setting a global variable. This may
  // happen when a variable is defined twice and when you try to set a value
  // that doesn't correspond to the variable's type.
  VARIABLE_ERROR,
  // An error occurred during a scan operation.
  SCAN_ERROR,
  // A scan operation was aborted due to a timeout.
  SCAN_TIMEOUT,
  // An error indicating that some of the arguments passed to a function is
  // invalid. Usually indicates a nil pointer to a scanner or compiler.
  INVALID_ARGUMENT,
  // An error indicating that some of the strings passed to a function is
  // not valid UTF-8.
  INVALID_UTF8,
  // An error occurred while serializing/deserializing YARA rules.
  SERIALIZATION_ERROR,
  // An error returned when a rule doesn't have any metadata.
  NO_METADATA,
} YRX_RESULT;

// A compiler that takes YARA source code and produces compiled rules.
typedef struct YRX_COMPILER YRX_COMPILER;

// A single YARA rule.
typedef struct YRX_RULE YRX_RULE;

// A set of compiled YARA rules.
typedef struct YRX_RULES YRX_RULES;

// A scanner that scans data with a set of compiled YARA rules.
typedef struct YRX_SCANNER YRX_SCANNER;

// Represents a buffer with arbitrary data.
typedef struct YRX_BUFFER {
  // Pointer to the data contained in the buffer.
  uint8_t *data;
  // Length of data in bytes.
  size_t length;
} YRX_BUFFER;

// Represents a metadata value that contains raw bytes.
typedef struct YRX_METADATA_BYTES {
  // Number of bytes.
  size_t length;
  // Pointer to the bytes.
  uint8_t *data;
} YRX_METADATA_BYTES;

// Metadata value.
typedef union YRX_METADATA_VALUE {
  int64_t i64;
  double f64;
  bool boolean;
  char *string;
  struct YRX_METADATA_BYTES bytes;
} YRX_METADATA_VALUE;

// A metadata entry.
typedef struct YRX_METADATA_ENTRY {
  // Metadata identifier.
  char *identifier;
  // Type of value.
  enum YRX_METADATA_VALUE_TYPE value_type;
  // The value itself. This is a union, use the member that matches the
  // value type.
  union YRX_METADATA_VALUE value;
} YRX_METADATA_ENTRY;

// Represents the metadata associated to a rule.
typedef struct YRX_METADATA {
  // Number of metadata entries.
  size_t num_entries;
  // Pointer to an array of YRX_METADATA_ENTRY structures. The array has
  // num_entries items. If num_entries is zero this pointer is invalid
  // and should not be de-referenced.
  struct YRX_METADATA_ENTRY *entries;
} YRX_METADATA;

// Contains information about a pattern match.
typedef struct YRX_MATCH {
  // Offset within the data where the match occurred.
  size_t offset;
  // Length of the match.
  size_t length;
} YRX_MATCH;

// A pattern within a rule.
typedef struct YRX_PATTERN {
  // Pattern's identifier (i.e: $a, $foo)
  char *identifier;
  // Number of matches found for this pattern.
  size_t num_matches;
  // Pointer to an array of YRX_MATCH structures describing the matches
  // for this pattern. The array has num_matches items. If num_matches is
  // zero this pointer is invalid and should not be de-referenced.
  struct YRX_MATCH *matches;
} YRX_PATTERN;

// A set of patterns declared in a YARA rule.
typedef struct YRX_PATTERNS {
  // Number of patterns.
  size_t num_patterns;
  // Pointer to an array of YRX_PATTERN structures. The array has
  // num_patterns items. If num_patterns is zero this pointer is invalid
  // and should not be de-referenced.
  struct YRX_PATTERN *patterns;
} YRX_PATTERNS;

// Callback function passed to the scanner via [`yrx_scanner_on_matching_rule`]
// which receives notifications about matching rules.
//
// The callback receives a pointer to the matching rule, represented by a
// [`YRX_RULE`] structure. This pointer is guaranteed to be valid while the
// callback function is being executed, but it may be freed after the callback
// function returns, so you cannot use the pointer outside the callback.
//
// It also receives the `user_data` pointer that was passed to the
// [`yrx_scanner_on_matching_rule`] function, which can point to arbitrary
// data owned by the user.
typedef void (*YRX_ON_MATCHING_RULE)(const struct YRX_RULE *rule,
                                     void *user_data);

// Compiles YARA source code and creates a [`YRX_RULES`] object that contains
// the compiled rules.
//
// The rules must be destroyed with [`yrx_rules_destroy`].
enum YRX_RESULT yrx_compile(const char *src,
                            struct YRX_RULES **rules);

// Serializes the rules as a sequence of bytes.
//
// In the address indicated by the `buf` pointer, the function will copy a
// `YRX_BUFFER*` pointer. The `YRX_BUFFER` structure represents a buffer
// that contains the serialized rules. This structure has a pointer to the
// data itself, and its length.
//
// The [`YRX_BUFFER`] must be destroyed with [`yrx_buffer_destroy`].
enum YRX_RESULT yrx_rules_serialize(struct YRX_RULES *rules,
                                    struct YRX_BUFFER **buf);

// Deserializes the rules from a sequence of bytes produced by
// [`yrx_rules_serialize`].
//
enum YRX_RESULT yrx_rules_deserialize(const uint8_t *data,
                                      size_t len,
                                      struct YRX_RULES **rules);

// Destroys a [`YRX_RULES`] object.
void yrx_rules_destroy(struct YRX_RULES *rules);

// Returns the name of the rule represented by [`YRX_RULE`].
//
// Arguments `ident` and `len` are output parameters that receive pointers
// to a `const uint8_t*` and `size_t`, where this function will leave a pointer
// to the rule's name and its length, respectively. The rule's name is *NOT*
// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
// object that contains the rule is not freed. The name is guaranteed to be a
// valid UTF-8 string.
enum YRX_RESULT yrx_rule_identifier(const struct YRX_RULE *rule,
                                    const uint8_t **ident,
                                    size_t *len);

// Returns the namespace of the rule represented by [`YRX_RULE`].
//
// Arguments `ns` and `len` are output parameters that receive pointers to a
// `const uint8_t*` and `size_t`, where this function will leave a pointer
// to the rule's namespace and its length, respectively. The namespace is *NOT*
// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
// object that contains the rule is not freed. The namespace is guaranteed to
// be a valid UTF-8 string.
enum YRX_RESULT yrx_rule_namespace(const struct YRX_RULE *rule,
                                   const uint8_t **ns,
                                   size_t *len);

// Returns the metadata associated to a rule.
//
// The metadata is represented by a [`YRX_METADATA`] object that must be
// destroyed with [`yrx_metadata_destroy`] when not needed anymore.
//
// This function returns a null pointer when `rule` is null or the
// rule doesn't have any metadata.
struct YRX_METADATA *yrx_rule_metadata(const struct YRX_RULE *rule);

// Destroys a [`YRX_METADATA`] object.
void yrx_metadata_destroy(struct YRX_METADATA *metadata);

// Returns all the patterns defined by a rule.
//
// Each pattern contains information about whether it matched or not, and where
// in the data it matched. The patterns are represented by a [`YRX_PATTERNS`]
// object that must be destroyed with [`yrx_patterns_destroy`] when not needed
// anymore.
//
// This function returns a null pointer when `rule` is null.
struct YRX_PATTERNS *yrx_rule_patterns(const struct YRX_RULE *rule);

// Destroys a [`YRX_PATTERNS`] object.
void yrx_patterns_destroy(struct YRX_PATTERNS *patterns);

// Destroys a [`YRX_BUFFER`] object.
void yrx_buffer_destroy(struct YRX_BUFFER *buf);

// Returns the error message for the most recent function in this API
// invoked by the current thread.
//
// The returned pointer is only valid until this thread calls some other
// function, as it can modify the last error and render the pointer to
// a previous error message invalid. Also, the pointer will be null if
// the most recent function was successfully.
const char *yrx_last_error(void);

// Creates a [`YRX_COMPILER`] object.
enum YRX_RESULT yrx_compiler_create(uint32_t flags,
                                    struct YRX_COMPILER **compiler);

// Destroys a [`YRX_COMPILER`] object.
void yrx_compiler_destroy(struct YRX_COMPILER *compiler);

// Adds a YARA source code to be compiled.
//
// This function can be called multiple times.
enum YRX_RESULT yrx_compiler_add_source(struct YRX_COMPILER *compiler,
                                        const char *src);

// Tell the compiler that a YARA module is not supported.
//
// Import statements for ignored modules will be ignored without errors but a
// warning will be issued. Any rule that make use of an ignored module will be
// ignored, while the rest of rules that don't rely on that module will be
// correctly compiled.
enum YRX_RESULT yrx_compiler_ignore_module(struct YRX_COMPILER *compiler,
                                           const char *module);

// Creates a new namespace.
//
// Further calls to `yrx_compiler_add_source` will put the rules under the
// newly created namespace.
//
// The `namespace` argument must be pointer to null-terminated UTF-8 string.
// If the string is not valid UTF-8 the result is an `INVALID_ARGUMENT` error.
enum YRX_RESULT yrx_compiler_new_namespace(struct YRX_COMPILER *compiler,
                                           const char *namespace_);

// Defines a global variable of string type and sets its initial value.
enum YRX_RESULT yrx_compiler_define_global_str(struct YRX_COMPILER *compiler,
                                               const char *ident,
                                               const char *value);

// Defines a global variable of bool type and sets its initial value.
enum YRX_RESULT yrx_compiler_define_global_bool(struct YRX_COMPILER *compiler,
                                                const char *ident,
                                                bool value);

// Defines a global variable of integer type and sets its initial value.
enum YRX_RESULT yrx_compiler_define_global_int(struct YRX_COMPILER *compiler,
                                               const char *ident,
                                               int64_t value);

// Defines a global variable of float type and sets its initial value.
enum YRX_RESULT yrx_compiler_define_global_float(struct YRX_COMPILER *compiler,
                                                 const char *ident,
                                                 double value);

// Builds the source code previously added to the compiler.
//
// After calling this function the compiler is reset to its initial state,
// (i.e: the state it had after returning from yrx_compiler_create) you can
// keep using it by adding more sources and calling this function again.
struct YRX_RULES *yrx_compiler_build(struct YRX_COMPILER *compiler);

// Creates a [`YRX_SCANNER`] object that can be used for scanning data with
// the provided [`YRX_RULES`].
//
// It's ok to pass the same [`YRX_RULES`] to multiple scanners, and use each
// scanner from a different thread. The scanner can be used as many times as
// you want, and it must be destroyed with [`yrx_scanner_destroy`]. Also, the
// scanner is valid as long as the rules are not destroyed, so, always destroy
// the [`YRX_SCANNER`] object before the [`YRX_RULES`] object.
enum YRX_RESULT yrx_scanner_create(const struct YRX_RULES *rules,
                                   struct YRX_SCANNER **scanner);

// Destroys a [`YRX_SCANNER`] object.
void yrx_scanner_destroy(struct YRX_SCANNER *scanner);

// Sets a timeout (in seconds) for scan operations.
//
// The scan functions will return a timeout error once the provided timeout
// duration has elapsed. The scanner will make every effort to stop promptly
// after the designated timeout duration. However, in some cases, particularly
// with rules containing only a few patterns, the scanner could potentially
// continue running for a longer period than the specified timeout.
enum YRX_RESULT yrx_scanner_set_timeout(struct YRX_SCANNER *scanner,
                                        uint64_t timeout);

// Scans a data buffer.
//
// `data` can be null as long as `len` is 0. In such cases its handled as
// empty data. Some YARA rules (i.e: `rule dummy { condition: true }`) can
// match even with empty data.
enum YRX_RESULT yrx_scanner_scan(struct YRX_SCANNER *scanner,
                                 const uint8_t *data,
                                 size_t len);

// Sets a callback function that is called by the scanner for each rule that
// matched during a scan.
//
// The `user_data` pointer can be used to provide additional context to your
// callback function. If the callback is not set, the scanner doesn't notify
// about matching rules.
//
// See [`YRX_ON_MATCHING_RULE`] for more details.
enum YRX_RESULT yrx_scanner_on_matching_rule(struct YRX_SCANNER *scanner,
                                             YRX_ON_MATCHING_RULE callback,
                                             void *user_data);

// Specifies the output data structure for a module.
//
// Each YARA module generates an output consisting of a data structure that
// contains information about the scanned file. This data structure is represented
// by a Protocol Buffer. Typically, you won't need to provide this output data
// yourself, as the YARA module automatically generates different outputs for
// each file it scans.
//
// However, there are two scenarios in which you may want to provide the output
// for a module yourself:
//
// 1) When the module does not produce any output on its own.
// 2) When you already know the output of the module for the upcoming file to
// be scanned, and you prefer to reuse this data instead of generating it again.
//
// Case 1) applies to certain modules lacking a main function, thus incapable of
// producing any output on their own. For such modules, you must set the output
// before scanning the associated data. Since the module's output typically varies
// with each scanned file, you need to call [yrx_scanner_set_module_output] prior
// to each invocation of [yrx_scanner_scan]. Once [yrx_scanner_scan] is executed,
// the module's output is consumed and will be empty unless set again before the
// subsequent call.
//
// Case 2) applies when you have previously stored the module's output for certain
// scanned data. In such cases, when rescanning the data, you can utilize this
// function to supply the module's output, thereby preventing redundant computation
// by the module. This optimization enhances performance by eliminating the need
// for the module to reparse the scanned data.
//
// The `name` argument is either a YARA module name (i.e: "pe", "elf", "dotnet",
// etc.) or the fully-qualified name of the protobuf message associated to
// the module. It must be a valid UTF-8 string.
enum YRX_RESULT yrx_scanner_set_module_output(struct YRX_SCANNER *scanner,
                                              const char *name,
                                              const uint8_t *data,
                                              size_t len);

// Sets the value of a global variable of type string.
enum YRX_RESULT yrx_scanner_set_global_str(struct YRX_SCANNER *scanner,
                                           const char *ident,
                                           const char *value);

// Sets the value of a global variable of type bool.
enum YRX_RESULT yrx_scanner_set_global_bool(struct YRX_SCANNER *scanner,
                                            const char *ident,
                                            bool value);

// Sets the value of a global variable of type int.
enum YRX_RESULT yrx_scanner_set_global_int(struct YRX_SCANNER *scanner,
                                           const char *ident,
                                           int64_t value);

// Sets the value of a global variable of type float.
enum YRX_RESULT yrx_scanner_set_global_float(struct YRX_SCANNER *scanner,
                                             const char *ident,
                                             double value);

#endif /* YARA_X */