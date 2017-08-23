#ifndef JSONPARSER_H__
#define JSONPARSER_H__

typedef enum {
    JSON_NULL,
    JSON_FALSE,
    JSON_TRUE,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct {
    double n;
    json_type type;
} json_value;

enum {
    JSON_PARSE_OK = 0,
    JSON_PARSE_EXPECT_VALUE,
    JSON_PARSE_INVALID_VALUE,
    JSON_PARSE_ROOT_NOT_SINGULAR,
    JSON_PARSE_NUMBER_TOO_BIG
};

int json_parse(json_value* v, const char* json);

json_type json_get_type(const json_value* v);

double json_get_number(const json_value* v);

#endif // !JSONPARSER_H__
