#include "jsonparser.h"
#include <assert.h> // assert()
#include <errno.h>  // errno, ERANGE
#include <math.h>   // HUGE_VAL
#include <stdlib.h> // strtod()

#define EXPECT(c, ch)      do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)        ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)    ((ch) >= '1' && (ch) <= '9')

typedef struct {
    const char* json;
}json_context;

static void json_parse_whitespace(json_context* c) {
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int json_parse_literal(json_context* c, json_value* v, const char* literal, json_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return JSON_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return JSON_PARSE_OK;
}

static int json_parse_number(json_context* c, json_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return JSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return JSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return JSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->n = strtod(c->json, nullptr);
    if (errno = ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
        return JSON_PARSE_NUMBER_TOO_BIG;
    v->type = JSON_NUMBER;
    c->json = p;
    return JSON_PARSE_OK;
}

static int json_parse_value(json_context* c, json_value* v) {
    switch (*c->json) {
    case't': return json_parse_literal(c, v, "true", JSON_TRUE);
    case'f': return json_parse_literal(c, v, "false", JSON_FALSE);
    case'n': return json_parse_literal(c, v, "null", JSON_NULL);
    default: break;
    }
}

int json_parse(json_value* v, const char* json) {
    json_context c;
    int ret;
    assert(v != nullptr);
    c.json = json;
    v->type = JSON_NULL;
    json_parse_whitespace(&c);
    if ((ret = json_parse_value(&c, v)) == JSON_PARSE_OK) {
        json_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = JSON_NULL;
            ret = JSON_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

json_type json_get_type(const json_value* v) {
    assert(v != nullptr);
    return v->type;
}

double json_get_number(const json_value* v) {
    assert(v != nullptr && v->type == JSON_NUMBER);
    return v->n;
}