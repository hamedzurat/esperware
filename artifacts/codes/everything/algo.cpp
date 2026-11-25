#include "everything.hpp"

#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace ev {

// ---- linked list and binary tree --------------------------------------

Node *list_push(Node *head, int key) {
    Node *n = static_cast<Node *>(std::malloc(sizeof(Node)));
    if (!n) return head;
    n->key = key;
    n->next = head;
    return n;
}

Node *list_reverse(Node *head) {
    Node *prev = nullptr;
    while (head) {
        Node *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

long list_sum(const Node *head) {
    long total = 0;
    for (; head; head = head->next) total += head->key;
    return total;
}

void list_free(Node *head) {
    while (head) {
        Node *next = head->next;
        std::free(head);
        head = next;
    }
}

Tree *tree_insert(Tree *root, int key) {
    if (!root) {
        Tree *t = new Tree;
        t->key = key;
        t->left = t->right = nullptr;
        return t;
    }
    if (key < root->key)
        root->left = tree_insert(root->left, key);
    else
        root->right = tree_insert(root->right, key);
    return root;
}

int tree_height(const Tree *root) {
    if (!root) return 0;
    int l = tree_height(root->left), r = tree_height(root->right);
    return 1 + (l > r ? l : r);
}

void tree_walk(const Tree *root, void (*visit)(int, void *), void *ctx) {
    if (!root) return;
    tree_walk(root->left, visit, ctx);
    visit(root->key, ctx);
    tree_walk(root->right, visit, ctx);
}

void tree_free(Tree *root) {
    if (!root) return;
    tree_free(root->left);
    tree_free(root->right);
    delete root;
}

// ---- bit manipulation and hashing -------------------------------------

static uint32_t crc_table[256];
static bool crc_ready = false;

static void crc_init() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
    crc_ready = true;
}

uint32_t crc32(const uint8_t *data, size_t len) {
    if (!crc_ready) crc_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) c = crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

uint32_t hash_fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 16777619u;
    }
    return h;
}

unsigned popcount_manual(uint64_t v) {
    unsigned n = 0;
    while (v) {
        v &= v - 1;
        n++;
    }
    return n;
}

uint32_t rotl32(uint32_t v, unsigned n) {
    n &= 31;
    return (v << n) | (v >> ((32 - n) & 31));
}

// ---- numeric loops (vectorizer targets) -------------------------------

void saxpy(float *y, const float *x, float a, size_t n) {
    for (size_t i = 0; i < n; i++) y[i] += a * x[i];
}

float dot(const float *a, const float *b, size_t n) {
    float total = 0.0f;
    for (size_t i = 0; i < n; i++) total += a[i] * b[i];
    return total;
}

double norm(const float *a, size_t n) { return std::sqrt(static_cast<double>(dot(a, a, n))); }

int64_t sum_squares(const int *v, size_t n) {
    int64_t total = 0;
    for (size_t i = 0; i < n; i++) total += static_cast<int64_t>(v[i]) * v[i];
    return total;
}

static int compare_ints(const void *a, const void *b) {
    int x = *static_cast<const int *>(a), y = *static_cast<const int *>(b);
    return (x > y) - (x < y);
}

void sort_ints(int *v, size_t n) { std::qsort(v, n, sizeof(int), compare_ints); }

// ---- control flow -----------------------------------------------------

// Accepts "<letters><digits>" such as "add12"; returns the number, or -1.
int parse_command(const char *text) {
    enum State { START, WORD, NUMBER, DONE, FAIL } state = START;
    int value = 0;
    for (const char *p = text; state != DONE && state != FAIL; p++) {
        unsigned char c = static_cast<unsigned char>(*p);
        switch (state) {
        case START:
            state = std::isalpha(c) ? WORD : FAIL;
            break;
        case WORD:
            if (std::isdigit(c)) {
                value = c - '0';
                state = NUMBER;
            } else if (!std::isalpha(c)) {
                state = FAIL;
            }
            break;
        case NUMBER:
            if (std::isdigit(c))
                value = value * 10 + (c - '0');
            else
                state = c == '\0' ? DONE : FAIL;
            break;
        default:
            break;
        }
    }
    return state == DONE ? value : -1;
}

long dispatch(int op, long a, long b) {
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : 0;
    case 4: return b ? a % b : 0;
    case 5: return a & b;
    case 6: return a | b;
    case 7: return a ^ b;
    case 8: return a << (b & 31);
    case 9: return a >> (b & 31);
    default: return -1;
    }
}

static long op_min(long a, long b) { return a < b ? a : b; }
static long op_max(long a, long b) { return a > b ? a : b; }
static long op_avg(long a, long b) { return (a + b) / 2; }
static long op_mod7(long a, long b) { return (a + b) % 7; }  // division by a constant

static long (*const op_table[])(long, long) = {op_min, op_max, op_avg, op_mod7};

long apply_table(unsigned idx, long a, long b) {
    return op_table[idx % (sizeof(op_table) / sizeof(op_table[0]))](a, b);
}

int sum_variadic(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int total = 0;
    for (int i = 0; i < count; i++) total += va_arg(ap, int);
    va_end(ap);
    return total;
}

// ---- structs by value, strings ----------------------------------------

Record make_record(const char *name, uint32_t id, double score) {
    Record r;
    std::memset(&r, 0, sizeof(r));
    std::strncpy(r.name, name, sizeof(r.name) - 1);
    r.id = id;
    r.level = static_cast<uint16_t>(id % 100);
    for (size_t i = 0; i < sizeof(r.tags); i++) r.tags[i] = static_cast<uint8_t>(id >> i);
    r.score = score;
    r.pos = Vec2{static_cast<float>(id), static_cast<float>(score)} * 0.5f;
    return r;
}

double score_record(Record r) {
    double bonus = 0.0;
    for (uint8_t t : r.tags) bonus += t & 1;
    return r.score * (1.0 + r.level / 100.0) + bonus + r.pos.dot(r.pos);
}

size_t format_record(char *out, size_t n, const Record &r) {
    char tags[32];  // stack buffer + string calls: stack protector and FORTIFY targets
    tags[0] = '\0';
    for (size_t i = 0; i < 3; i++) {
        char piece[8];
        std::snprintf(piece, sizeof(piece), "%02x", r.tags[i]);
        std::strcat(tags, piece);
    }
    int written = std::snprintf(out, n, "%s#%u lvl=%u tags=%s score=%.2f", r.name, r.id,
                                static_cast<unsigned>(r.level), tags, r.score);
    return written < 0 ? 0 : static_cast<size_t>(written);
}

// ---- recursion, integer math, global state ----------------------------

uint64_t fib_rec(unsigned n) { return n < 2 ? n : fib_rec(n - 1) + fib_rec(n - 2); }

uint64_t fib_iter(unsigned n) {
    uint64_t a = 0, b = 1;
    while (n--) {
        uint64_t t = a + b;
        a = b;
        b = t;
    }
    return a;
}

uint64_t gcd(uint64_t a, uint64_t b) { return b ? gcd(b, a % b) : a; }  // tail call

unsigned collatz_steps(uint64_t n) {
    unsigned steps = 0;
    while (n > 1) {
        n = (n & 1) ? 3 * n + 1 : n / 2;
        steps++;
    }
    return steps;
}

static uint32_t rng_state = 1;

void seed_random(uint32_t seed) { rng_state = seed ? seed : 1; }

uint32_t next_random() {  // xorshift32
    static unsigned calls = 0;
    calls++;
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state + (calls & 1);
}

// ---- tagged union -----------------------------------------------------

Variant parse_variant(const char *text) {
    Variant out;
    char *end = nullptr;
    long long i = std::strtoll(text, &end, 0);
    if (end != text && *end == '\0') {
        out.tag = Variant::INT;
        out.v.i = i;
        return out;
    }
    double d = std::strtod(text, &end);
    if (end != text && *end == '\0') {
        out.tag = Variant::REAL;
        out.v.d = d;
        return out;
    }
    out.tag = Variant::TEXT;
    out.v.s = text;
    return out;
}

double variant_as_real(const Variant &v) {
    switch (v.tag) {
    case Variant::INT: return static_cast<double>(v.v.i);
    case Variant::REAL: return v.v.d;
    case Variant::TEXT: return static_cast<double>(std::strlen(v.v.s));
    }
    return 0.0;
}

}  // namespace ev
