// One program that touches many source-level concepts, so the profiles in
// profiles.toml can be compared on the same code. All inputs come from argv,
// so the optimizer cannot fold the work away.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ev {

// ---- plain data types -------------------------------------------------

enum class Kind : uint8_t { Circle, Rect, Triangle, Unknown };

enum Flags : uint32_t { F_NONE = 0, F_VISIBLE = 1, F_FILLED = 2, F_LOCKED = 4 };

struct Vec2 {
    float x, y;
    Vec2 operator+(Vec2 o) const { return {x + o.x, y + o.y}; }
    Vec2 operator*(float k) const { return {x * k, y * k}; }
    float dot(Vec2 o) const { return x * o.x + y * o.y; }
};

struct PackedHeader {  // bitfields
    uint32_t version : 4;
    uint32_t kind : 3;
    uint32_t flags : 9;
    uint32_t length : 16;
};

union Value {
    int64_t i;
    double d;
    const char *s;
    uint8_t bytes[8];
};

struct Variant {  // tagged union
    enum Tag { INT, REAL, TEXT } tag;
    Value v;
};

struct Record {  // too big for registers: passed and returned through memory
    char name[24];
    uint32_t id;
    uint16_t level;
    uint8_t tags[6];
    double score;
    Vec2 pos;
};

// ---- class hierarchy (shapes.cpp) -------------------------------------

class Shape {
public:
    virtual ~Shape();
    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual Kind kind() const = 0;
    virtual const char *name() const;
    uint32_t flags;

protected:
    explicit Shape(uint32_t f) : flags(f) {}
};

class Circle : public Shape {
public:
    explicit Circle(double r);
    double area() const override;
    double perimeter() const override;
    Kind kind() const override;
    const char *name() const override;
    double radius;
};

class Rect : public Shape {
public:
    Rect(double w, double h);
    double area() const override;
    double perimeter() const override;
    Kind kind() const override;
    const char *name() const override;
    double w, h;
};

class Triangle : public Shape {
public:
    Triangle(double a, double b, double c);
    double area() const override;
    double perimeter() const override;
    Kind kind() const override;
    double a, b, c;
};

class Named {
public:
    virtual ~Named();
    virtual std::string label() const = 0;
};

class LabeledRect : public Rect, public Named {  // multiple inheritance
public:
    LabeledRect(double w, double h, std::string text);
    std::string label() const override;
    const char *name() const override;

private:
    std::string text_;
};

// Throws std::invalid_argument on bad input (returns nullptr without exceptions).
std::unique_ptr<Shape> make_shape(Kind kind, const double *params, size_t n);
double total_area(const std::vector<std::unique_ptr<Shape>> &shapes);
std::string describe(const Shape &shape);  // dynamic_cast when RTTI is on
PackedHeader pack_header(const Shape &shape, size_t length);
uint32_t unpack_header(PackedHeader h);

// ---- data structures and algorithms (algo.cpp) ------------------------

struct Node {
    int key;
    Node *next;
};

struct Tree {
    int key;
    Tree *left, *right;
};

Node *list_push(Node *head, int key);
Node *list_reverse(Node *head);
long list_sum(const Node *head);
void list_free(Node *head);

Tree *tree_insert(Tree *root, int key);
int tree_height(const Tree *root);
void tree_walk(const Tree *root, void (*visit)(int key, void *ctx), void *ctx);
void tree_free(Tree *root);

uint32_t crc32(const uint8_t *data, size_t len);
uint32_t hash_fnv1a(const char *s);
unsigned popcount_manual(uint64_t v);
uint32_t rotl32(uint32_t v, unsigned n);

void saxpy(float *y, const float *x, float a, size_t n);
float dot(const float *a, const float *b, size_t n);
double norm(const float *a, size_t n);
int64_t sum_squares(const int *v, size_t n);
void sort_ints(int *v, size_t n);  // qsort + comparator

int parse_command(const char *text);          // state machine
long dispatch(int op, long a, long b);        // dense switch
long apply_table(unsigned idx, long a, long b);  // function pointer table
int sum_variadic(int count, ...);

Record make_record(const char *name, uint32_t id, double score);
double score_record(Record r);
size_t format_record(char *out, size_t n, const Record &r);

uint64_t fib_rec(unsigned n);
uint64_t fib_iter(unsigned n);
uint64_t gcd(uint64_t a, uint64_t b);
unsigned collatz_steps(uint64_t n);
uint32_t next_random();  // global + static state
void seed_random(uint32_t seed);

Variant parse_variant(const char *text);
double variant_as_real(const Variant &v);

// ---- templates --------------------------------------------------------

template <typename T>
T clamp_to(T v, T lo, T hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

template <typename T, size_t N>
class Stack {
public:
    bool push(const T &v) {
        if (size_ == N) return false;
        items_[size_++] = v;
        return true;
    }
    bool pop(T &out) {
        if (size_ == 0) return false;
        out = items_[--size_];
        return true;
    }
    size_t size() const { return size_; }

private:
    T items_[N];
    size_t size_ = 0;
};

}  // namespace ev
