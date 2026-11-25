#include "everything.hpp"

#include <cmath>
#include <stdexcept>
#include <utility>

namespace ev {

static const double PI = 3.14159265358979323846;

Shape::~Shape() {}
const char *Shape::name() const { return "shape"; }

Circle::Circle(double r) : Shape(F_VISIBLE | F_FILLED), radius(r) {}
double Circle::area() const { return PI * radius * radius; }
double Circle::perimeter() const { return 2.0 * PI * radius; }
Kind Circle::kind() const { return Kind::Circle; }
const char *Circle::name() const { return "circle"; }

Rect::Rect(double w_, double h_) : Shape(F_VISIBLE), w(w_), h(h_) {}
double Rect::area() const { return w * h; }
double Rect::perimeter() const { return 2.0 * (w + h); }
Kind Rect::kind() const { return Kind::Rect; }
const char *Rect::name() const { return "rect"; }

Triangle::Triangle(double a_, double b_, double c_) : Shape(F_NONE), a(a_), b(b_), c(c_) {}
double Triangle::area() const {  // Heron's formula
    double s = (a + b + c) / 2.0;
    return std::sqrt(s * (s - a) * (s - b) * (s - c));
}
double Triangle::perimeter() const { return a + b + c; }
Kind Triangle::kind() const { return Kind::Triangle; }

Named::~Named() {}

LabeledRect::LabeledRect(double w_, double h_, std::string text)
    : Rect(w_, h_), text_(std::move(text)) {
    flags |= F_LOCKED;
}
std::string LabeledRect::label() const { return "[" + text_ + "]"; }
const char *LabeledRect::name() const { return "labeled-rect"; }

static void bad_shape(const char *why) {
#if defined(__cpp_exceptions)
    throw std::invalid_argument(why);
#else
    (void)why;
#endif
}

std::unique_ptr<Shape> make_shape(Kind kind, const double *p, size_t n) {
    switch (kind) {
    case Kind::Circle:
        if (n < 1 || p[0] <= 0.0) break;
        return std::unique_ptr<Shape>(new Circle(p[0]));
    case Kind::Rect:
        if (n < 2 || p[0] <= 0.0 || p[1] <= 0.0) break;
        if (p[0] == p[1]) return std::unique_ptr<Shape>(new LabeledRect(p[0], p[1], "square"));
        return std::unique_ptr<Shape>(new Rect(p[0], p[1]));
    case Kind::Triangle:
        if (n < 3 || p[0] + p[1] <= p[2] || p[0] + p[2] <= p[1] || p[1] + p[2] <= p[0]) break;
        return std::unique_ptr<Shape>(new Triangle(p[0], p[1], p[2]));
    default:
        bad_shape("unknown shape kind");
        return nullptr;
    }
    bad_shape("bad shape parameters");
    return nullptr;
}

double total_area(const std::vector<std::unique_ptr<Shape>> &shapes) {
    double total = 0.0;
    for (const auto &s : shapes) {
        if (s && (s->flags & F_VISIBLE)) total += s->area();  // virtual call in a loop
    }
    return total;
}

std::string describe(const Shape &shape) {
    std::string out = shape.name();
#if defined(__cpp_rtti)
    if (const Named *named = dynamic_cast<const Named *>(&shape)) {
        out += " ";
        out += named->label();
    } else if (const Circle *c = dynamic_cast<const Circle *>(&shape)) {
        out += " r=" + std::to_string(c->radius);
    }
#else
    if (shape.kind() == Kind::Circle) {
        out += " r=" + std::to_string(static_cast<const Circle &>(shape).radius);
    }
#endif
    return out;
}

PackedHeader pack_header(const Shape &shape, size_t length) {
    PackedHeader h;
    h.version = 3;
    h.kind = static_cast<uint32_t>(shape.kind());
    h.flags = shape.flags;
    h.length = static_cast<uint32_t>(length);
    return h;
}

uint32_t unpack_header(PackedHeader h) {
    return (h.version << 28) ^ (h.kind << 25) ^ (h.flags << 16) ^ h.length;
}

}  // namespace ev
