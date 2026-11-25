// Usage: everything [count] [word...]
//   count  how much data to generate (default 24); also seeds the generator
//   word   extra inputs: parsed as commands ("add12"), variants and map keys
#include "everything.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <stdexcept>

using namespace ev;

static uint64_t checksum = 0;  // every stage mixes its result in here

static void mix(const char *stage, uint64_t value) {
    checksum = (checksum ^ value) * 0x100000001B3ull;
    std::printf("%-10s %llu\n", stage, static_cast<unsigned long long>(value));
}

static void run_shapes(size_t count) {
    std::vector<std::unique_ptr<Shape>> shapes;
    size_t rejected = 0;
    for (size_t i = 0; i < count; i++) {
        double params[3] = {1.0 + next_random() % 9, 1.0 + next_random() % 9,
                            1.0 + next_random() % 9};
        Kind kind = static_cast<Kind>(next_random() % 4);  // 3 is Unknown: error path
#if defined(__cpp_exceptions)
        try {
            shapes.push_back(make_shape(kind, params, 3));
        } catch (const std::invalid_argument &e) {
            rejected += std::strlen(e.what()) > 0;
        }
#else
        if (auto s = make_shape(kind, params, 3))
            shapes.push_back(std::move(s));
        else
            rejected++;
#endif
    }

    std::sort(shapes.begin(), shapes.end(),
              [](const std::unique_ptr<Shape> &a, const std::unique_ptr<Shape> &b) {
                  return a->area() < b->area();
              });

    uint32_t headers = 0;
    size_t text = 0;
    for (const auto &s : shapes) {
        std::string d = describe(*s);
        text += d.size();
        headers ^= unpack_header(pack_header(*s, d.size()));
    }
    mix("area", static_cast<uint64_t>(total_area(shapes) * 100.0));
    mix("rejected", rejected);
    mix("headers", headers + text);
    if (!shapes.empty()) std::printf("largest    %s\n", describe(*shapes.back()).c_str());
}

static void run_structures(size_t count) {
    Node *list = nullptr;
    Tree *tree = nullptr;
    for (size_t i = 0; i < count; i++) {
        int key = static_cast<int>(next_random() % 1000);
        list = list_push(list, key);
        tree = tree_insert(tree, key);
    }
    list = list_reverse(list);
    mix("list", static_cast<uint64_t>(list_sum(list)));
    mix("height", static_cast<uint64_t>(tree_height(tree)));

    struct Walk {
        long total;
        int last;
        bool sorted;
    } walk = {0, -1, true};
    tree_walk(  // captureless lambda as a C callback
        tree,
        [](int key, void *ctx) {
            Walk *w = static_cast<Walk *>(ctx);
            w->sorted = w->sorted && key >= w->last;
            w->last = key;
            w->total += key;
        },
        &walk);
    mix("walk", static_cast<uint64_t>(walk.total) + walk.sorted);

    Stack<int, 8> stack;  // class template, fixed capacity
    for (const Node *n = list; n; n = n->next) stack.push(clamp_to(n->key, 100, 900));
    int top = 0, popped = 0;
    while (stack.pop(top)) popped += top;
    mix("stack", static_cast<uint64_t>(popped));

    list_free(list);
    tree_free(tree);
}

static void run_numeric(size_t count) {
    std::vector<float> x(count), y(count);
    std::vector<int> ints(count);
    for (size_t i = 0; i < count; i++) {
        x[i] = static_cast<float>(next_random() % 100) / 8.0f;  // eighths are exact in binary
        y[i] = static_cast<float>(next_random() % 100) / 8.0f;
        ints[i] = static_cast<int>(next_random() % 2000) - 1000;
    }
    saxpy(y.data(), x.data(), 1.5f, count);
    mix("dot", static_cast<uint64_t>(dot(x.data(), y.data(), count)));
    mix("norm", static_cast<uint64_t>(norm(y.data(), count) * 1000.0));
    mix("squares", static_cast<uint64_t>(sum_squares(ints.data(), count)));
    sort_ints(ints.data(), count);
    mix("median", static_cast<uint64_t>(ints[count / 2] + 1000));

    const uint8_t *raw = reinterpret_cast<const uint8_t *>(ints.data());
    mix("crc", crc32(raw, count * sizeof(int)));
    mix("bits", popcount_manual(checksum) + rotl32(static_cast<uint32_t>(checksum), 7));
}

static void run_control(size_t count, int argc, char **argv) {
    long acc = static_cast<long>(count);
    for (int op = 0; op < 12; op++) acc = dispatch(op, acc + 3, static_cast<long>(count) + op);
    for (unsigned i = 0; i < 6; i++) acc += apply_table(i, acc, static_cast<long>(count));
    mix("dispatch", static_cast<uint64_t>(acc));
    mix("variadic", static_cast<uint64_t>(sum_variadic(4, static_cast<int>(count), 2, 3, argc)));

    unsigned n = static_cast<unsigned>(count % 24);
    mix("fib", fib_rec(n) + fib_iter(n + 40));
    mix("gcd", gcd(count * 36, 48) + collatz_steps(count + 26));

    std::map<std::string, int> seen;                // red-black tree, std::string keys
    std::function<int(const char *)> classify =     // type-erased call
        [&seen](const char *word) { return ++seen[word] + parse_command(word); };
    double reals = 0.0;
    int commands = 0;
    for (int i = 2; i < argc; i++) {
        commands += classify(argv[i]);
        reals += variant_as_real(parse_variant(argv[i]));
        commands += static_cast<int>(hash_fnv1a(argv[i]) & 0xF);
    }
    mix("words", static_cast<uint64_t>(commands) + seen.size());
    mix("variants", static_cast<uint64_t>(reals * 10.0));
}

static void run_records(size_t count, const char *label) {
    char line[96];
    double total = 0.0;
    size_t chars = 0;
    for (size_t i = 0; i < count; i++) {
        uint32_t id = next_random() % 5000;  // separate statements: argument order is unspecified
        double score = (next_random() % 1000) / 8.0;
        Record r = make_record(label, id, score);
        total += score_record(r);  // passed by value
        chars += format_record(line, sizeof(line), r);
    }
    mix("records", static_cast<uint64_t>(total) + chars);
    std::printf("last       %s\n", line);
}

int main(int argc, char **argv) {
    size_t count = argc > 1 ? std::strtoul(argv[1], nullptr, 10) : 24;
    count = clamp_to<size_t>(count, 4, 4096);
    seed_random(static_cast<uint32_t>(count * 2654435761u));

    run_shapes(count);
    run_structures(count);
    run_numeric(count);
    run_control(count, argc, argv);
    run_records(count, argc > 2 ? argv[2] : "record");

    std::printf("checksum   %016llx\n", static_cast<unsigned long long>(checksum));
    return 0;
}
